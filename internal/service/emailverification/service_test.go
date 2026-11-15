package emailverification_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/emailcode"
	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/emailchallenge"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/emailverification"
	"github.com/matiasfelau/vinculo-vial-identity/internal/testsupport/emailchallenges"
)

var inicio = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

const (
	grantTTL = 30 * time.Minute
	eph      = "clave-efimera"
	ct       = "ciphertext"
)

type decryptorMock struct {
	plaintext []byte
	err       error
}

func (m *decryptorMock) Decrypt(_, _ []byte) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return append([]byte(nil), m.plaintext...), nil
}

func (m *decryptorMock) DecryptCombined([]byte) ([]byte, error) { panic("no se usa") }

// usersMock solo responde ExistsByEmail: es lo único que la verificación de email
// le pide al repositorio de usuarios.
type usersMock struct {
	existing map[string]bool
	err      error

	mu     sync.Mutex
	checks []string
}

func (m *usersMock) ExistsByEmail(_ context.Context, email string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checks = append(m.checks, email)
	return m.existing[email], m.err
}

func (m *usersMock) Create(context.Context, *domain.User, domain.OutboxEvent, *domain.GrantConsumption) error {
	panic("no se usa")
}
func (m *usersMock) FindByID(context.Context, uuid.UUID) (*domain.User, error) { panic("no se usa") }
func (m *usersMock) FindByDNIHashed(context.Context, string) (*domain.User, error) {
	panic("no se usa")
}
func (m *usersMock) FindByOwnerAndDNIHash(context.Context, uuid.UUID, string) (*domain.User, error) {
	panic("no se usa")
}

type harness struct {
	svc       *emailverification.Service
	decryptor *decryptorMock
	users     *usersMock
	repo      *emailchallenges.Memory
	codec     *emailcode.Codec
	now       time.Time
	logs      *strings.Builder
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	codec, err := emailcode.New(make([]byte, emailcode.KeyLength))
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{
		decryptor: &decryptorMock{},
		users:     &usersMock{existing: map[string]bool{}},
		repo:      emailchallenges.New(),
		codec:     codec,
		now:       inicio,
		logs:      &strings.Builder{},
	}
	logger := slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	engine, err := emailchallenge.New(emailchallenge.Deps{
		Challenges: h.repo, Codec: codec, Logger: logger, Now: func() time.Time { return h.now },
		Settings: emailchallenge.Settings{CodeTTL: 10 * time.Minute, MaxCodeAttempts: 5, ResendInterval: time.Minute, MaxSendsPerDay: 5},
	})
	if err != nil {
		t.Fatal(err)
	}

	h.svc, err = emailverification.New(emailverification.Deps{
		Decryptor: h.decryptor, Users: h.users, Engine: engine, GrantTTL: grantTTL, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) payload(t *testing.T, fields map[string]string) {
	t.Helper()
	b, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	h.decryptor.plaintext = b
}

func (h *harness) request(t *testing.T, email string) error {
	t.Helper()
	h.payload(t, map[string]string{"email": email})
	return h.svc.Request(t.Context(), []byte(eph), []byte(ct))
}

func (h *harness) confirm(t *testing.T, email, code string) (string, time.Duration, error) {
	t.Helper()
	h.payload(t, map[string]string{"email": email, "code": code})
	return h.svc.Confirm(t.Context(), []byte(eph), []byte(ct))
}

func (h *harness) emails(t *testing.T) []domain.EmailRequested {
	t.Helper()
	var out []domain.EmailRequested
	for _, row := range h.repo.Outbox() {
		evt, err := domain.ParseEmailRequested(row)
		if err != nil {
			t.Fatalf("ParseEmailRequested: %v", err)
		}
		out = append(out, evt)
	}
	return out
}

func TestRequestConEmailLibreEnviaElCodigo(t *testing.T) {
	h := newHarness(t)

	if err := h.request(t, "  Vecino@VinculoVial.AR "); err != nil {
		t.Fatalf("Request: %v", err)
	}

	emails := h.emails(t)
	if len(emails) != 1 {
		t.Fatalf("hay %d mails, se esperaba 1", len(emails))
	}
	e := emails[0]
	if e.Template != domain.EmailTemplateEmailVerification || e.To != "vecino@vinculovial.ar" {
		t.Errorf("mail = %+v: se esperaba EMAIL_VERIFICATION al email normalizado", e)
	}
	if len(e.Code) != domain.EmailCodeDigits || e.ExpiresAt == nil || e.Actor != nil {
		t.Errorf("mail = %+v: se esperaba código, vencimiento y sin actor", e)
	}
	if got := h.users.checks; len(got) != 1 || got[0] != "vecino@vinculovial.ar" {
		t.Errorf("ExistsByEmail se llamó con %v, se esperaba el email normalizado", got)
	}
}

func TestRequestConEmailRegistradoEnviaAccountExistsSinCodigo(t *testing.T) {
	h := newHarness(t)
	h.users.existing["vecino@vinculovial.ar"] = true

	if err := h.request(t, "vecino@vinculovial.ar"); err != nil {
		t.Fatalf("Request: %v", err)
	}

	emails := h.emails(t)
	if len(emails) != 1 {
		t.Fatalf("hay %d mails, se esperaba 1", len(emails))
	}
	if e := emails[0]; e.Template != domain.EmailTemplateAccountExists || e.Code != "" || e.ExpiresAt != nil || e.Actor != nil {
		t.Errorf("mail = %+v: ACCOUNT_EXISTS no lleva código, vencimiento ni actor", e)
	}
}

// Anti-enumeración: quien llama no puede distinguir los dos casos por lo que el
// servicio devuelve ni por cuántas veces toca la base.
func TestRequestEsIndistinguibleParaQuienLlama(t *testing.T) {
	libre, registrado := newHarness(t), newHarness(t)
	registrado.users.existing["vecino@vinculovial.ar"] = true

	errLibre := libre.request(t, "vecino@vinculovial.ar")
	errRegistrado := registrado.request(t, "vecino@vinculovial.ar")

	if errLibre != nil || errRegistrado != nil {
		t.Fatalf("errores = (%v, %v), se esperaba nil en los dos", errLibre, errRegistrado)
	}
	if libre.repo.Mutations() != registrado.repo.Mutations() || len(libre.users.checks) != len(registrado.users.checks) {
		t.Error("los dos casos no hacen el mismo trabajo contra la base")
	}
	if len(libre.repo.Outbox()) != len(registrado.repo.Outbox()) {
		t.Error("los dos casos encolan una cantidad distinta de eventos")
	}
}

// Ni los logs (a nivel debug incluido) llevan el email ni el código, ni dicen si
// la cuenta existía.
func TestRequestNoLogueaElEmailNiElCodigo(t *testing.T) {
	for _, registrado := range []bool{false, true} {
		h := newHarness(t)
		h.users.existing["vecino@vinculovial.ar"] = registrado

		if err := h.request(t, "vecino@vinculovial.ar"); err != nil {
			t.Fatal(err)
		}

		out := h.logs.String()
		if strings.Contains(out, "vecino") || strings.Contains(out, "vinculovial") {
			t.Errorf("registrado=%v: el log contiene el email:\n%s", registrado, out)
		}
		if code := h.emails(t)[0].Code; code != "" && strings.Contains(out, code) {
			t.Errorf("registrado=%v: el log contiene el código", registrado)
		}
	}
}

// El nivel info nunca dice nada del pedido, exista o no la cuenta.
func TestRequestNoDejaNadaEnElNivelInfo(t *testing.T) {
	for _, registrado := range []bool{false, true} {
		h := newHarness(t)
		h.users.existing["vecino@vinculovial.ar"] = registrado
		h.request(t, "vecino@vinculovial.ar")

		for _, linea := range strings.Split(h.logs.String(), "\n") {
			if strings.Contains(linea, "level=INFO") {
				t.Errorf("registrado=%v: línea info inesperada: %s", registrado, linea)
			}
		}
	}
}

func TestRequestDentroDelThrottleNoEnviaOtroMailPeroResponde(t *testing.T) {
	h := newHarness(t)
	h.request(t, "vecino@vinculovial.ar")

	h.now = h.now.Add(30 * time.Second)
	if err := h.request(t, "vecino@vinculovial.ar"); err != nil {
		t.Fatalf("el pedido throttleado debería responder igual: %v", err)
	}

	if got := len(h.emails(t)); got != 1 {
		t.Errorf("hay %d mails, se esperaba 1", got)
	}
}

func TestRequestRechazaLosDatosInvalidos(t *testing.T) {
	h := newHarness(t)

	for _, email := range []string{"", "sin-arroba", "a@b@c.ar", "a@localhost"} {
		if err := h.request(t, email); !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("email %q: error = %v, se esperaba ErrInvalidInput", email, err)
		}
	}
	h.decryptor.plaintext = []byte(`{no es json`)
	if err := h.svc.Request(t.Context(), []byte(eph), []byte(ct)); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("JSON inválido: error = %v, se esperaba ErrInvalidInput", err)
	}

	if len(h.users.checks) != 0 || h.repo.Mutations() != 0 {
		t.Error("se tocó la base con datos inválidos")
	}
}

func TestPropagaLosErroresDelDescifrado(t *testing.T) {
	for _, want := range []error{domain.ErrMalformedCryptogram, domain.ErrInvalidCryptogram} {
		h := newHarness(t)
		h.decryptor.err = want

		if err := h.svc.Request(t.Context(), []byte(eph), []byte(ct)); !errors.Is(err, want) {
			t.Errorf("Request: error = %v, se esperaba %v", err, want)
		}
		if _, _, err := h.svc.Confirm(t.Context(), []byte(eph), []byte(ct)); !errors.Is(err, want) {
			t.Errorf("Confirm: error = %v, se esperaba %v", err, want)
		}
	}
}

func TestRequestConLaBaseCaidaDevuelveElError(t *testing.T) {
	h := newHarness(t)
	h.users.err = domain.ErrDatabaseUnavailable
	if err := h.request(t, "vecino@vinculovial.ar"); !errors.Is(err, domain.ErrDatabaseUnavailable) {
		t.Errorf("ExistsByEmail caído: error = %v", err)
	}

	h = newHarness(t)
	h.repo.Err = domain.ErrDatabaseUnavailable
	if err := h.request(t, "vecino@vinculovial.ar"); !errors.Is(err, domain.ErrDatabaseUnavailable) {
		t.Errorf("desafíos caídos: error = %v", err)
	}
}

func TestConfirmConElCodigoCorrectoEmiteElToken(t *testing.T) {
	h := newHarness(t)
	h.request(t, "vecino@vinculovial.ar")
	code := h.emails(t)[0].Code

	token, expiresIn, err := h.confirm(t, "  VECINO@vinculovial.ar", code)
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}

	if token == "" || expiresIn != grantTTL {
		t.Errorf("(token=%q, expires_in=%v), se esperaba un token y %v", token, expiresIn, grantTTL)
	}
	c := h.repo.Get(domain.EmailChallengePurposeEmailVerification,
		h.codec.SubjectHMAC(domain.EmailChallengePurposeEmailVerification, "vecino@vinculovial.ar"))
	if c == nil || c.GrantHash != h.codec.GrantHash(token) {
		t.Error("el grant guardado no corresponde al token emitido")
	}
}

func TestConfirmDaCodigoInvalidoSinDistinguirElMotivo(t *testing.T) {
	h := newHarness(t)
	h.request(t, "vecino@vinculovial.ar")
	code := h.emails(t)[0].Code
	otro := "000000"
	if code == otro {
		otro = "000001"
	}

	casos := map[string][2]string{
		"código incorrecto":  {"vecino@vinculovial.ar", otro},
		"email sin pedido":   {"otro@vinculovial.ar", code},
		"email mal formado":  {"no-es-un-email", code},
		"código mal formado": {"vecino@vinculovial.ar", "12ab"},
		"código vacío":       {"vecino@vinculovial.ar", ""},
	}
	var textos []string
	for name, c := range casos {
		_, _, err := h.confirm(t, c[0], c[1])
		if !errors.Is(err, domain.ErrInvalidCode) {
			t.Errorf("%s: error = %v, se esperaba ErrInvalidCode", name, err)
			continue
		}
		textos = append(textos, err.Error())
	}
	for _, s := range textos {
		if s != textos[0] {
			t.Errorf("los errores difieren: %q vs %q", s, textos[0])
		}
	}

	h.decryptor.plaintext = []byte(`{no es json`)
	if _, _, err := h.svc.Confirm(t.Context(), []byte(eph), []byte(ct)); !errors.Is(err, domain.ErrInvalidCode) {
		t.Errorf("JSON inválido: error = %v, se esperaba ErrInvalidCode", err)
	}
}

// Confirmar sobre un email que ya tenía cuenta (ACCOUNT_EXISTS, sin código) da el
// mismo INVALID_CODE que un código incorrecto.
func TestConfirmSobreUnEmailConCuentaDaCodigoInvalido(t *testing.T) {
	h := newHarness(t)
	h.users.existing["vecino@vinculovial.ar"] = true
	h.request(t, "vecino@vinculovial.ar")

	if _, _, err := h.confirm(t, "vecino@vinculovial.ar", "123456"); !errors.Is(err, domain.ErrInvalidCode) {
		t.Fatalf("error = %v, se esperaba ErrInvalidCode", err)
	}
}

func TestConfirmConLaBaseCaidaNoDiceCodigoInvalido(t *testing.T) {
	h := newHarness(t)
	h.request(t, "vecino@vinculovial.ar")
	code := h.emails(t)[0].Code
	h.repo.Err = domain.ErrDatabaseUnavailable

	_, _, err := h.confirm(t, "vecino@vinculovial.ar", code)

	if !errors.Is(err, domain.ErrDatabaseUnavailable) || errors.Is(err, domain.ErrInvalidCode) {
		t.Fatalf("error = %v, se esperaba ErrDatabaseUnavailable", err)
	}
}

func TestNoLogueaElTokenNiElCodigoAlConfirmar(t *testing.T) {
	h := newHarness(t)
	h.request(t, "vecino@vinculovial.ar")
	code := h.emails(t)[0].Code

	token, _, err := h.confirm(t, "vecino@vinculovial.ar", code)
	if err != nil {
		t.Fatal(err)
	}
	h.confirm(t, "vecino@vinculovial.ar", code) // segundo intento: rechazado y logueado

	out := h.logs.String()
	for _, secreto := range []string{token, code, "vecino@vinculovial.ar"} {
		if strings.Contains(out, secreto) {
			t.Errorf("el log contiene %q", secreto)
		}
	}
}

func TestNewValidaLasDependencias(t *testing.T) {
	h := newHarness(t)
	engine, _ := emailchallenge.New(emailchallenge.Deps{
		Challenges: h.repo, Codec: h.codec,
		Settings: emailchallenge.Settings{CodeTTL: time.Minute, MaxCodeAttempts: 1, ResendInterval: time.Second, MaxSendsPerDay: 1},
	})
	base := func() emailverification.Deps {
		return emailverification.Deps{Decryptor: h.decryptor, Users: h.users, Engine: engine, GrantTTL: grantTTL}
	}
	if _, err := emailverification.New(base()); err != nil {
		t.Fatalf("configuración válida: %v", err)
	}

	casos := map[string]func(*emailverification.Deps){
		"sin descifrador": func(d *emailverification.Deps) { d.Decryptor = nil },
		"sin usuarios":    func(d *emailverification.Deps) { d.Users = nil },
		"sin motor":       func(d *emailverification.Deps) { d.Engine = nil },
		"sin vida":        func(d *emailverification.Deps) { d.GrantTTL = 0 },
	}
	for name, tune := range casos {
		d := base()
		tune(&d)
		if _, err := emailverification.New(d); err == nil {
			t.Errorf("%s: New no rechazó la configuración", name)
		}
	}
}
