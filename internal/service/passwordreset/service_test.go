package passwordreset_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/emailcode"
	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/emailchallenge"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/passwordreset"
	"github.com/matiasfelau/vinculo-vial-identity/internal/testsupport/emailchallenges"
)

var inicio = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

const (
	resetTTL      = 15 * time.Minute
	maxIdentidad  = 3
	eph           = "clave-efimera"
	ct            = "ciphertext"
	dniDeLaCuenta = "30123456"
	dniAjeno      = "27111222"
	emailCuenta   = "vecino@vinculovial.ar"
	claveNueva    = "Rosario-2026!clave"
	tramite       = "12345678901"
)

// selfieBase64 es el contenido mínimo que pasa la validación de formato: la
// cabecera PNG y nada más.
var selfieBase64 = base64.StdEncoding.EncodeToString([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x01})

type harness struct {
	svc       *passwordreset.Service
	decryptor *decryptorMock
	hasher    *hasherMock
	renaper   *renaperMock
	users     *usersMock
	repo      *emailchallenges.Memory
	codec     *emailcode.Codec
	user      *domain.User
	now       time.Time
	logs      *strings.Builder
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	codec, err := emailcode.New(make([]byte, emailcode.KeyLength))
	if err != nil {
		t.Fatal(err)
	}
	verified := inicio.Add(-time.Hour)
	user := &domain.User{
		ID: uuid.New(), Email: emailCuenta, PasswordHash: "$argon2id$vieja",
		DNIHashed: "idx:" + dniDeLaCuenta, EmailVerifiedAt: &verified,
	}

	h := &harness{
		decryptor: &decryptorMock{}, hasher: &hasherMock{}, renaper: &renaperMock{verified: true},
		users: newUsersMock(), repo: emailchallenges.New(), codec: codec, user: user, now: inicio,
		logs: &strings.Builder{},
	}
	h.users.add(user)
	logger := slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	engine, err := emailchallenge.New(emailchallenge.Deps{
		Challenges: h.repo, Codec: codec, Logger: logger, Now: func() time.Time { return h.now },
		Settings: emailchallenge.Settings{CodeTTL: 10 * time.Minute, MaxCodeAttempts: 5, ResendInterval: time.Minute, MaxSendsPerDay: 5},
	})
	if err != nil {
		t.Fatal(err)
	}

	h.svc, err = passwordreset.New(passwordreset.Deps{
		Decryptor: h.decryptor, Indexer: indexerMock{}, Hasher: h.hasher, Renaper: h.renaper,
		Users: h.users, Challenges: h.repo, Codec: codec, Engine: engine,
		GrantTTL: resetTTL, MaxIdentityAttempts: maxIdentidad, Logger: logger,
		Now: func() time.Time { return h.now },
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

func (h *harness) request(t *testing.T, dni string) error {
	t.Helper()
	h.payload(t, map[string]string{"dni": dni})
	return h.svc.Request(t.Context(), []byte(eph), []byte(ct))
}

func (h *harness) confirm(t *testing.T, dni, code string) (string, time.Duration, error) {
	t.Helper()
	h.payload(t, map[string]string{"dni": dni, "code": code})
	return h.svc.Confirm(t.Context(), []byte(eph), []byte(ct))
}

// complete arma el payload de la revalidación con valores válidos; override pisa
// campos puntuales.
func (h *harness) complete(t *testing.T, token string, override map[string]string) error {
	t.Helper()
	fields := map[string]string{
		"reset_token": token, "dni": dniDeLaCuenta, "tramite": tramite, "sexo": "f",
		"selfie": selfieBase64, "new_password": claveNueva,
	}
	for k, v := range override {
		fields[k] = v
	}
	h.payload(t, fields)
	return h.svc.Complete(t.Context(), []byte(eph), []byte(ct))
}

func (h *harness) emails(t *testing.T) []domain.EmailRequested {
	t.Helper()
	var out []domain.EmailRequested
	for _, row := range h.repo.Outbox() {
		if row.Type != domain.EventTypeEmailRequested {
			continue
		}
		evt, err := domain.ParseEmailRequested(row)
		if err != nil {
			t.Fatalf("ParseEmailRequested: %v", err)
		}
		out = append(out, evt)
	}
	return out
}

func (h *harness) challenge() *domain.EmailChallenge {
	return h.repo.Get(domain.EmailChallengePurposePasswordReset,
		h.codec.SubjectHMAC(domain.EmailChallengePurposePasswordReset, h.user.ID.String()))
}

// conToken lleva el flujo hasta tener un reset_token vigente: pedido y
// confirmación del código.
func (h *harness) conToken(t *testing.T) string {
	t.Helper()
	if err := h.request(t, dniDeLaCuenta); err != nil {
		t.Fatalf("Request: %v", err)
	}
	token, _, err := h.confirm(t, dniDeLaCuenta, h.emails(t)[0].Code)
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	return token
}

// ---------------------------------------------------------------- Request ---

func TestRequestConCuentaVerificadaEnviaElCodigoAlEmailDeLaCuenta(t *testing.T) {
	h := newHarness(t)

	if err := h.request(t, "30.123.456"); err != nil {
		t.Fatalf("Request: %v", err)
	}

	emails := h.emails(t)
	if len(emails) != 1 {
		t.Fatalf("hay %d mails, se esperaba 1", len(emails))
	}
	e := emails[0]
	if e.Template != domain.EmailTemplatePasswordReset || e.To != emailCuenta {
		t.Errorf("mail = %+v, se esperaba PASSWORD_RESET al email de la cuenta", e)
	}
	if len(e.Code) != domain.EmailCodeDigits || e.ExpiresAt == nil {
		t.Errorf("mail = %+v, se esperaba código y vencimiento", e)
	}
	if e.Actor == nil || *e.Actor != h.user.ID {
		t.Errorf("actor = %v, se esperaba el usuario %v", e.Actor, h.user.ID)
	}
	if c := h.challenge(); c == nil || c.UserID == nil || *c.UserID != h.user.ID {
		t.Errorf("desafío = %+v, se esperaba atado a la cuenta", c)
	}
}

// Sin cuenta, o con la cuenta sin email verificado, no se hace nada: ni mail ni
// desafío.
func TestRequestSinCuentaRecuperableNoHaceNada(t *testing.T) {
	sinVerificar := func(h *harness) { h.user.EmailVerifiedAt = nil; h.users.add(h.user) }
	casos := map[string]struct {
		dni   string
		setup func(h *harness)
	}{
		"DNI sin cuenta":              {dniAjeno, func(*harness) {}},
		"cuenta sin email verificado": {dniDeLaCuenta, sinVerificar},
	}
	for name, tc := range casos {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			tc.setup(h)

			if err := h.request(t, tc.dni); err != nil {
				t.Fatalf("Request: %v", err)
			}

			if len(h.repo.Outbox()) != 0 || h.repo.Mutations() != 0 {
				t.Errorf("se escribió algo: outbox=%d mutaciones=%d", len(h.repo.Outbox()), h.repo.Mutations())
			}
		})
	}
}

// Anti-enumeración: el pedido devuelve nil, y nada que quien llama pueda ver
// distingue "hay cuenta" de "no hay cuenta".
func TestRequestDevuelveLoMismoExistaONoLaCuenta(t *testing.T) {
	con, sin := newHarness(t), newHarness(t)

	errCon := con.request(t, dniDeLaCuenta)
	errSin := sin.request(t, dniAjeno)

	if errCon != nil || errSin != nil {
		t.Fatalf("errores = (%v, %v), se esperaba nil en los dos", errCon, errSin)
	}
}

func TestRequestNoDejaNadaEnInfoNiLogueaElDNIElEmailNiElCodigo(t *testing.T) {
	for _, dni := range []string{dniDeLaCuenta, dniAjeno} {
		h := newHarness(t)
		h.request(t, dni)

		out := h.logs.String()
		for _, linea := range strings.Split(out, "\n") {
			if strings.Contains(linea, "level=INFO") {
				t.Errorf("dni=%s: línea info inesperada: %s", dni, linea)
			}
		}
		for _, secreto := range []string{dni, "idx:", "vecino", "vinculovial"} {
			if strings.Contains(out, secreto) {
				t.Errorf("dni=%s: el log contiene %q:\n%s", dni, secreto, out)
			}
		}
		for _, e := range h.emails(t) {
			if strings.Contains(out, e.Code) {
				t.Errorf("dni=%s: el log contiene el código", dni)
			}
		}
	}
}

func TestRequestDentroDelThrottleNoEnviaOtroMailPeroResponde(t *testing.T) {
	h := newHarness(t)
	h.request(t, dniDeLaCuenta)

	h.now = h.now.Add(30 * time.Second)
	if err := h.request(t, dniDeLaCuenta); err != nil {
		t.Fatalf("el pedido throttleado debería responder igual: %v", err)
	}
	if got := len(h.emails(t)); got != 1 {
		t.Errorf("hay %d mails, se esperaba 1", got)
	}

	h.now = h.now.Add(31 * time.Second)
	h.request(t, dniDeLaCuenta)
	if got := len(h.emails(t)); got != 2 {
		t.Errorf("hay %d mails tras el intervalo, se esperaban 2", got)
	}
}

func TestRequestRechazaDatosInvalidosSinTocarLaBase(t *testing.T) {
	h := newHarness(t)

	for _, dni := range []string{"", "123", "abcdefgh", "012345678"} {
		if err := h.request(t, dni); !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("dni %q: error = %v, se esperaba ErrInvalidInput", dni, err)
		}
	}
	h.decryptor.plaintext = []byte(`{no es json`)
	if err := h.svc.Request(t.Context(), []byte(eph), []byte(ct)); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("JSON inválido: error = %v, se esperaba ErrInvalidInput", err)
	}
	if h.users.dniCalls != 0 {
		t.Errorf("se buscó en la base %d veces con datos inválidos", h.users.dniCalls)
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
		if err := h.svc.Complete(t.Context(), []byte(eph), []byte(ct)); !errors.Is(err, want) {
			t.Errorf("Complete: error = %v, se esperaba %v", err, want)
		}
	}
}

func TestRequestConLaBaseCaidaDevuelveElError(t *testing.T) {
	h := newHarness(t)
	h.users.dniErr = domain.ErrDatabaseUnavailable
	if err := h.request(t, dniDeLaCuenta); !errors.Is(err, domain.ErrDatabaseUnavailable) {
		t.Errorf("usuarios caídos: error = %v", err)
	}

	h = newHarness(t)
	h.repo.Err = domain.ErrDatabaseUnavailable
	if err := h.request(t, dniDeLaCuenta); !errors.Is(err, domain.ErrDatabaseUnavailable) {
		t.Errorf("desafíos caídos: error = %v", err)
	}
}

// ---------------------------------------------------------------- Confirm ---

func TestConfirmConElCodigoCorrectoEmiteElResetToken(t *testing.T) {
	h := newHarness(t)
	h.request(t, dniDeLaCuenta)
	code := h.emails(t)[0].Code

	token, expiresIn, err := h.confirm(t, "30.123.456", code)
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}

	if token == "" || expiresIn != resetTTL {
		t.Errorf("(token=%q, expires_in=%v), se esperaba un token y %v", token, expiresIn, resetTTL)
	}
	if c := h.challenge(); c == nil || c.GrantHash != h.codec.GrantHash(token) || c.GrantAttempts != 0 {
		t.Errorf("desafío = %+v, se esperaba el grant del token con 0 intentos", c)
	}
}

func TestConfirmDaCodigoInvalidoSinDistinguirElMotivo(t *testing.T) {
	h := newHarness(t)
	h.request(t, dniDeLaCuenta)
	code := h.emails(t)[0].Code
	otro := "000000"
	if code == otro {
		otro = "000001"
	}
	cuentaSinVerificar := newHarness(t)
	cuentaSinVerificar.user.EmailVerifiedAt = nil
	cuentaSinVerificar.users.add(cuentaSinVerificar.user)

	casos := map[string]func() error{
		"código incorrecto":  func() error { _, _, err := h.confirm(t, dniDeLaCuenta, otro); return err },
		"DNI sin cuenta":     func() error { _, _, err := h.confirm(t, dniAjeno, code); return err },
		"DNI mal formado":    func() error { _, _, err := h.confirm(t, "12", code); return err },
		"código mal formado": func() error { _, _, err := h.confirm(t, dniDeLaCuenta, "12ab"); return err },
		"cuenta sin email verificado": func() error {
			_, _, err := cuentaSinVerificar.confirm(t, dniDeLaCuenta, code)
			return err
		},
		"sin pedido previo": func() error {
			_, _, err := newHarness(t).confirm(t, dniDeLaCuenta, code)
			return err
		},
	}
	var textos []string
	for name, run := range casos {
		err := run()
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

func TestConfirmSuma1IntentoPorCodigoIncorrectoYSeAgotaALosCinco(t *testing.T) {
	h := newHarness(t)
	h.request(t, dniDeLaCuenta)
	code := h.emails(t)[0].Code
	malo := "000000"
	if code == malo {
		malo = "000001"
	}

	for i := 1; i <= 5; i++ {
		h.confirm(t, dniDeLaCuenta, malo)
		if got := h.challenge().CodeAttempts; got != i {
			t.Fatalf("tras %d fallos, code_attempts = %d", i, got)
		}
	}
	if _, _, err := h.confirm(t, dniDeLaCuenta, code); !errors.Is(err, domain.ErrInvalidCode) {
		t.Fatalf("con los intentos agotados el código correcto no puede servir: %v", err)
	}
}

func TestConfirmConLaBaseCaidaNoDiceCodigoInvalido(t *testing.T) {
	h := newHarness(t)
	h.request(t, dniDeLaCuenta)
	code := h.emails(t)[0].Code

	h.users.dniErr = domain.ErrDatabaseUnavailable
	if _, _, err := h.confirm(t, dniDeLaCuenta, code); !errors.Is(err, domain.ErrDatabaseUnavailable) || errors.Is(err, domain.ErrInvalidCode) {
		t.Errorf("usuarios caídos: error = %v", err)
	}

	h.users.dniErr = nil
	h.repo.Err = domain.ErrDatabaseUnavailable
	if _, _, err := h.confirm(t, dniDeLaCuenta, code); !errors.Is(err, domain.ErrDatabaseUnavailable) || errors.Is(err, domain.ErrInvalidCode) {
		t.Errorf("desafíos caídos: error = %v", err)
	}
}

// --------------------------------------------------------------- Complete ---

func TestCompleteCambiaLaContrasenaYEncolaLosDosEventosEnUnaSolaTransaccion(t *testing.T) {
	h := newHarness(t)
	token := h.conToken(t)
	h.now = h.now.Add(2 * time.Minute)

	if err := h.complete(t, token, nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	completions := h.repo.Completions()
	if len(completions) != 1 {
		t.Fatalf("se completó %d veces, se esperaba 1", len(completions))
	}
	c := completions[0]
	if c.UserID != h.user.ID {
		t.Errorf("user = %v, se esperaba %v", c.UserID, h.user.ID)
	}
	if c.PasswordHash != "$argon2id$"+claveNueva {
		t.Errorf("hash = %q, se esperaba el de la contraseña nueva", c.PasswordHash)
	}
	if c.GrantHash != h.codec.GrantHash(token) || c.MaxIdentityAttempts != maxIdentidad {
		t.Errorf("grant/máximo = %q/%d", c.GrantHash, c.MaxIdentityAttempts)
	}
	if !c.Now.Equal(h.now) {
		t.Errorf("now = %v, se esperaba el reloj inyectado", c.Now)
	}

	// user.sessions.revoked con el motivo PASSWORD_RESET.
	if c.SessionsRevoked.Type != domain.EventTypeUserSessionsRevoked {
		t.Errorf("tipo = %q, se esperaba user.sessions.revoked", c.SessionsRevoked.Type)
	}
	var revoked map[string]string
	if err := json.Unmarshal(c.SessionsRevoked.Payload, &revoked); err != nil {
		t.Fatal(err)
	}
	if revoked["user_id"] != h.user.ID.String() || revoked["reason"] != "PASSWORD_RESET" {
		t.Errorf("payload de user.sessions.revoked = %v", revoked)
	}

	// email.requested PASSWORD_CHANGED, sin código ni vencimiento, con el usuario
	// como actor.
	changed, err := domain.ParseEmailRequested(c.PasswordChanged)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Template != domain.EmailTemplatePasswordChanged || changed.To != emailCuenta ||
		changed.Code != "" || changed.ExpiresAt != nil || changed.Actor == nil || *changed.Actor != h.user.ID {
		t.Errorf("email.requested = %+v", changed)
	}

	// RENAPER recibió los datos normalizados.
	if h.renaper.calls != 1 || h.renaper.dni[0] != dniDeLaCuenta || h.renaper.tramite[0] != tramite || h.renaper.sexo[0] != "F" {
		t.Errorf("RENAPER = %+v, se esperaba 1 llamada con los datos normalizados", h.renaper)
	}
	if string(h.renaper.selfie[0]) == "" {
		t.Error("RENAPER no recibió la selfie")
	}
}

func TestCompleteConsumeElTokenYNoSePuedeReusar(t *testing.T) {
	h := newHarness(t)
	token := h.conToken(t)

	if err := h.complete(t, token, nil); err != nil {
		t.Fatalf("primera: %v", err)
	}
	if err := h.complete(t, token, nil); !errors.Is(err, domain.ErrInvalidResetToken) {
		t.Fatalf("segunda: %v, se esperaba ErrInvalidResetToken", err)
	}
	if got := len(h.repo.Completions()); got != 1 {
		t.Errorf("se completó %d veces, se esperaba 1", got)
	}
}

// Un token ausente, desconocido, vencido, usado, sin intentos, de otro propósito o
// de una cuenta que ya no se puede recuperar da siempre ErrInvalidResetToken, y
// no gasta RENAPER.
func TestCompleteConUnTokenQueNoSirveDaResetTokenInvalido(t *testing.T) {
	casos := map[string]func(t *testing.T, h *harness) string{
		"vacío":       func(*testing.T, *harness) string { return "" },
		"desconocido": func(*testing.T, *harness) string { return "token-que-nadie-emitio" },
		"desmesurado": func(*testing.T, *harness) string { return strings.Repeat("a", 4096) },
		"vencido": func(t *testing.T, h *harness) string {
			token := h.conToken(t)
			h.now = h.now.Add(resetTTL)
			return token
		},
		"usado": func(t *testing.T, h *harness) string {
			token := h.conToken(t)
			if err := h.complete(t, token, nil); err != nil {
				t.Fatal(err)
			}
			return token
		},
		"sin intentos": func(t *testing.T, h *harness) string {
			token := h.conToken(t)
			c := h.challenge()
			c.GrantAttempts = maxIdentidad
			h.repo.Put(*c)
			return token
		},
		"de verificación de email": func(t *testing.T, h *harness) string {
			token, hash, _ := h.codec.NewGrant()
			expira := h.now.Add(time.Hour)
			h.repo.Put(domain.EmailChallenge{
				ID: uuid.New(), Purpose: domain.EmailChallengePurposeEmailVerification, SubjectHMAC: "x",
				UserID: &h.user.ID, GrantHash: hash, GrantExpiresAt: &expira,
			})
			return token
		},
		"de un desafío sin cuenta": func(t *testing.T, h *harness) string {
			token, hash, _ := h.codec.NewGrant()
			expira := h.now.Add(time.Hour)
			h.repo.Put(domain.EmailChallenge{
				ID: uuid.New(), Purpose: domain.EmailChallengePurposePasswordReset, SubjectHMAC: "y",
				GrantHash: hash, GrantExpiresAt: &expira,
			})
			return token
		},
		"de una cuenta que ya no existe": func(t *testing.T, h *harness) string {
			token := h.conToken(t)
			delete(h.users.byID, h.user.ID)
			return token
		},
		"de una cuenta sin email verificado": func(t *testing.T, h *harness) string {
			token := h.conToken(t)
			h.user.EmailVerifiedAt = nil
			h.users.add(h.user)
			return token
		},
	}
	for name, setup := range casos {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			token := setup(t, h)
			antes := h.renaper.calls

			err := h.complete(t, token, nil)

			if !errors.Is(err, domain.ErrInvalidResetToken) {
				t.Fatalf("error = %v, se esperaba ErrInvalidResetToken", err)
			}
			if h.renaper.calls != antes {
				t.Error("se consultó RENAPER con un token que no sirve")
			}
			if name != "usado" && len(h.repo.Completions()) != 0 {
				t.Error("se completó la recuperación con un token que no sirve")
			}
		})
	}
}

// El token se valida antes que los campos: con un token inválido, ni siquiera se
// mira la contraseña.
func TestCompleteValidaElTokenAntesQueLosCampos(t *testing.T) {
	h := newHarness(t)

	err := h.complete(t, "token-que-nadie-emitio", map[string]string{"new_password": "x", "dni": "1"})

	if !errors.Is(err, domain.ErrInvalidResetToken) {
		t.Fatalf("error = %v, se esperaba ErrInvalidResetToken", err)
	}
}

// Contraseña o campos inválidos: el mismo detalle que el alta, sin RENAPER y sin
// descontar intentos del token.
func TestCompleteConCamposInvalidosDaDatosInvalidosSinGastarIntentos(t *testing.T) {
	casos := map[string]map[string]string{
		"contraseña débil":                    {"new_password": "corta"},
		"contraseña sin símbolos":             {"new_password": "Rosario2026clave"},
		"contraseña con el DNI":               {"new_password": "Zz-" + dniDeLaCuenta + "-Aa!"},
		"contraseña con el usuario del email": {"new_password": "Vecino-2026!Aa"},
		"trámite inválido":                    {"tramite": "123"},
		"sexo inválido":                       {"sexo": "Q"},
		"selfie ausente":                      {"selfie": ""},
		"selfie que no es imagen":             {"selfie": "bm8gZXMgdW5hIGltYWdlbg=="},
		"DNI mal formado":                     {"dni": "12"},
	}
	for name, override := range casos {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			token := h.conToken(t)

			err := h.complete(t, token, override)

			if !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("error = %v, se esperaba ErrInvalidInput", err)
			}
			if h.renaper.calls != 0 {
				t.Error("se consultó RENAPER con campos inválidos")
			}
			if got := h.challenge().GrantAttempts; got != 0 {
				t.Errorf("grant_attempts = %d: un campo inválido no descuenta intentos", got)
			}
			if c := h.repo.Completions(); len(c) != 0 {
				t.Error("se completó la recuperación")
			}
		})
	}
}

// El DNI escaneado de otra persona se frena antes de RENAPER y descuenta un
// intento; al tercero, el token queda inválido.
func TestCompleteConElDNIDeOtraPersonaDescuentaIntentosHastaInvalidarElToken(t *testing.T) {
	h := newHarness(t)
	token := h.conToken(t)

	for i := 1; i <= maxIdentidad; i++ {
		err := h.complete(t, token, map[string]string{"dni": dniAjeno})
		if !errors.Is(err, domain.ErrIdentityNotVerified) {
			t.Fatalf("intento %d: %v, se esperaba ErrIdentityNotVerified", i, err)
		}
		if got := h.challenge().GrantAttempts; got != i {
			t.Fatalf("tras %d rechazos, grant_attempts = %d", i, got)
		}
	}
	if h.renaper.calls != 0 {
		t.Errorf("se consultó RENAPER %d veces con un DNI que no es el de la cuenta", h.renaper.calls)
	}

	// El token murió: ni siquiera con los datos correctos.
	if err := h.complete(t, token, nil); !errors.Is(err, domain.ErrInvalidResetToken) {
		t.Fatalf("tras agotar los intentos: %v, se esperaba ErrInvalidResetToken", err)
	}
	if len(h.repo.Completions()) != 0 {
		t.Error("se completó la recuperación con el token agotado")
	}
}

func TestCompleteSiRenaperRechazaDescuentaUnIntento(t *testing.T) {
	h := newHarness(t)
	token := h.conToken(t)
	h.renaper.verified = false

	err := h.complete(t, token, nil)

	if !errors.Is(err, domain.ErrIdentityNotVerified) {
		t.Fatalf("error = %v, se esperaba ErrIdentityNotVerified", err)
	}
	if got := h.challenge().GrantAttempts; got != 1 {
		t.Errorf("grant_attempts = %d, se esperaba 1", got)
	}
	if h.renaper.calls != 1 {
		t.Errorf("RENAPER se consultó %d veces, se esperaba 1", h.renaper.calls)
	}
	if len(h.repo.Completions()) != 0 || len(h.hasher.passwords) != 0 {
		t.Error("se derivó la contraseña o se completó pese al rechazo")
	}
}

// RENAPER caído no es un veredicto sobre la identidad: no descuenta intentos, y el
// error conserva el centinela que la capa HTTP traduce a 503.
func TestCompleteConRenaperCaidoNoDescuentaIntentos(t *testing.T) {
	casos := map[string]error{
		"timeout o circuito abierto":  domain.ErrUpstreamUnavailable,
		"respuesta fuera de contrato": domain.ErrUpstreamInvalidResponse,
	}
	for name, upstream := range casos {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			token := h.conToken(t)
			h.renaper.err = fmt.Errorf("renaper: %w", upstream)

			err := h.complete(t, token, nil)

			if !errors.Is(err, upstream) {
				t.Fatalf("error = %v, se esperaba %v", err, upstream)
			}
			if errors.Is(err, domain.ErrIdentityNotVerified) {
				t.Error("una dependencia caída se tradujo a identidad no verificada")
			}
			if got := h.challenge().GrantAttempts; got != 0 {
				t.Errorf("grant_attempts = %d, se esperaba 0: la dependencia caída no descuenta", got)
			}

			// Y el token sigue sirviendo cuando RENAPER vuelve.
			h.renaper.err = nil
			if err := h.complete(t, token, nil); err != nil {
				t.Errorf("con RENAPER de vuelta: %v", err)
			}
		})
	}
}

// Si no se puede registrar el rechazo, se devuelve ese error: callarlo dejaría
// reintentos ilimitados.
func TestCompleteSiNoSePuedeRegistrarElRechazoDevuelveElError(t *testing.T) {
	h := newHarness(t)
	token := h.conToken(t)
	h.repo.GrantAttemptErr = domain.ErrDatabaseUnavailable

	err := h.complete(t, token, map[string]string{"dni": dniAjeno})

	if !errors.Is(err, domain.ErrDatabaseUnavailable) || errors.Is(err, domain.ErrIdentityNotVerified) {
		t.Fatalf("error = %v, se esperaba ErrDatabaseUnavailable", err)
	}
}

func TestCompleteSiElRepositorioRechazaElTokenEnLaTransaccion(t *testing.T) {
	h := newHarness(t)
	token := h.conToken(t)
	h.repo.CompleteErr = domain.ErrInvalidResetToken

	if err := h.complete(t, token, nil); !errors.Is(err, domain.ErrInvalidResetToken) {
		t.Fatalf("error = %v, se esperaba ErrInvalidResetToken", err)
	}
}

func TestCompletePropagaLosErroresDeInfraestructura(t *testing.T) {
	t.Run("falla la transacción", func(t *testing.T) {
		h := newHarness(t)
		token := h.conToken(t)
		h.repo.CompleteErr = domain.ErrDatabaseUnavailable
		if err := h.complete(t, token, nil); !errors.Is(err, domain.ErrDatabaseUnavailable) {
			t.Errorf("error = %v", err)
		}
	})
	t.Run("falla el hash", func(t *testing.T) {
		h := newHarness(t)
		token := h.conToken(t)
		boom := errors.New("sin memoria")
		h.hasher.err = boom
		if err := h.complete(t, token, nil); !errors.Is(err, boom) {
			t.Errorf("error = %v", err)
		}
		if len(h.repo.Completions()) != 0 {
			t.Error("se completó sin poder derivar la contraseña")
		}
	})
	t.Run("falla la búsqueda del token", func(t *testing.T) {
		h := newHarness(t)
		token := h.conToken(t)
		h.repo.Err = domain.ErrDatabaseUnavailable
		if err := h.complete(t, token, nil); !errors.Is(err, domain.ErrDatabaseUnavailable) || errors.Is(err, domain.ErrInvalidResetToken) {
			t.Errorf("error = %v", err)
		}
	})
	t.Run("falla la búsqueda de la cuenta", func(t *testing.T) {
		h := newHarness(t)
		token := h.conToken(t)
		h.users.idErr = domain.ErrDatabaseUnavailable
		if err := h.complete(t, token, nil); !errors.Is(err, domain.ErrDatabaseUnavailable) || errors.Is(err, domain.ErrInvalidResetToken) {
			t.Errorf("error = %v", err)
		}
	})
	t.Run("JSON inválido", func(t *testing.T) {
		h := newHarness(t)
		h.decryptor.plaintext = []byte(`{no es json`)
		if err := h.svc.Complete(t.Context(), []byte(eph), []byte(ct)); !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("error = %v", err)
		}
	})
}

// Ni la contraseña, ni el token, ni el DNI, ni el email llegan a un log; el único
// info es el del restablecimiento, con el id de usuario.
func TestCompleteNoLogueaDatosPersonales(t *testing.T) {
	h := newHarness(t)
	token := h.conToken(t)
	h.complete(t, token, map[string]string{"dni": dniAjeno}) // rechazo de identidad
	h.complete(t, token, nil)                                // éxito

	out := h.logs.String()
	for _, secreto := range []string{claveNueva, token, dniDeLaCuenta, dniAjeno, emailCuenta, selfieBase64, tramite} {
		if strings.Contains(out, secreto) {
			t.Errorf("el log contiene %q", secreto)
		}
	}
	if !strings.Contains(out, "contraseña restablecida") || !strings.Contains(out, h.user.ID.String()) {
		t.Errorf("falta el log del restablecimiento con el id de usuario:\n%s", out)
	}
}

func TestNewValidaLasDependenciasYLosParametros(t *testing.T) {
	h := newHarness(t)
	engine, _ := emailchallenge.New(emailchallenge.Deps{
		Challenges: h.repo, Codec: h.codec,
		Settings: emailchallenge.Settings{CodeTTL: time.Minute, MaxCodeAttempts: 1, ResendInterval: time.Second, MaxSendsPerDay: 1},
	})
	base := func() passwordreset.Deps {
		return passwordreset.Deps{
			Decryptor: h.decryptor, Indexer: indexerMock{}, Hasher: h.hasher, Renaper: h.renaper,
			Users: h.users, Challenges: h.repo, Codec: h.codec, Engine: engine,
			GrantTTL: resetTTL, MaxIdentityAttempts: maxIdentidad,
		}
	}
	if _, err := passwordreset.New(base()); err != nil {
		t.Fatalf("configuración válida: %v", err)
	}

	casos := map[string]func(*passwordreset.Deps){
		"sin descifrador":    func(d *passwordreset.Deps) { d.Decryptor = nil },
		"sin indexador":      func(d *passwordreset.Deps) { d.Indexer = nil },
		"sin hasher":         func(d *passwordreset.Deps) { d.Hasher = nil },
		"sin RENAPER":        func(d *passwordreset.Deps) { d.Renaper = nil },
		"sin usuarios":       func(d *passwordreset.Deps) { d.Users = nil },
		"sin desafíos":       func(d *passwordreset.Deps) { d.Challenges = nil },
		"sin codec":          func(d *passwordreset.Deps) { d.Codec = nil },
		"sin motor":          func(d *passwordreset.Deps) { d.Engine = nil },
		"sin vida del token": func(d *passwordreset.Deps) { d.GrantTTL = 0 },
		"sin intentos":       func(d *passwordreset.Deps) { d.MaxIdentityAttempts = 0 },
	}
	for name, tune := range casos {
		d := base()
		tune(&d)
		if _, err := passwordreset.New(d); err == nil {
			t.Errorf("%s: New no rechazó la configuración", name)
		}
	}
}

// Sin Logger ni Now explícitos el servicio funciona.
func TestNewAplicaValoresPorDefecto(t *testing.T) {
	h := newHarness(t)
	engine, _ := emailchallenge.New(emailchallenge.Deps{
		Challenges: h.repo, Codec: h.codec,
		Settings: emailchallenge.Settings{CodeTTL: time.Minute, MaxCodeAttempts: 1, ResendInterval: time.Second, MaxSendsPerDay: 1},
	})
	svc, err := passwordreset.New(passwordreset.Deps{
		Decryptor: h.decryptor, Indexer: indexerMock{}, Hasher: h.hasher, Renaper: h.renaper,
		Users: h.users, Challenges: h.repo, Codec: h.codec, Engine: engine,
		GrantTTL: resetTTL, MaxIdentityAttempts: maxIdentidad,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.payload(t, map[string]string{"dni": dniAjeno})
	if err := svc.Request(t.Context(), []byte(eph), []byte(ct)); err != nil {
		t.Errorf("Request con los valores por defecto: %v", err)
	}
}
