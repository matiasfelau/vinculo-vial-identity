package signin_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/signin"
)

const (
	validDNI      = "30123456"
	validPassword = "Rosario-2026!clave"
)

func validPayload(dni, password string) []byte {
	b, err := json.Marshal(map[string]string{"dni": dni, "password": password})
	if err != nil {
		panic(err)
	}
	return b
}

func validUser() *domain.User {
	return &domain.User{
		ID:            uuid.New(),
		Email:         "vecino@vinculovial.ar",
		PasswordHash:  "$argon2id$" + validPassword,
		DNIHashed:     "blind-index-de:" + validDNI,
		AccountStatus: domain.AccountStatusActive,
	}
}

// harness agrupa los seis dobles y el logger, para que cada test arme la vía
// feliz completa y degrade solo lo que le interesa ejercitar.
type harness struct {
	decryptor *decryptorMock
	indexer   *indexerMock
	hasher    *hasherMock
	users     *usersMock
	sessions  *sessionsMock
	tokens    *tokensMock
	logs      *strings.Builder
	now       time.Time
}

func newHarness() *harness {
	now := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	return &harness{
		decryptor: &decryptorMock{plaintext: validPayload(validDNI, validPassword)},
		indexer:   &indexerMock{},
		hasher:    &hasherMock{},
		users:     &usersMock{user: validUser()},
		sessions:  &sessionsMock{},
		tokens: &tokensMock{
			accessToken:      "access-token-emitido",
			refreshToken:     "refresh-token-emitido",
			refreshHash:      "hash-del-refresh-token",
			refreshExpiresAt: now.Add(30 * 24 * time.Hour),
		},
		logs: &strings.Builder{},
		now:  now,
	}
}

func (h *harness) service(t *testing.T) *signin.Service {
	t.Helper()

	svc, err := signin.New(signin.Deps{
		Decryptor: h.decryptor,
		Indexer:   h.indexer,
		Hasher:    h.hasher,
		Users:     h.users,
		Sessions:  h.sessions,
		Tokens:    h.tokens,
		Logger:    slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now:       func() time.Time { return h.now },
	})
	if err != nil {
		t.Fatalf("no se pudo construir el servicio: %v", err)
	}
	return svc
}

func TestSignInExitoso(t *testing.T) {
	h := newHarness()
	svc := h.service(t)

	access, refresh, err := svc.SignIn(context.Background(), []byte("clave-efimera"), []byte("ciphertext"))
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if access != h.tokens.accessToken {
		t.Errorf("access token = %q, se esperaba %q", access, h.tokens.accessToken)
	}
	if refresh != h.tokens.refreshToken {
		t.Errorf("refresh token = %q, se esperaba %q", refresh, h.tokens.refreshToken)
	}
	if h.tokens.accessUserID != h.users.user.ID {
		t.Errorf("el access token se emitió para %v, se esperaba %v", h.tokens.accessUserID, h.users.user.ID)
	}

	if h.sessions.calls != 1 {
		t.Fatalf("se crearon %d sesiones, se esperaba 1", h.sessions.calls)
	}
	s := h.sessions.last()
	if s.UserID != h.users.user.ID {
		t.Errorf("session.UserID = %v, se esperaba %v", s.UserID, h.users.user.ID)
	}
	if s.RefreshTokenHash != h.tokens.refreshHash {
		t.Errorf("session.RefreshTokenHash = %q, se esperaba %q", s.RefreshTokenHash, h.tokens.refreshHash)
	}
	if s.IsRevoked {
		t.Error("una sesión recién creada no debe nacer revocada")
	}
	if !s.ExpiresAt.Equal(h.tokens.refreshExpiresAt) {
		t.Errorf("session.ExpiresAt = %v, se esperaba %v", s.ExpiresAt, h.tokens.refreshExpiresAt)
	}
	if !s.StartedAt.Equal(h.now) {
		t.Errorf("session.StartedAt = %v, el login debe fijar el instante actual (%v)", s.StartedAt, h.now)
	}
}

// El DNI inexistente y la contraseña incorrecta tienen que producir
// exactamente el mismo error: distinguirlos habilitaría enumerar qué DNIs
// están registrados.
func TestSignInConDNIInexistenteDevuelveElErrorUnificado(t *testing.T) {
	h := newHarness()
	h.users.err = domain.ErrUserNotFound
	svc := h.service(t)

	access, refresh, err := svc.SignIn(context.Background(), []byte("efimera"), []byte("ciphertext"))

	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Errorf("error = %v, se esperaba ErrInvalidCredentials", err)
	}
	if access != "" || refresh != "" {
		t.Error("un login rechazado no debe emitir tokens")
	}
	if h.sessions.calls != 0 {
		t.Error("un login rechazado no debe persistir una sesión")
	}
	if h.tokens.accessCalls != 0 {
		t.Error("un login rechazado no debe emitir un access token")
	}
	// Defensa de timing: se paga el costo de Verify aunque no haya usuario.
	if got := h.hasher.verifyCallCount(); got != 1 {
		t.Errorf("Verify se llamó %d veces, se esperaba 1 (contra el hash dummy)", got)
	}
}

func TestSignInConPasswordIncorrectaDevuelveElErrorUnificado(t *testing.T) {
	h := newHarness()
	h.decryptor.plaintext = validPayload(validDNI, "otra-contraseña-cualquiera")
	svc := h.service(t)

	access, refresh, err := svc.SignIn(context.Background(), []byte("efimera"), []byte("ciphertext"))

	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Errorf("error = %v, se esperaba ErrInvalidCredentials", err)
	}
	if access != "" || refresh != "" {
		t.Error("un login rechazado no debe emitir tokens")
	}
	if h.sessions.calls != 0 {
		t.Error("un login rechazado no debe persistir una sesión")
	}
	if got := h.hasher.verifyCallCount(); got != 1 {
		t.Errorf("Verify se llamó %d veces, se esperaba 1 (contra el hash real)", got)
	}
	if got := h.hasher.lastVerify().encodedHash; got != h.users.user.PasswordHash {
		t.Errorf("Verify se llamó contra %q, se esperaba el hash real del usuario", got)
	}
}

func TestSignInDNIInexistenteYPasswordIncorrectaProducenElMismoError(t *testing.T) {
	sinUsuario := newHarness()
	sinUsuario.users.err = domain.ErrUserNotFound
	_, _, err1 := sinUsuario.service(t).SignIn(context.Background(), []byte("e"), []byte("c"))

	passwordMala := newHarness()
	passwordMala.decryptor.plaintext = validPayload(validDNI, "incorrecta")
	_, _, err2 := passwordMala.service(t).SignIn(context.Background(), []byte("e"), []byte("c"))

	if err1.Error() != err2.Error() {
		t.Errorf("los mensajes difieren y permiten distinguir los casos: %q vs %q", err1, err2)
	}
}

func TestSignInRechazaPayloadInvalido(t *testing.T) {
	cases := map[string][]byte{
		"DNI con letras":  validPayload("30abc456", validPassword),
		"password vacío":  validPayload(validDNI, ""),
		"DNI vacío":       validPayload("", validPassword),
	}

	for name, plaintext := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness()
			h.decryptor.plaintext = plaintext
			svc := h.service(t)

			_, _, err := svc.SignIn(context.Background(), []byte("e"), []byte("c"))

			if !errors.Is(err, domain.ErrInvalidInput) {
				t.Errorf("error = %v, se esperaba ErrInvalidInput", err)
			}
			if h.users.calls != 0 {
				t.Error("un payload inválido no debe llegar a buscar el usuario")
			}
		})
	}
}

func TestSignInRechazaJSONMalformado(t *testing.T) {
	h := newHarness()
	h.decryptor.plaintext = []byte("esto no es JSON")
	svc := h.service(t)

	_, _, err := svc.SignIn(context.Background(), []byte("e"), []byte("c"))

	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("error = %v, se esperaba ErrInvalidInput", err)
	}
}

func TestSignInPropagaElErrorDeDescifradoSinTraducirlo(t *testing.T) {
	h := newHarness()
	h.decryptor.err = domain.ErrInvalidCryptogram
	svc := h.service(t)

	_, _, err := svc.SignIn(context.Background(), []byte("e"), []byte("c"))

	if !errors.Is(err, domain.ErrInvalidCryptogram) {
		t.Errorf("error = %v, se esperaba ErrInvalidCryptogram sin traducir", err)
	}
}

// Si falla la persistencia de la sesión, los tokens ya generados no deben
// devolverse: un refresh token que el cliente recibe pero que no existe en
// sessions no verificaría nunca contra /refresh.
func TestSignInNoDevuelveTokensSiFallaPersistirLaSesion(t *testing.T) {
	h := newHarness()
	h.sessions.err = errors.New("la base no responde")
	svc := h.service(t)

	access, refresh, err := svc.SignIn(context.Background(), []byte("e"), []byte("c"))

	if err == nil {
		t.Fatal("se esperaba un error")
	}
	if access != "" || refresh != "" {
		t.Error("no deben devolverse tokens si la sesión no se pudo persistir")
	}
}

// Un hash almacenado que no se puede interpretar es un dato corrupto, no una
// contraseña incorrecta: no debe colapsarse en el 401 unificado.
func TestSignInNoColapsaUnHashCorruptoEnCredencialesInvalidas(t *testing.T) {
	h := newHarness()
	h.hasher.verifyErr = errors.New("hash con formato inválido")
	svc := h.service(t)

	_, _, err := svc.SignIn(context.Background(), []byte("e"), []byte("c"))

	if errors.Is(err, domain.ErrInvalidCredentials) {
		t.Error("un hash corrupto no debería reportarse como credenciales inválidas")
	}
	if err == nil {
		t.Fatal("se esperaba un error")
	}
}

func TestNewValidaLasDependencias(t *testing.T) {
	h := newHarness()
	base := signin.Deps{
		Decryptor: h.decryptor,
		Indexer:   h.indexer,
		Hasher:    h.hasher,
		Users:     h.users,
		Sessions:  h.sessions,
		Tokens:    h.tokens,
	}

	cases := map[string]func(*signin.Deps){
		"sin decryptor": func(d *signin.Deps) { d.Decryptor = nil },
		"sin indexer":   func(d *signin.Deps) { d.Indexer = nil },
		"sin hasher":    func(d *signin.Deps) { d.Hasher = nil },
		"sin users":     func(d *signin.Deps) { d.Users = nil },
		"sin sessions":  func(d *signin.Deps) { d.Sessions = nil },
		"sin tokens":    func(d *signin.Deps) { d.Tokens = nil },
	}

	for name, degradar := range cases {
		t.Run(name, func(t *testing.T) {
			d := base
			degradar(&d)
			if _, err := signin.New(d); err == nil {
				t.Error("se esperaba un error de construcción")
			}
		})
	}
}

func TestNewPropagaElErrorAlPrepararLaDefensaDeTiming(t *testing.T) {
	h := newHarness()
	h.hasher.hashErr = errors.New("no se pudo derivar el hash")

	_, err := signin.New(signin.Deps{
		Decryptor: h.decryptor,
		Indexer:   h.indexer,
		Hasher:    h.hasher,
		Users:     h.users,
		Sessions:  h.sessions,
		Tokens:    h.tokens,
	})
	if err == nil {
		t.Error("se esperaba un error al no poder derivar el hash dummy")
	}
}

// Un intento fallido queda en el log identificado por dni_hashed, nunca por
// el DNI ni la contraseña en claro.
func TestIntentoFallidoQuedaRegistradoSinFiltrarDatosSensibles(t *testing.T) {
	h := newHarness()
	h.users.err = domain.ErrUserNotFound
	// El índice del doble por defecto ("blind-index-de:"+dni) incluye el DNI
	// como substring a propósito, para que otros tests puedan verificar qué
	// valor se indexó. Acá se fija a un valor opaco, como sería un HMAC real,
	// para que la aserción de "no se filtra el DNI" pruebe el comportamiento
	// del servicio y no un artefacto del doble.
	h.indexer.index = "5f4dcc3b5aa765d61d8327deb882cf99"
	svc := h.service(t)

	if _, _, err := svc.SignIn(context.Background(), []byte("e"), []byte("c")); err == nil {
		t.Fatal("se esperaba un error")
	}

	logs := h.logs.String()
	for _, esperado := range []string{"WARN", "intento de inicio de sesión rechazado", "dni_hashed", "dni inexistente"} {
		if !strings.Contains(logs, esperado) {
			t.Errorf("el log debería incluir %q: %s", esperado, logs)
		}
	}
	for _, prohibido := range []string{validDNI, validPassword} {
		if strings.Contains(logs, prohibido) {
			t.Errorf("el log filtra un dato sensible (%q): %s", prohibido, logs)
		}
	}
}
