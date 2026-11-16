package http_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	delivery "github.com/matiasfelau/vinculo-vial-identity/internal/delivery/http"
	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/validation"
)

// Dobles de los servicios de US-13. Guardan lo que recibieron, para comprobar
// que el handler decodifica el sobre antes de delegarlo.

type emailVerificationServiceMock struct {
	token     string
	expiresIn time.Duration
	err       error

	requestCalls, confirmCalls int
	ephemeralPublicKey         []byte
	ciphertext                 []byte
}

func (m *emailVerificationServiceMock) Request(_ context.Context, eph, ct []byte) error {
	m.requestCalls++
	m.ephemeralPublicKey, m.ciphertext = eph, ct
	return m.err
}

func (m *emailVerificationServiceMock) Confirm(_ context.Context, eph, ct []byte) (string, time.Duration, error) {
	m.confirmCalls++
	m.ephemeralPublicKey, m.ciphertext = eph, ct
	if m.err != nil {
		return "", 0, m.err
	}
	return m.token, m.expiresIn, nil
}

type passwordResetServiceMock struct {
	token     string
	expiresIn time.Duration
	err       error

	requestCalls, confirmCalls, completeCalls int
	ephemeralPublicKey                        []byte
	ciphertext                                []byte
}

func (m *passwordResetServiceMock) Request(_ context.Context, eph, ct []byte) error {
	m.requestCalls++
	m.ephemeralPublicKey, m.ciphertext = eph, ct
	return m.err
}

func (m *passwordResetServiceMock) Confirm(_ context.Context, eph, ct []byte) (string, time.Duration, error) {
	m.confirmCalls++
	m.ephemeralPublicKey, m.ciphertext = eph, ct
	if m.err != nil {
		return "", 0, m.err
	}
	return m.token, m.expiresIn, nil
}

func (m *passwordResetServiceMock) Complete(_ context.Context, eph, ct []byte) error {
	m.completeCalls++
	m.ephemeralPublicKey, m.ciphertext = eph, ct
	return m.err
}

const (
	pathEmailRequest = "/api/v1/auth/email-verifications"
	pathEmailConfirm = "/api/v1/auth/email-verifications/confirm"
	pathResetRequest = "/api/v1/auth/password-resets"
	pathResetConfirm = "/api/v1/auth/password-resets/confirm"
	pathResetDone    = "/api/v1/auth/password-resets/complete"
)

// endpointDeRecuperacion describe uno de los cinco endpoints de US-13 y cómo
// hacer que su servicio devuelva un error.
type endpointDeRecuperacion struct {
	name string
	path string
	// fail configura el error del servicio que atiende el endpoint.
	fail func(ts *testServer, err error)
	// calls cuenta las llamadas que recibió el servicio.
	calls func(ts *testServer) int
}

func endpointsDeRecuperacion() []endpointDeRecuperacion {
	return []endpointDeRecuperacion{
		{"email-verifications", pathEmailRequest,
			func(ts *testServer, err error) { ts.emailSvc.err = err },
			func(ts *testServer) int { return ts.emailSvc.requestCalls }},
		{"email-verifications/confirm", pathEmailConfirm,
			func(ts *testServer, err error) { ts.emailSvc.err = err },
			func(ts *testServer) int { return ts.emailSvc.confirmCalls }},
		{"password-resets", pathResetRequest,
			func(ts *testServer, err error) { ts.resetSvc.err = err },
			func(ts *testServer) int { return ts.resetSvc.requestCalls }},
		{"password-resets/confirm", pathResetConfirm,
			func(ts *testServer, err error) { ts.resetSvc.err = err },
			func(ts *testServer) int { return ts.resetSvc.confirmCalls }},
		{"password-resets/complete", pathResetDone,
			func(ts *testServer, err error) { ts.resetSvc.err = err },
			func(ts *testServer) int { return ts.resetSvc.completeCalls }},
	}
}

func TestPedidosDeCodigoDevuelven202ConCuerpoVacio(t *testing.T) {
	for _, path := range []string{pathEmailRequest, pathResetRequest} {
		t.Run(path, func(t *testing.T) {
			ts := newTestServer(t, nil)

			rec := ts.post(t, path, signUpBodyCon("clave-efimera", "criptograma"))

			if rec.Code != http.StatusAccepted {
				t.Fatalf("status = %d, se esperaba 202 (%s)", rec.Code, rec.Body.String())
			}
			if got := strings.TrimSpace(rec.Body.String()); got != "{}" {
				t.Errorf("cuerpo = %q, se esperaba {}: el 202 no puede llevar nada que dependa de la cuenta", got)
			}
		})
	}
}

// El 202 es idéntico en status y cuerpo con independencia de lo que el servicio
// haya hecho por dentro: el handler no tiene forma de distinguirlo, y este test
// fija que tampoco lo intenta.
func TestElPedidoDeCodigoDevuelveLoMismoSinImportarElResultadoInterno(t *testing.T) {
	a := newTestServer(t, nil)
	b := newTestServer(t, nil)

	recA := a.post(t, pathResetRequest, signUpBodyCon("clave-efimera", "criptograma"))
	recB := b.post(t, pathResetRequest, signUpBodyCon("otra-clave", "otro-criptograma"))

	if recA.Code != recB.Code || recA.Body.String() != recB.Body.String() {
		t.Errorf("las respuestas difieren: %d %q vs %d %q", recA.Code, recA.Body.String(), recB.Code, recB.Body.String())
	}
}

func TestLasConfirmacionesDevuelven200ConElTokenYLosSegundos(t *testing.T) {
	casos := []struct {
		path      string
		tokenKey  string
		tokenWant string
		secsWant  float64
	}{
		{pathEmailConfirm, "verification_token", "verification-token", 1800},
		{pathResetConfirm, "reset_token", "reset-token", 900},
	}
	for _, tc := range casos {
		t.Run(tc.path, func(t *testing.T) {
			ts := newTestServer(t, nil)

			rec := ts.post(t, tc.path, signUpBodyCon("clave-efimera", "criptograma"))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, se esperaba 200 (%s)", rec.Code, rec.Body.String())
			}
			body := decodeError(t, rec)
			if body[tc.tokenKey] != tc.tokenWant {
				t.Errorf("%s = %v, se esperaba %q", tc.tokenKey, body[tc.tokenKey], tc.tokenWant)
			}
			if body["expires_in"] != tc.secsWant {
				t.Errorf("expires_in = %v, se esperaban %v segundos", body["expires_in"], tc.secsWant)
			}
		})
	}
}

func TestLaRevalidacionExitosaDevuelve204SinCuerpo(t *testing.T) {
	ts := newTestServer(t, nil)

	rec := ts.post(t, pathResetDone, signUpBodyCon("clave-efimera", "criptograma"))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, se esperaba 204 (%s)", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Errorf("el 204 lleva cuerpo: %q", rec.Body.String())
	}
}

// El handler decodifica las dos piezas del sobre antes de delegarlas, como el
// alta y el login.
func TestLosEndpointsDeRecuperacionDecodificanElSobre(t *testing.T) {
	for _, ep := range endpointsDeRecuperacion() {
		t.Run(ep.name, func(t *testing.T) {
			ts := newTestServer(t, nil)

			ts.post(t, ep.path, signUpBodyCon("clave-efimera", "criptograma"))

			if ep.calls(ts) != 1 {
				t.Fatalf("el servicio recibió %d llamadas, se esperaba 1", ep.calls(ts))
			}
			eph, ct := ts.emailSvc.ephemeralPublicKey, ts.emailSvc.ciphertext
			if strings.HasPrefix(ep.name, "password") {
				eph, ct = ts.resetSvc.ephemeralPublicKey, ts.resetSvc.ciphertext
			}
			if string(eph) != "clave-efimera" || string(ct) != "criptograma" {
				t.Errorf("el servicio recibió (%q, %q), se esperaban las piezas ya decodificadas", eph, ct)
			}
		})
	}
}

func TestLosEndpointsDeRecuperacionRechazanSobresInvalidosSinLlamarAlServicio(t *testing.T) {
	casos := map[string]string{
		"no es JSON":            `{`,
		"sin ephemeral":         `{"ciphertext":"Y3Q="}`,
		"sin ciphertext":        `{"ephemeral_public_key":"ZXBo"}`,
		"ephemeral no base64":   `{"ephemeral_public_key":"@@@","ciphertext":"Y3Q="}`,
		"ciphertext no base64":  `{"ephemeral_public_key":"ZXBo","ciphertext":"@@@"}`,
		"campo de tipo erróneo": `{"ephemeral_public_key":1,"ciphertext":"Y3Q="}`,
	}
	for _, ep := range endpointsDeRecuperacion() {
		for name, body := range casos {
			t.Run(ep.name+"/"+name, func(t *testing.T) {
				ts := newTestServer(t, nil)

				rec := ts.post(t, ep.path, body)

				if rec.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, se esperaba 400", rec.Code)
				}
				if got := decodeError(t, rec)["code"]; got != "solicitud_invalida" {
					t.Errorf("code = %v, se esperaba solicitud_invalida", got)
				}
				if ep.calls(ts) != 0 {
					t.Errorf("el servicio recibió %d llamadas, se esperaba 0", ep.calls(ts))
				}
			})
		}
	}
}

func TestLosErroresDeRecuperacionSeMapeanALosCodigosDelContrato(t *testing.T) {
	invalidInput := fmt.Errorf("%w: detalle", domain.ErrInvalidInput)

	casos := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{"código inválido", domain.ErrInvalidCode, http.StatusBadRequest, "INVALID_CODE"},
		{"código inválido envuelto", fmt.Errorf("capa: %w", domain.ErrInvalidCode), http.StatusBadRequest, "INVALID_CODE"},
		{"reset token inválido", domain.ErrInvalidResetToken, http.StatusBadRequest, "INVALID_RESET_TOKEN"},
		{"identidad no verificada", domain.ErrIdentityNotVerified, http.StatusBadRequest, "identidad_no_verificada"},
		{"datos inválidos", invalidInput, http.StatusBadRequest, "datos_invalidos"},
		{"sobre mal formado", domain.ErrMalformedCryptogram, http.StatusBadRequest, "solicitud_invalida"},
		{"criptograma que no autentica", domain.ErrInvalidCryptogram, http.StatusInternalServerError, "error_interno"},
		{"base caída", domain.ErrDatabaseUnavailable, http.StatusServiceUnavailable, "dependencia_no_disponible"},
		{"RENAPER caído", fmt.Errorf("x: %w", domain.ErrUpstreamUnavailable), http.StatusServiceUnavailable, "dependencia_no_disponible"},
		{"RENAPER responde mal", domain.ErrUpstreamInvalidResponse, http.StatusBadGateway, "upstream_invalido"},
		{"error inesperado", errors.New("secreto interno: dni=30123456"), http.StatusInternalServerError, "error_interno"},
	}

	for _, ep := range endpointsDeRecuperacion() {
		for _, tc := range casos {
			t.Run(ep.name+"/"+tc.name, func(t *testing.T) {
				ts := newTestServer(t, nil)
				ep.fail(ts, tc.err)

				rec := ts.post(t, ep.path, signUpBodyCon("clave-efimera", "criptograma"))

				if rec.Code != tc.wantStatus {
					t.Fatalf("status = %d, se esperaba %d (%s)", rec.Code, tc.wantStatus, rec.Body.String())
				}
				body := decodeError(t, rec)
				if body["code"] != tc.wantCode {
					t.Errorf("code = %v, se esperaba %q", body["code"], tc.wantCode)
				}
				if body["requestId"] == "" || body["requestId"] == nil {
					t.Error("el error no trae requestId")
				}
				if strings.Contains(rec.Body.String(), "secreto interno") || strings.Contains(rec.Body.String(), "30123456") {
					t.Errorf("la respuesta expone el error subyacente: %s", rec.Body.String())
				}
			})
		}
	}
}

func TestLasDependenciasCaidasDevuelvenRetryAfter(t *testing.T) {
	for _, err := range []error{domain.ErrDatabaseUnavailable, domain.ErrUpstreamUnavailable} {
		ts := newTestServer(t, nil)
		ts.resetSvc.err = err

		rec := ts.post(t, pathResetDone, signUpBodyCon("clave-efimera", "criptograma"))

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, se esperaba 503", rec.Code)
		}
		if got := rec.Header().Get("Retry-After"); got == "" {
			t.Errorf("falta Retry-After en el 503 (%v)", err)
		}
	}
}

func TestLosDatosInvalidosDetallanLosCamposSinExponerValores(t *testing.T) {
	ts := newTestServer(t, nil)
	var errs validation.Errors
	errs = append(errs, validation.FieldError{Field: "password", Code: validation.CodeWeak, Message: "la contraseña es débil"})
	ts.resetSvc.err = fmt.Errorf("%w: %w", domain.ErrInvalidInput, errs)

	rec := ts.post(t, pathResetDone, signUpBodyCon("clave-efimera", "criptograma"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, se esperaba 400", rec.Code)
	}
	body := decodeError(t, rec)
	if body["code"] != "datos_invalidos" {
		t.Fatalf("code = %v, se esperaba datos_invalidos", body["code"])
	}
	details, ok := body["details"].([]any)
	if !ok || len(details) != 1 {
		t.Fatalf("details = %v, se esperaba el detalle del campo", body["details"])
	}
	if !strings.Contains(ts.logs.String(), "password") {
		t.Error("el rechazo de validación no quedó en el log")
	}
}

// Ningún log de la verificación y la recuperación incluye el contenido del
// sobre.
func TestLosEndpointsDeRecuperacionNoLoguenElSobre(t *testing.T) {
	ts := newTestServer(t, nil)
	ts.emailSvc.err = errors.New("falla")

	ts.post(t, pathEmailConfirm, signUpBodyCon("clave-efimera-secreta", "criptograma-secreto"))

	for _, secreto := range []string{"clave-efimera-secreta", "criptograma-secreto"} {
		if strings.Contains(ts.logs.String(), secreto) {
			t.Errorf("el log contiene %q", secreto)
		}
	}
}

func TestLosPedidosDeRecuperacionTienenUnTopeDeCuerpoPropio(t *testing.T) {
	grande := signUpBodyCon("clave-efimera", strings.Repeat("a", 16<<10))

	for _, path := range []string{pathEmailRequest, pathEmailConfirm, pathResetRequest, pathResetConfirm} {
		t.Run(path, func(t *testing.T) {
			ts := newTestServer(t, nil)

			rec := ts.post(t, path, grande)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, se esperaba 400 por cuerpo desmesurado", rec.Code)
			}
			if ts.emailSvc.requestCalls+ts.emailSvc.confirmCalls+ts.resetSvc.requestCalls+ts.resetSvc.confirmCalls != 0 {
				t.Error("el servicio recibió un cuerpo que superaba el tope")
			}
		})
	}
}

// La revalidación lleva una selfie: usa el tope del alta, no el de los pedidos.
func TestLaRevalidacionAceptaUnCuerpoConSelfie(t *testing.T) {
	ts := newTestServer(t, nil)

	rec := ts.post(t, pathResetDone, signUpBodyCon("clave-efimera", strings.Repeat("a", 64<<10)))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, se esperaba 204 (%s)", rec.Code, rec.Body.String())
	}
}

func TestLasRespuestasDeRecuperacionNoSeCachean(t *testing.T) {
	for _, ep := range endpointsDeRecuperacion() {
		ts := newTestServer(t, nil)

		rec := ts.post(t, ep.path, signUpBodyCon("clave-efimera", "criptograma"))

		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control = %q, se esperaba no-store", ep.name, got)
		}
	}
}

func TestLosEndpointsDeRecuperacionSoloAdmitenPOST(t *testing.T) {
	ts := newTestServer(t, nil)
	for _, ep := range endpointsDeRecuperacion() {
		rec := httptest.NewRecorder()
		ts.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, ep.path, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: GET devolvió %d, se esperaba 405", ep.name, rec.Code)
		}
	}
}

func TestSignUpMapeaEmailNoVerificado(t *testing.T) {
	ts := newTestServer(t, nil)
	ts.svc.err = domain.ErrEmailNotVerified

	rec := ts.post(t, "/api/v1/auth/signup", signUpBody("criptograma"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, se esperaba 400", rec.Code)
	}
	if got := decodeError(t, rec)["code"]; got != "EMAIL_NOT_VERIFIED" {
		t.Errorf("code = %v, se esperaba EMAIL_NOT_VERIFIED", got)
	}
}

func TestNewRouterExigeLosServiciosDeRecuperacion(t *testing.T) {
	base := func() delivery.RouterConfig {
		return delivery.RouterConfig{
			SignUp:            &serviceMock{},
			SignIn:            &signInServiceMock{},
			Refresh:           &refreshServiceMock{},
			Logout:            &logoutServiceMock{},
			DeleteAccount:     &deleteAccountServiceMock{},
			EmailVerification: &emailVerificationServiceMock{},
			PasswordReset:     &passwordResetServiceMock{},
			Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
	}

	t.Run("completo", func(t *testing.T) {
		if _, err := delivery.NewRouter(base()); err != nil {
			t.Fatalf("la configuración completa falló: %v", err)
		}
	})
	t.Run("sin verificación de email", func(t *testing.T) {
		cfg := base()
		cfg.EmailVerification = nil
		if _, err := delivery.NewRouter(cfg); err == nil {
			t.Error("se esperaba un error sin el servicio de verificación de email")
		}
	})
	t.Run("sin recuperación de contraseña", func(t *testing.T) {
		cfg := base()
		cfg.PasswordReset = nil
		if _, err := delivery.NewRouter(cfg); err == nil {
			t.Error("se esperaba un error sin el servicio de recuperación de contraseña")
		}
	})
}

func TestNewRecoveryHandlerAceptaUnLoggerNulo(t *testing.T) {
	if _, err := delivery.NewRecoveryHandler(&emailVerificationServiceMock{}, &passwordResetServiceMock{}, nil); err != nil {
		t.Fatalf("un logger nulo debería usar el de por defecto: %v", err)
	}
}
