package http_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	delivery "github.com/matiasfelau/vinculo-vial-identity/internal/delivery/http"
	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/validation"
)

type serviceMock struct {
	userID uuid.UUID
	err    error

	calls      int
	cryptogram []byte
}

func (m *serviceMock) SignUp(_ context.Context, cryptogram []byte) (uuid.UUID, error) {
	m.calls++
	m.cryptogram = cryptogram
	if m.err != nil {
		return uuid.Nil, m.err
	}
	return m.userID, nil
}

type testServer struct {
	handler http.Handler
	svc     *serviceMock
	logs    *strings.Builder
}

func newTestServer(t *testing.T, ready func(context.Context) error) *testServer {
	t.Helper()

	svc := &serviceMock{userID: uuid.New()}
	logs := &strings.Builder{}

	router, err := delivery.NewRouter(delivery.RouterConfig{
		SignUp:         svc,
		Logger:         slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		ReadinessCheck: ready,
	})
	if err != nil {
		t.Fatalf("no se pudo armar el router: %v", err)
	}

	return &testServer{handler: router, svc: svc, logs: logs}
}

func (ts *testServer) post(t *testing.T, path, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, req)
	return rec
}

func signUpBody(cryptogram string) string {
	payload, _ := json.Marshal(map[string]string{
		"cryptogram": base64.StdEncoding.EncodeToString([]byte(cryptogram)),
	})
	return string(payload)
}

func decodeError(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("la respuesta no es JSON: %v (%s)", err, rec.Body.String())
	}
	return body
}

func TestSignUpDevuelve201(t *testing.T) {
	ts := newTestServer(t, nil)

	rec := ts.post(t, "/api/v1/auth/signup", signUpBody("criptograma"))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, se esperaba 201 (%s)", rec.Code, rec.Body.String())
	}

	var body struct {
		UserID string `json:"userId"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("la respuesta no es JSON: %v", err)
	}
	if body.UserID != ts.svc.userID.String() {
		t.Errorf("userId = %q, se esperaba %q", body.UserID, ts.svc.userID)
	}

	// El 201 no emite sesión: la autenticación es US-02.
	for _, prohibido := range []string{"token", "accessToken", "refreshToken"} {
		if strings.Contains(rec.Body.String(), prohibido) {
			t.Errorf("la respuesta del alta no debe contener %q: %s", prohibido, rec.Body.String())
		}
	}
}

func TestSignUpDecodificaElCriptogramaAntesDeDelegarlo(t *testing.T) {
	ts := newTestServer(t, nil)

	if rec := ts.post(t, "/api/v1/auth/signup", signUpBody("criptograma")); rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, se esperaba 201", rec.Code)
	}

	if got := string(ts.svc.cryptogram); got != "criptograma" {
		t.Errorf("el servicio recibió %q, se esperaba el criptograma decodificado", got)
	}
}

func TestSignUpDevuelve400AnteCuerposInvalidos(t *testing.T) {
	cases := map[string]string{
		"cuerpo vacío":             ``,
		"JSON malformado":          `{"cryptogram":`,
		"cryptogram ausente":       `{}`,
		"cryptogram vacío":         `{"cryptogram":""}`,
		"cryptogram no es base64":  `{"cryptogram":"no-es-base64-!!!"}`,
		"cryptogram no es cadena":  `{"cryptogram":42}`,
		"cuerpo que no es un mapa": `["criptograma"]`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			ts := newTestServer(t, nil)

			rec := ts.post(t, "/api/v1/auth/signup", body)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, se esperaba 400 (%s)", rec.Code, rec.Body.String())
			}
			// Un cuerpo ilegible no debe llegar al caso de uso.
			if ts.svc.calls != 0 {
				t.Error("el servicio no debería invocarse con un cuerpo inválido")
			}
		})
	}
}

func TestSignUpMapeaLosErroresDeDominio(t *testing.T) {
	cases := map[string]struct {
		err    error
		status int
		code   string
	}{
		"datos inválidos":      {domain.ErrInvalidInput, http.StatusBadRequest, "datos_invalidos"},
		"usuario duplicado":    {domain.ErrDuplicateUser, http.StatusConflict, "registro_no_disponible"},
		"criptograma ilegible": {domain.ErrInvalidCryptogram, http.StatusInternalServerError, "error_interno"},
		"fallo inesperado":     {errors.New("la base no responde"), http.StatusInternalServerError, "error_interno"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ts := newTestServer(t, nil)
			ts.svc.err = tc.err

			rec := ts.post(t, "/api/v1/auth/signup", signUpBody("criptograma"))

			if rec.Code != tc.status {
				t.Fatalf("status = %d, se esperaba %d (%s)", rec.Code, tc.status, rec.Body.String())
			}
			if got := decodeError(t, rec)["code"]; got != tc.code {
				t.Errorf("code = %v, se esperaba %q", got, tc.code)
			}
		})
	}
}

// Distinguir "ese email ya existe" de "ese DNI ya existe" permitiría averiguar
// si una persona concreta está registrada.
func TestConflictoNoRevelaQueDatoColisiono(t *testing.T) {
	ts := newTestServer(t, nil)
	ts.svc.err = domain.ErrDuplicateUser

	rec := ts.post(t, "/api/v1/auth/signup", signUpBody("criptograma"))

	cuerpo := strings.ToLower(rec.Body.String())
	for _, filtracion := range []string{"email", "dni", "duplicad", "existe"} {
		if strings.Contains(cuerpo, filtracion) {
			t.Errorf("el 409 menciona %q y permite enumerar usuarios: %s", filtracion, rec.Body.String())
		}
	}
}

// El 400 sí detalla los campos, para que la app corrija el formulario de una
// vez, pero nunca los valores rechazados.
func TestErrorDeValidacionDetallaCamposSinExponerValores(t *testing.T) {
	ts := newTestServer(t, nil)
	ts.svc.err = validation.Errors{
		{Field: "email", Code: validation.CodeFormat, Message: "el dominio del email no es válido"},
		{Field: "dni", Code: validation.CodeLength, Message: "el DNI debe tener entre 7 y 8 dígitos"},
	}

	rec := ts.post(t, "/api/v1/auth/signup", signUpBody("criptograma"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, se esperaba 400", rec.Code)
	}

	var body struct {
		Code    string                  `json:"code"`
		Details []validation.FieldError `json:"details"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("la respuesta no es JSON: %v", err)
	}
	if len(body.Details) != 2 {
		t.Fatalf("se devolvieron %d detalles, se esperaban 2: %s", len(body.Details), rec.Body.String())
	}
	if body.Details[0].Field != "email" || body.Details[1].Field != "dni" {
		t.Errorf("los campos rechazados no coinciden: %+v", body.Details)
	}
}

// El detalle criptográfico no puede salir en la respuesta: convertiría al
// endpoint en un oráculo sobre el estado de las claves.
func TestErrorCriptograficoNoSeFiltraEnLaRespuesta(t *testing.T) {
	ts := newTestServer(t, nil)
	ts.svc.err = domain.ErrInvalidCryptogram

	rec := ts.post(t, "/api/v1/auth/signup", signUpBody("criptograma"))

	cuerpo := strings.ToLower(rec.Body.String())
	for _, filtracion := range []string{"hpke", "aead", "clave", "criptograma", "descifr"} {
		if strings.Contains(cuerpo, filtracion) {
			t.Errorf("el 500 filtra detalle criptográfico (%q): %s", filtracion, rec.Body.String())
		}
	}
	// Pero sí debe quedar registrado del lado del servidor.
	if !strings.Contains(ts.logs.String(), "criptograma") {
		t.Error("el fallo de descifrado debe quedar en el log del servidor")
	}
}

func TestRespuestaCorrelacionaConElRequestID(t *testing.T) {
	ts := newTestServer(t, nil)

	t.Run("propaga el que envía el gateway", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", strings.NewReader(signUpBody("criptograma")))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(delivery.HeaderRequestID, "trace-de-kong")

		rec := httptest.NewRecorder()
		ts.handler.ServeHTTP(rec, req)

		if got := rec.Header().Get(delivery.HeaderRequestID); got != "trace-de-kong" {
			t.Errorf("request id = %q, se esperaba el del gateway", got)
		}
	})

	t.Run("genera uno si falta", func(t *testing.T) {
		rec := ts.post(t, "/api/v1/auth/signup", signUpBody("criptograma"))

		if got := rec.Header().Get(delivery.HeaderRequestID); got == "" {
			t.Error("se esperaba un request id generado")
		}
	})
}

func TestErrorIncluyeElRequestIDParaCorrelacionar(t *testing.T) {
	ts := newTestServer(t, nil)
	ts.svc.err = domain.ErrDuplicateUser

	rec := ts.post(t, "/api/v1/auth/signup", signUpBody("criptograma"))

	if decodeError(t, rec)["requestId"] == "" {
		t.Error("el error debe llevar el request id para poder correlacionarlo con el log")
	}
}

// Sin tope, un cliente podría hacer consumir memoria arbitraria antes siquiera
// de intentar descifrar.
func TestCuerpoDesmesuradoSeRechaza(t *testing.T) {
	ts := newTestServer(t, nil)

	rec := ts.post(t, "/api/v1/auth/signup", signUpBody(strings.Repeat("a", int(delivery.DefaultMaxBodyBytes)*2)))

	if rec.Code == http.StatusCreated {
		t.Errorf("un cuerpo por encima del tope no debería aceptarse (status %d)", rec.Code)
	}
	if ts.svc.calls != 0 {
		t.Error("el servicio no debería invocarse con un cuerpo por encima del tope")
	}
}

// El cuerpo es el criptograma: loguearlo dejaría material criptográfico en el
// agregador sin utilidad para diagnosticar.
func TestElLogDeAccesoNoIncluyeElCuerpo(t *testing.T) {
	ts := newTestServer(t, nil)

	body := signUpBody("criptograma-secreto")
	if rec := ts.post(t, "/api/v1/auth/signup", body); rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, se esperaba 201", rec.Code)
	}

	logs := ts.logs.String()
	if strings.Contains(logs, base64.StdEncoding.EncodeToString([]byte("criptograma-secreto"))) {
		t.Errorf("el log de acceso incluye el cuerpo: %s", logs)
	}
	if !strings.Contains(logs, "/api/v1/auth/signup") {
		t.Errorf("el log de acceso debería registrar la ruta: %s", logs)
	}
}

func TestRespuestasDeAutenticacionNoSeCachean(t *testing.T) {
	ts := newTestServer(t, nil)

	rec := ts.post(t, "/api/v1/auth/signup", signUpBody("criptograma"))

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, se esperaba no-store", got)
	}
}

func TestHealthz(t *testing.T) {
	ts := newTestServer(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, se esperaba 200", rec.Code)
	}
}

func TestReadyz(t *testing.T) {
	t.Run("200 con las dependencias sanas", func(t *testing.T) {
		ts := newTestServer(t, func(context.Context) error { return nil })

		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		rec := httptest.NewRecorder()
		ts.handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, se esperaba 200", rec.Code)
		}
	})

	t.Run("503 si una dependencia no responde", func(t *testing.T) {
		ts := newTestServer(t, func(context.Context) error { return errors.New("la base no responde") })

		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		rec := httptest.NewRecorder()
		ts.handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, se esperaba 503", rec.Code)
		}
		// El motivo va al log, no al cuerpo: /readyz lo lee cualquiera que
		// alcance el puerto.
		if strings.Contains(rec.Body.String(), "la base no responde") {
			t.Errorf("el cuerpo revela el motivo del fallo: %s", rec.Body.String())
		}
		if !strings.Contains(ts.logs.String(), "la base no responde") {
			t.Error("el motivo debería quedar en el log")
		}
	})
}

func TestRutasYMetodosNoSoportados(t *testing.T) {
	ts := newTestServer(t, nil)

	t.Run("404 en una ruta inexistente", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/inexistente", nil)
		rec := httptest.NewRecorder()
		ts.handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("status = %d, se esperaba 404", rec.Code)
		}
	})

	t.Run("405 con el método equivocado", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/signup", nil)
		rec := httptest.NewRecorder()
		ts.handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, se esperaba 405", rec.Code)
		}
	})
}

func TestNewRouterExigeElServicio(t *testing.T) {
	if _, err := delivery.NewRouter(delivery.RouterConfig{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}); err == nil {
		t.Error("se esperaba un error al armar el router sin servicio")
	}
}
