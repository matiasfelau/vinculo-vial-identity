package http_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
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

	calls              int
	ephemeralPublicKey []byte
	ciphertext         []byte
}

func (m *serviceMock) SignUp(_ context.Context, ephemeralPublicKey, ciphertext []byte) (uuid.UUID, error) {
	m.calls++
	m.ephemeralPublicKey = ephemeralPublicKey
	m.ciphertext = ciphertext
	if m.err != nil {
		return uuid.Nil, m.err
	}
	return m.userID, nil
}

type signInServiceMock struct {
	accessToken  string
	refreshToken string
	err          error

	calls              int
	ephemeralPublicKey []byte
	ciphertext         []byte
}

func (m *signInServiceMock) SignIn(_ context.Context, ephemeralPublicKey, ciphertext []byte) (string, string, error) {
	m.calls++
	m.ephemeralPublicKey = ephemeralPublicKey
	m.ciphertext = ciphertext
	if m.err != nil {
		return "", "", m.err
	}
	return m.accessToken, m.refreshToken, nil
}

type refreshServiceMock struct {
	accessToken  string
	refreshToken string
	err          error

	calls         int
	receivedToken string
}

func (m *refreshServiceMock) Refresh(_ context.Context, refreshToken string) (string, string, error) {
	m.calls++
	m.receivedToken = refreshToken
	if m.err != nil {
		return "", "", m.err
	}
	return m.accessToken, m.refreshToken, nil
}

type logoutServiceMock struct {
	err error

	calls         int
	receivedToken string
}

func (m *logoutServiceMock) Logout(_ context.Context, refreshToken string) error {
	m.calls++
	m.receivedToken = refreshToken
	return m.err
}

type testServer struct {
	handler    http.Handler
	svc        *serviceMock
	signInSvc  *signInServiceMock
	refreshSvc *refreshServiceMock
	logoutSvc  *logoutServiceMock
	logs       *strings.Builder
}

func newTestServer(t *testing.T, ready func(context.Context) error) *testServer {
	t.Helper()

	svc := &serviceMock{userID: uuid.New()}
	signInSvc := &signInServiceMock{accessToken: "access-token", refreshToken: "refresh-token"}
	refreshSvc := &refreshServiceMock{accessToken: "access-token-rotado", refreshToken: "refresh-token-rotado"}
	logoutSvc := &logoutServiceMock{}
	logs := &strings.Builder{}

	router, err := delivery.NewRouter(delivery.RouterConfig{
		SignUp:         svc,
		SignIn:         signInSvc,
		Refresh:        refreshSvc,
		Logout:         logoutSvc,
		Logger:         slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		ReadinessCheck: ready,
	})
	if err != nil {
		t.Fatalf("no se pudo armar el router: %v", err)
	}

	return &testServer{handler: router, svc: svc, signInSvc: signInSvc, refreshSvc: refreshSvc, logoutSvc: logoutSvc, logs: logs}
}

func (ts *testServer) post(t *testing.T, path, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, req)
	return rec
}

// signUpBody arma el cuerpo del contrato compartido: las dos piezas del mensaje
// HPKE, cada una en base64. El handler no interpreta su contenido —eso es del
// descifrador—, así que los tests le pasan texto plano reconocible.
func signUpBody(ciphertext string) string {
	return signUpBodyCon("clave-efimera", ciphertext)
}

func signUpBodyCon(ephemeralPublicKey, ciphertext string) string {
	payload, _ := json.Marshal(map[string]string{
		"ephemeral_public_key": base64.StdEncoding.EncodeToString([]byte(ephemeralPublicKey)),
		"ciphertext":           base64.StdEncoding.EncodeToString([]byte(ciphertext)),
	})
	return string(payload)
}

// signInBody arma el cuerpo del login: el mismo wrapper HPKE de dos piezas que
// el alta, así que reutiliza exactamente la misma forma de sobre.
func signInBody(ciphertext string) string {
	return signInBodyCon("clave-efimera", ciphertext)
}

func signInBodyCon(ephemeralPublicKey, ciphertext string) string {
	payload, _ := json.Marshal(map[string]string{
		"ephemeral_public_key": base64.StdEncoding.EncodeToString([]byte(ephemeralPublicKey)),
		"ciphertext":           base64.StdEncoding.EncodeToString([]byte(ciphertext)),
	})
	return string(payload)
}

// refreshBody arma el cuerpo de /refresh: JSON plano con el Refresh Token
// opaco, sin el wrapper HPKE que sí usan /signup y /signin.
func refreshBody(refreshToken string) string {
	payload, _ := json.Marshal(map[string]string{"refresh_token": refreshToken})
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

// Las dos piezas llegan en base64 y se delegan decodificadas, cada una en su
// argumento: intercambiarlas rompería el descifrado de forma difícil de
// diagnosticar, así que el test las distingue por contenido.
func TestSignUpDecodificaLasDosPiezasAntesDeDelegarlas(t *testing.T) {
	ts := newTestServer(t, nil)

	body := signUpBodyCon("la-clave-efimera", "el-ciphertext")
	if rec := ts.post(t, "/api/v1/auth/signup", body); rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, se esperaba 201", rec.Code)
	}

	if got := string(ts.svc.ephemeralPublicKey); got != "la-clave-efimera" {
		t.Errorf("ephemeral_public_key = %q, se esperaba la clave efímera decodificada", got)
	}
	if got := string(ts.svc.ciphertext); got != "el-ciphertext" {
		t.Errorf("ciphertext = %q, se esperaba el ciphertext decodificado", got)
	}
}

// El contrato dice "base64" sin precisar variante, y cada plataforma elige por
// su cuenta. Rechazar la URL-safe o la que viene sin relleno convertiría esa
// diferencia en un 400 a diagnosticar entre repositorios.
func TestSignUpAceptaLasVariantesDeBase64(t *testing.T) {
	const enc = "clave-efimera"
	// Contiene un byte 0xFF, que en el alfabeto estándar produce `/` y en el
	// URL-safe `_`: sin un valor así las dos variantes serían idénticas y el test
	// no distinguiría nada.
	ct := []byte{0xFF, 0xFE, 0xFD, 0x01}

	variantes := map[string]*base64.Encoding{
		"estándar con relleno": base64.StdEncoding,
		"estándar sin relleno": base64.RawStdEncoding,
		"URL-safe con relleno": base64.URLEncoding,
		"URL-safe sin relleno": base64.RawURLEncoding,
	}

	for name, codificacion := range variantes {
		t.Run(name, func(t *testing.T) {
			ts := newTestServer(t, nil)

			body, _ := json.Marshal(map[string]string{
				"ephemeral_public_key": codificacion.EncodeToString([]byte(enc)),
				"ciphertext":           codificacion.EncodeToString(ct),
			})

			rec := ts.post(t, "/api/v1/auth/signup", string(body))

			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d, se esperaba 201 (%s)", rec.Code, rec.Body.String())
			}
			// Las cuatro variantes tienen que producir exactamente los mismos
			// bytes: aceptar de más no puede significar decodificar distinto.
			if got := string(ts.svc.ephemeralPublicKey); got != enc {
				t.Errorf("ephemeral_public_key = %q, se esperaba %q", got, enc)
			}
			if got := ts.svc.ciphertext; !bytes.Equal(got, ct) {
				t.Errorf("ciphertext = %v, se esperaba %v", got, ct)
			}
		})
	}
}

func TestSignUpDevuelve400AnteCuerposInvalidos(t *testing.T) {
	valida := base64.StdEncoding.EncodeToString([]byte("clave-efimera"))

	cases := map[string]string{
		"cuerpo vacío":                   ``,
		"JSON malformado":                `{"ciphertext":`,
		"cuerpo vacío como objeto":       `{}`,
		"ephemeral_public_key ausente":   `{"ciphertext":"` + valida + `"}`,
		"ephemeral_public_key vacía":     `{"ephemeral_public_key":"","ciphertext":"` + valida + `"}`,
		"ephemeral_public_key no base64": `{"ephemeral_public_key":"no-es-base64-!!!","ciphertext":"` + valida + `"}`,
		"ephemeral_public_key no cadena": `{"ephemeral_public_key":42,"ciphertext":"` + valida + `"}`,
		"ciphertext ausente":             `{"ephemeral_public_key":"` + valida + `"}`,
		"ciphertext vacío":               `{"ephemeral_public_key":"` + valida + `","ciphertext":""}`,
		"ciphertext no base64":           `{"ephemeral_public_key":"` + valida + `","ciphertext":"no-es-base64-!!!"}`,
		"ciphertext no es cadena":        `{"ephemeral_public_key":"` + valida + `","ciphertext":42}`,
		"formato concatenado anterior":   `{"cryptogram":"` + valida + `"}`,
		"cuerpo que no es un mapa":       `["criptograma"]`,
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

// Los tres rechazos del sobre externo (JSON ilegible, campo vacío, campo no
// base64) también quedan en el log del servidor, igual que los rechazos del
// payload interno: `code=solicitud_invalida` sin más contexto no alcanza para
// diagnosticar de qué de los tres se trata.
func TestSignUpDevuelve400AnteCuerposInvalidosQuedaRegistradoEnElLog(t *testing.T) {
	valida := base64.StdEncoding.EncodeToString([]byte("clave-efimera"))

	cases := map[string]struct {
		body     string
		esperado []string
	}{
		"JSON malformado": {
			`{"ciphertext":`,
			[]string{"WARN", "no es JSON interpretable"},
		},
		"ephemeral_public_key ausente": {
			`{"ciphertext":"` + valida + `"}`,
			[]string{"WARN", "campo del sobre HPKE vacío", "ephemeral_public_key"},
		},
		"ciphertext no base64": {
			`{"ephemeral_public_key":"` + valida + `","ciphertext":"no-es-base64-!!!"}`,
			[]string{"WARN", "no es base64 válido", "ciphertext", "longitud_recibida"},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ts := newTestServer(t, nil)

			rec := ts.post(t, "/api/v1/auth/signup", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, se esperaba 400 (%s)", rec.Code, rec.Body.String())
			}

			logs := ts.logs.String()
			for _, esperado := range tc.esperado {
				if !strings.Contains(logs, esperado) {
					t.Errorf("el log debería incluir %q: %s", esperado, logs)
				}
			}
		})
	}
}

// A esta altura ni siquiera se intentó descifrar el mensaje: dni, tramite,
// sexo y selfie siguen dentro del ciphertext. El log del sobre externo no
// puede filtrarlos porque todavía no existen en claro en ningún lado.
func TestSignUpCiphertextNoBase64NoFiltraElValorEnElLog(t *testing.T) {
	ts := newTestServer(t, nil)
	valida := base64.StdEncoding.EncodeToString([]byte("clave-efimera"))
	const basura = "no-es-base64-pero-podria-parecer-sensible-!!!"

	rec := ts.post(t, "/api/v1/auth/signup",
		`{"ephemeral_public_key":"`+valida+`","ciphertext":"`+basura+`"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, se esperaba 400", rec.Code)
	}

	if strings.Contains(ts.logs.String(), basura) {
		t.Errorf("el log incluye el contenido del campo, no solo su longitud: %s", ts.logs.String())
	}
}

func TestSignUpMapeaLosErroresDeDominio(t *testing.T) {
	cases := map[string]struct {
		err    error
		status int
		code   string
	}{
		"datos inválidos":         {domain.ErrInvalidInput, http.StatusBadRequest, "datos_invalidos"},
		"identidad no verificada": {domain.ErrIdentityNotVerified, http.StatusBadRequest, "identidad_no_verificada"},
		"usuario duplicado":       {domain.ErrDuplicateUser, http.StatusConflict, "registro_no_disponible"},
		"criptograma mal formado": {domain.ErrMalformedCryptogram, http.StatusBadRequest, "solicitud_invalida"},
		"criptograma ilegible":    {domain.ErrInvalidCryptogram, http.StatusInternalServerError, "error_interno"},
		"renaper no disponible":   {domain.ErrUpstreamUnavailable, http.StatusServiceUnavailable, "dependencia_no_disponible"},
		"renaper responde mal":    {domain.ErrUpstreamInvalidResponse, http.StatusBadGateway, "upstream_invalido"},
		"base de datos caída":     {domain.ErrDatabaseUnavailable, http.StatusServiceUnavailable, "dependencia_no_disponible"},
		"fallo inesperado":        {errors.New("la base no responde"), http.StatusInternalServerError, "error_interno"},
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

// El mismo motivo que el test anterior: precisar si falló el trámite, el sexo
// o la selfie facilitaría tantear los datos de otra persona hasta acertar.
func TestIdentidadNoVerificadaNoRevelaQueDatoFallo(t *testing.T) {
	ts := newTestServer(t, nil)
	ts.svc.err = domain.ErrIdentityNotVerified

	rec := ts.post(t, "/api/v1/auth/signup", signUpBody("criptograma"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, se esperaba 400", rec.Code)
	}

	cuerpo := strings.ToLower(rec.Body.String())
	for _, filtracion := range []string{"tramite", "trámite", "sexo", "selfie", "renaper"} {
		if strings.Contains(cuerpo, filtracion) {
			t.Errorf("la respuesta menciona %q y permite tantear datos de otra persona: %s", filtracion, rec.Body.String())
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

// El motivo del rechazo también tiene que quedar en el log del servidor, no
// solo en la respuesta: es lo que permite diagnosticar un patrón de rechazos
// (un campo del frontend mal mapeado, una regla que empezó a fallar en masa)
// sin depender de que el cliente reporte el error.
func TestErrorDeValidacionQuedaRegistradoEnElLog(t *testing.T) {
	ts := newTestServer(t, nil)
	ts.svc.err = validation.Errors{
		{Field: "tramite", Code: validation.CodeLength, Message: "el número de trámite debe tener 11 dígitos"},
		{Field: "sexo", Code: validation.CodeFormat, Message: "el sexo debe ser M, F o X"},
	}

	rec := ts.post(t, "/api/v1/auth/signup", signUpBody("criptograma"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, se esperaba 400", rec.Code)
	}

	logs := ts.logs.String()
	for _, esperado := range []string{
		"WARN", "registro rechazado por validación",
		"tramite", "el número de trámite debe tener 11 dígitos",
		"sexo", "el sexo debe ser M, F o X",
	} {
		if !strings.Contains(logs, esperado) {
			t.Errorf("el log debería incluir %q: %s", esperado, logs)
		}
	}
}

// FieldError no tiene un campo Value: no hay dónde filtrar el dato rechazado
// aunque el log quisiera incluirlo. Este test no ejercita una limpieza activa,
// deja constancia de la garantía estructural para que, si alguna vez alguien le
// agrega un campo Value a FieldError, algo en el repo lo obligue a repensarlo.
func TestErrorDeValidacionNoTieneDondeFiltrarElValor(t *testing.T) {
	var fe validation.FieldError
	typ := reflect.TypeOf(fe)

	for i := range typ.NumField() {
		if name := typ.Field(i).Name; name == "Value" || name == "RejectedValue" {
			t.Fatalf("FieldError ganó un campo %q: el log y la respuesta HTTP volverían a filtrar el dato rechazado", name)
		}
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
	if !strings.Contains(ts.logs.String(), "descifrar") {
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

// message repite error bajo una clave más explícita, para clientes que buscan
// esa convención por nombre. No es información nueva, así que alcanza con
// probar que las dos claves coinciden siempre.
func TestErrorIncluyeMessageIgualAError(t *testing.T) {
	ts := newTestServer(t, nil)
	ts.svc.err = domain.ErrDuplicateUser

	rec := ts.post(t, "/api/v1/auth/signup", signUpBody("criptograma"))

	body := decodeError(t, rec)
	if body["message"] == "" {
		t.Fatal("se esperaba el campo message")
	}
	if body["message"] != body["error"] {
		t.Errorf("message = %q, error = %q; deberían coincidir", body["message"], body["error"])
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

func TestReady(t *testing.T) {
	t.Run("200 con las dependencias sanas", func(t *testing.T) {
		ts := newTestServer(t, func(context.Context) error { return nil })

		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		rec := httptest.NewRecorder()
		ts.handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, se esperaba 200", rec.Code)
		}
	})

	t.Run("503 si una dependencia no responde", func(t *testing.T) {
		ts := newTestServer(t, func(context.Context) error { return errors.New("la base no responde") })

		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		rec := httptest.NewRecorder()
		ts.handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, se esperaba 503", rec.Code)
		}
		// El motivo va al log, no al cuerpo: /ready lo lee cualquiera que
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
	t.Run("sin servicio de registro", func(t *testing.T) {
		cfg := delivery.RouterConfig{
			SignIn:  &signInServiceMock{},
			Refresh: &refreshServiceMock{},
			Logout:  &logoutServiceMock{},
			Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
		if _, err := delivery.NewRouter(cfg); err == nil {
			t.Error("se esperaba un error al armar el router sin servicio de registro")
		}
	})

	t.Run("sin servicio de login", func(t *testing.T) {
		cfg := delivery.RouterConfig{
			SignUp:  &serviceMock{},
			Refresh: &refreshServiceMock{},
			Logout:  &logoutServiceMock{},
			Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
		if _, err := delivery.NewRouter(cfg); err == nil {
			t.Error("se esperaba un error al armar el router sin servicio de login")
		}
	})

	t.Run("sin servicio de refresh", func(t *testing.T) {
		cfg := delivery.RouterConfig{
			SignUp: &serviceMock{},
			SignIn: &signInServiceMock{},
			Logout: &logoutServiceMock{},
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
		if _, err := delivery.NewRouter(cfg); err == nil {
			t.Error("se esperaba un error al armar el router sin servicio de refresh")
		}
	})

	t.Run("sin servicio de logout", func(t *testing.T) {
		cfg := delivery.RouterConfig{
			SignUp:  &serviceMock{},
			SignIn:  &signInServiceMock{},
			Refresh: &refreshServiceMock{},
			Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
		if _, err := delivery.NewRouter(cfg); err == nil {
			t.Error("se esperaba un error al armar el router sin servicio de logout")
		}
	})
}

func TestSignInDevuelve200ConLosTokens(t *testing.T) {
	ts := newTestServer(t, nil)

	rec := ts.post(t, "/api/v1/auth/signin", signInBody("criptograma"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, se esperaba 200 (%s)", rec.Code, rec.Body.String())
	}

	var body struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("la respuesta no es JSON: %v", err)
	}
	if body.AccessToken != ts.signInSvc.accessToken {
		t.Errorf("access_token = %q, se esperaba %q", body.AccessToken, ts.signInSvc.accessToken)
	}
	if body.RefreshToken != ts.signInSvc.refreshToken {
		t.Errorf("refresh_token = %q, se esperaba %q", body.RefreshToken, ts.signInSvc.refreshToken)
	}
}

func TestSignInDecodificaLasDosPiezasAntesDeDelegarlas(t *testing.T) {
	ts := newTestServer(t, nil)

	body := signInBodyCon("la-clave-efimera", "el-ciphertext")
	if rec := ts.post(t, "/api/v1/auth/signin", body); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, se esperaba 200", rec.Code)
	}

	if got := string(ts.signInSvc.ephemeralPublicKey); got != "la-clave-efimera" {
		t.Errorf("ephemeral_public_key = %q, se esperaba la clave efímera decodificada", got)
	}
	if got := string(ts.signInSvc.ciphertext); got != "el-ciphertext" {
		t.Errorf("ciphertext = %q, se esperaba el ciphertext decodificado", got)
	}
}

func TestSignInDevuelve400AnteCuerposInvalidos(t *testing.T) {
	valida := base64.StdEncoding.EncodeToString([]byte("clave-efimera"))

	cases := map[string]string{
		"cuerpo vacío":                 ``,
		"JSON malformado":              `{"ciphertext":`,
		"ephemeral_public_key ausente": `{"ciphertext":"` + valida + `"}`,
		"ciphertext ausente":           `{"ephemeral_public_key":"` + valida + `"}`,
		"ciphertext no base64":         `{"ephemeral_public_key":"` + valida + `","ciphertext":"no-es-base64-!!!"}`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			ts := newTestServer(t, nil)

			rec := ts.post(t, "/api/v1/auth/signin", body)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, se esperaba 400 (%s)", rec.Code, rec.Body.String())
			}
			if ts.signInSvc.calls != 0 {
				t.Error("el servicio no debería invocarse con un cuerpo inválido")
			}
		})
	}
}

func TestSignInMapeaLosErroresDeDominio(t *testing.T) {
	cases := map[string]struct {
		err    error
		status int
		code   string
	}{
		"datos inválidos":         {domain.ErrInvalidInput, http.StatusBadRequest, "datos_invalidos"},
		"credenciales inválidas":  {domain.ErrInvalidCredentials, http.StatusUnauthorized, "credenciales_invalidas"},
		"criptograma mal formado": {domain.ErrMalformedCryptogram, http.StatusBadRequest, "solicitud_invalida"},
		"criptograma ilegible":    {domain.ErrInvalidCryptogram, http.StatusInternalServerError, "error_interno"},
		"base de datos caída":     {domain.ErrDatabaseUnavailable, http.StatusServiceUnavailable, "dependencia_no_disponible"},
		"fallo inesperado":        {errors.New("la base no responde"), http.StatusInternalServerError, "error_interno"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ts := newTestServer(t, nil)
			ts.signInSvc.err = tc.err

			rec := ts.post(t, "/api/v1/auth/signin", signInBody("criptograma"))

			if rec.Code != tc.status {
				t.Fatalf("status = %d, se esperaba %d (%s)", rec.Code, tc.status, rec.Body.String())
			}
			if got := decodeError(t, rec)["code"]; got != tc.code {
				t.Errorf("code = %v, se esperaba %q", got, tc.code)
			}
		})
	}
}

// Un DNI inexistente y una contraseña incorrecta tienen que producir
// exactamente la misma respuesta: distinguirlas permitiría enumerar qué DNIs
// están registrados.
func TestCredencialesInvalidasNoRevelanQueDatoFallo(t *testing.T) {
	ts := newTestServer(t, nil)
	ts.signInSvc.err = domain.ErrInvalidCredentials

	rec := ts.post(t, "/api/v1/auth/signin", signInBody("criptograma"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, se esperaba 401", rec.Code)
	}

	cuerpo := strings.ToLower(rec.Body.String())
	for _, filtracion := range []string{"dni", "password", "contraseña", "existe", "usuario"} {
		if strings.Contains(cuerpo, filtracion) {
			t.Errorf("el 401 menciona %q y permite tantear cuál dato falló: %s", filtracion, rec.Body.String())
		}
	}
}

func TestSignInCuerpoDesmesuradoSeRechaza(t *testing.T) {
	ts := newTestServer(t, nil)

	rec := ts.post(t, "/api/v1/auth/signin", signInBody(strings.Repeat("a", int(delivery.DefaultMaxBodyBytes)*2)))

	if rec.Code == http.StatusOK {
		t.Errorf("un cuerpo por encima del tope no debería aceptarse (status %d)", rec.Code)
	}
	if ts.signInSvc.calls != 0 {
		t.Error("el servicio no debería invocarse con un cuerpo por encima del tope")
	}
}

func TestSignInRespuestaNoSeCachea(t *testing.T) {
	ts := newTestServer(t, nil)

	rec := ts.post(t, "/api/v1/auth/signin", signInBody("criptograma"))

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, se esperaba no-store", got)
	}
}

func TestRefreshDevuelve200ConLosTokensRotados(t *testing.T) {
	ts := newTestServer(t, nil)

	rec := ts.post(t, "/api/v1/auth/refresh", refreshBody("el-refresh-token-del-cliente"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, se esperaba 200 (%s)", rec.Code, rec.Body.String())
	}

	var body struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("la respuesta no es JSON: %v", err)
	}
	if body.AccessToken != ts.refreshSvc.accessToken {
		t.Errorf("access_token = %q, se esperaba %q", body.AccessToken, ts.refreshSvc.accessToken)
	}
	if body.RefreshToken != ts.refreshSvc.refreshToken {
		t.Errorf("refresh_token = %q, se esperaba %q", body.RefreshToken, ts.refreshSvc.refreshToken)
	}
	if ts.refreshSvc.receivedToken != "el-refresh-token-del-cliente" {
		t.Errorf("se delegó %q, se esperaba el refresh_token recibido", ts.refreshSvc.receivedToken)
	}
}

// A diferencia de /signup y /signin, /refresh no lleva ephemeral_public_key
// ni ciphertext: el cuerpo es JSON plano con el Refresh Token opaco.
func TestRefreshDevuelve400AnteCuerposInvalidos(t *testing.T) {
	cases := map[string]string{
		"cuerpo vacío":               ``,
		"JSON malformado":            `{"refresh_token":`,
		"cuerpo no es mapa":          `["token"]`,
		"refresh_token no es cadena": `{"refresh_token":42}`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			ts := newTestServer(t, nil)

			rec := ts.post(t, "/api/v1/auth/refresh", body)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, se esperaba 400 (%s)", rec.Code, rec.Body.String())
			}
			if ts.refreshSvc.calls != 0 {
				t.Error("el servicio no debería invocarse con un cuerpo inválido")
			}
		})
	}
}

// refresh_token ausente o vacío es JSON válido: se delega igual al servicio,
// que lo va a rechazar como una sesión inexistente (401), no como un 400. No
// hay motivo para distinguir el caso a nivel HTTP.
func TestRefreshConTokenVacioSeDelegaAlServicio(t *testing.T) {
	ts := newTestServer(t, nil)
	ts.refreshSvc.err = domain.ErrSessionNotFound

	rec := ts.post(t, "/api/v1/auth/refresh", `{}`)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, se esperaba 401 (%s)", rec.Code, rec.Body.String())
	}
	if ts.refreshSvc.calls != 1 {
		t.Error("un refresh_token ausente debería delegarse igual al servicio")
	}
}

func TestRefreshMapeaLosErroresDeDominio(t *testing.T) {
	cases := map[string]struct {
		err    error
		status int
		code   string
	}{
		"sesión inexistente":  {domain.ErrSessionNotFound, http.StatusUnauthorized, "sesion_invalida"},
		"sesión expirada":     {domain.ErrSessionExpired, http.StatusUnauthorized, "sesion_invalida"},
		"sesión reusada":      {domain.ErrSessionReused, http.StatusForbidden, "sesion_comprometida"},
		"base de datos caída": {domain.ErrDatabaseUnavailable, http.StatusServiceUnavailable, "dependencia_no_disponible"},
		"fallo inesperado":    {errors.New("la base no responde"), http.StatusInternalServerError, "error_interno"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ts := newTestServer(t, nil)
			ts.refreshSvc.err = tc.err

			rec := ts.post(t, "/api/v1/auth/refresh", refreshBody("un-refresh-token"))

			if rec.Code != tc.status {
				t.Fatalf("status = %d, se esperaba %d (%s)", rec.Code, tc.status, rec.Body.String())
			}
			if got := decodeError(t, rec)["code"]; got != tc.code {
				t.Errorf("code = %v, se esperaba %q", got, tc.code)
			}
		})
	}
}

// El token inexistente y el expirado tienen que producir exactamente la
// misma respuesta: no hay motivo para que el cliente distinga uno de otro.
// requestId se excluye de la comparación porque varía en cada petición por
// diseño (ver TestRespuestaCorrelacionaConElRequestID).
func TestRefreshSesionInexistenteYExpiradaProducenElMismoError(t *testing.T) {
	inexistente := newTestServer(t, nil)
	inexistente.refreshSvc.err = domain.ErrSessionNotFound
	rec1 := inexistente.post(t, "/api/v1/auth/refresh", refreshBody("un-refresh-token"))

	expirada := newTestServer(t, nil)
	expirada.refreshSvc.err = domain.ErrSessionExpired
	rec2 := expirada.post(t, "/api/v1/auth/refresh", refreshBody("un-refresh-token"))

	body1, body2 := decodeError(t, rec1), decodeError(t, rec2)
	delete(body1, "requestId")
	delete(body2, "requestId")

	if rec1.Code != rec2.Code {
		t.Fatalf("status difiere: %d vs %d", rec1.Code, rec2.Code)
	}
	if !reflect.DeepEqual(body1, body2) {
		t.Errorf("los cuerpos difieren y permiten distinguir los casos: %+v vs %+v", body1, body2)
	}
}

func TestRefreshCuerpoDesmesuradoSeRechaza(t *testing.T) {
	ts := newTestServer(t, nil)

	rec := ts.post(t, "/api/v1/auth/refresh", refreshBody(strings.Repeat("a", int(delivery.DefaultMaxBodyBytes)*2)))

	if rec.Code == http.StatusOK {
		t.Errorf("un cuerpo por encima del tope no debería aceptarse (status %d)", rec.Code)
	}
	if ts.refreshSvc.calls != 0 {
		t.Error("el servicio no debería invocarse con un cuerpo por encima del tope")
	}
}

func TestRefreshRespuestaNoSeCachea(t *testing.T) {
	ts := newTestServer(t, nil)

	rec := ts.post(t, "/api/v1/auth/refresh", refreshBody("un-refresh-token"))

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, se esperaba no-store", got)
	}
}

func TestLogoutDevuelve200YDelegaElToken(t *testing.T) {
	ts := newTestServer(t, nil)

	rec := ts.post(t, "/api/v1/auth/logout", refreshBody("el-refresh-token-a-cerrar"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, se esperaba 200 (%s)", rec.Code, rec.Body.String())
	}
	if ts.logoutSvc.calls != 1 {
		t.Fatalf("el servicio se llamó %d veces, se esperaba 1", ts.logoutSvc.calls)
	}
	if ts.logoutSvc.receivedToken != "el-refresh-token-a-cerrar" {
		t.Errorf("se delegó %q, se esperaba el refresh_token recibido", ts.logoutSvc.receivedToken)
	}
}

// El contrato de US-03 es 200 siempre, exista o no la sesión: el handler no
// tiene información para distinguir esos casos —LogoutService tampoco la
// expone— así que un token inexistente o ya revocado también es 200.
func TestLogoutDevuelve200AunConUnTokenInexistenteOYaRevocado(t *testing.T) {
	ts := newTestServer(t, nil)

	rec := ts.post(t, "/api/v1/auth/logout", refreshBody("token-que-no-existe-o-ya-se-revoco"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, se esperaba 200 siempre (%s)", rec.Code, rec.Body.String())
	}
}

func TestLogoutDevuelve400AnteCuerposInvalidos(t *testing.T) {
	cases := map[string]string{
		"cuerpo vacío":               ``,
		"JSON malformado":            `{"refresh_token":`,
		"cuerpo no es mapa":          `["token"]`,
		"refresh_token no es cadena": `{"refresh_token":42}`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			ts := newTestServer(t, nil)

			rec := ts.post(t, "/api/v1/auth/logout", body)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, se esperaba 400 (%s)", rec.Code, rec.Body.String())
			}
			if ts.logoutSvc.calls != 0 {
				t.Error("el servicio no debería invocarse con un cuerpo inválido")
			}
		})
	}
}

// El único caso en que /logout no responde 200 es un fallo real de
// infraestructura: la revocación no se pudo persistir.
func TestLogoutDevuelve500SiFallaLaRevocacion(t *testing.T) {
	ts := newTestServer(t, nil)
	ts.logoutSvc.err = errors.New("la base no responde")

	rec := ts.post(t, "/api/v1/auth/logout", refreshBody("un-refresh-token"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, se esperaba 500 (%s)", rec.Code, rec.Body.String())
	}
	if decodeError(t, rec)["code"] != "error_interno" {
		t.Errorf("code = %v, se esperaba error_interno", decodeError(t, rec)["code"])
	}
}

// Sección Postgres del contrato de resiliencia: la base propia caída es un
// 503, no el 500 genérico de arriba — ni siquiera en /logout, cuyo 200
// incondicional es sobre la existencia de la sesión (anti-enumeración), no
// sobre si la infraestructura responde.
func TestLogoutDevuelve503SiLaBaseDeDatosNoEstaDisponible(t *testing.T) {
	ts := newTestServer(t, nil)
	ts.logoutSvc.err = domain.ErrDatabaseUnavailable

	rec := ts.post(t, "/api/v1/auth/logout", refreshBody("un-refresh-token"))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, se esperaba 503 (%s)", rec.Code, rec.Body.String())
	}
	if decodeError(t, rec)["code"] != "dependencia_no_disponible" {
		t.Errorf("code = %v, se esperaba dependencia_no_disponible", decodeError(t, rec)["code"])
	}
}

func TestLogoutCuerpoDesmesuradoSeRechaza(t *testing.T) {
	ts := newTestServer(t, nil)

	rec := ts.post(t, "/api/v1/auth/logout", refreshBody(strings.Repeat("a", int(delivery.DefaultMaxBodyBytes)*2)))

	if rec.Code == http.StatusOK {
		t.Errorf("un cuerpo por encima del tope no debería aceptarse (status %d)", rec.Code)
	}
	if ts.logoutSvc.calls != 0 {
		t.Error("el servicio no debería invocarse con un cuerpo por encima del tope")
	}
}

func TestLogoutRespuestaNoSeCachea(t *testing.T) {
	ts := newTestServer(t, nil)

	rec := ts.post(t, "/api/v1/auth/logout", refreshBody("un-refresh-token"))

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, se esperaba no-store", got)
	}
}
