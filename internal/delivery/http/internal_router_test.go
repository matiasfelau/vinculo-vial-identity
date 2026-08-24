package http_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	delivery "github.com/matiasfelau/vinculo-vial-identity/internal/delivery/http"
	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

const secretoDePrueba = "un-secreto-de-servicio-bien-largo"

// verifyOwnershipServiceMock implementa delivery.VerifyOwnershipService.
type verifyOwnershipServiceMock struct {
	match bool
	err   error

	calls      int
	ownerID    uuid.UUID
	cryptogram []byte
}

func (m *verifyOwnershipServiceMock) VerifyOwnership(_ context.Context, ownerID uuid.UUID, cryptogram []byte) (bool, error) {
	m.calls++
	m.ownerID = ownerID
	m.cryptogram = cryptogram
	if m.err != nil {
		return false, m.err
	}
	return m.match, nil
}

type internalTestServer struct {
	handler         http.Handler
	verifyOwnership *verifyOwnershipServiceMock
}

func newInternalTestServer(t *testing.T) *internalTestServer {
	t.Helper()

	svc := &verifyOwnershipServiceMock{match: true}
	router, err := delivery.NewInternalRouter(delivery.InternalRouterConfig{
		VerifyOwnership: svc,
		ServiceToken:    secretoDePrueba,
	})
	if err != nil {
		t.Fatalf("no se pudo armar el router interno: %v", err)
	}
	return &internalTestServer{handler: router, verifyOwnership: svc}
}

func (ts *internalTestServer) post(t *testing.T, path, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(delivery.HeaderInternalServiceToken, secretoDePrueba)

	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, req)
	return rec
}

func verifyOwnershipBody(ownerID, dniEnc string) string {
	payload, _ := json.Marshal(map[string]string{"owner_id": ownerID, "dni_enc": dniEnc})
	return string(payload)
}

func TestNewInternalRouterExigeElSecretoConfigurado(t *testing.T) {
	svc := &verifyOwnershipServiceMock{}
	if _, err := delivery.NewInternalRouter(delivery.InternalRouterConfig{VerifyOwnership: svc, ServiceToken: ""}); err == nil {
		t.Fatal("se esperaba un error al faltar ServiceToken")
	}
}

func TestNewInternalRouterExigeElServicioDeVerificacion(t *testing.T) {
	if _, err := delivery.NewInternalRouter(delivery.InternalRouterConfig{ServiceToken: secretoDePrueba}); err == nil {
		t.Fatal("se esperaba un error al faltar VerifyOwnership")
	}
}

func TestInternalHealthzSinElSecretoDevuelve401(t *testing.T) {
	ts := newInternalTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/internal/healthz", nil)
	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, se esperaba 401 (%s)", rec.Code, rec.Body.String())
	}

	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("la respuesta no es JSON: %v", err)
	}
	if body.Code != "servicio_no_autorizado" {
		t.Errorf("code = %q, se esperaba servicio_no_autorizado", body.Code)
	}
}

func TestInternalHealthzConElSecretoIncorrectoDevuelve401(t *testing.T) {
	ts := newInternalTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/internal/healthz", nil)
	req.Header.Set(delivery.HeaderInternalServiceToken, "esto-no-es-el-secreto")
	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, se esperaba 401 (%s)", rec.Code, rec.Body.String())
	}
}

func TestInternalHealthzConElSecretoCorrectoDevuelve200(t *testing.T) {
	ts := newInternalTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/internal/healthz", nil)
	req.Header.Set(delivery.HeaderInternalServiceToken, secretoDePrueba)
	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, se esperaba 200 (%s)", rec.Code, rec.Body.String())
	}
}

// El status nunca debe delatar si una ruta interna existe: sin el secreto
// correcto, una ruta real y una inventada tienen que responder exactamente
// lo mismo.
func TestInternalRouterDevuelve401AntesDeRevelarSiLaRutaExiste(t *testing.T) {
	ts := newInternalTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/internal/una-ruta-que-no-existe", nil)
	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, se esperaba 401 (%s)", rec.Code, rec.Body.String())
	}
}

// El router interno y el público son dos *gin.Engine independientes: ninguna
// ruta del contrato público (/api/v1/auth/*) debería resolver acá, ni
// siquiera con el secreto de servicio correcto.
func TestInternalRouterNoExponeLasRutasPublicas(t *testing.T) {
	ts := newInternalTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", nil)
	req.Header.Set(delivery.HeaderInternalServiceToken, secretoDePrueba)
	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, se esperaba 404 (%s)", rec.Code, rec.Body.String())
	}
}

func TestVerifyOwnershipSinElSecretoDeServicioDevuelve401(t *testing.T) {
	ts := newInternalTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/internal/verify-ownership",
		strings.NewReader(verifyOwnershipBody(uuid.NewString(), base64.StdEncoding.EncodeToString([]byte("criptograma")))))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, se esperaba 401 (%s)", rec.Code, rec.Body.String())
	}
	if ts.verifyOwnership.calls != 0 {
		t.Error("el servicio no debería invocarse sin el secreto de servicio")
	}
}

func TestVerifyOwnershipConMatchDevuelve200(t *testing.T) {
	ts := newInternalTestServer(t)
	ts.verifyOwnership.match = true

	ownerID := uuid.New()
	cryptogram := base64.StdEncoding.EncodeToString([]byte("criptograma"))
	rec := ts.post(t, "/internal/verify-ownership", verifyOwnershipBody(ownerID.String(), cryptogram))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, se esperaba 200 (%s)", rec.Code, rec.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("la respuesta no es JSON: %v", err)
	}
	if match, _ := body["match"].(bool); !match {
		t.Errorf("match = %v, se esperaba true", body["match"])
	}
	// El contrato es estrictamente {match: bool}: nada más.
	if len(body) != 1 {
		t.Errorf("la respuesta trae campos de más: %v", body)
	}

	if ts.verifyOwnership.ownerID != ownerID {
		t.Errorf("owner_id recibido = %v, se esperaba %v", ts.verifyOwnership.ownerID, ownerID)
	}
	if string(ts.verifyOwnership.cryptogram) != "criptograma" {
		t.Errorf("cryptogram decodificado = %q, se esperaba %q", ts.verifyOwnership.cryptogram, "criptograma")
	}
}

func TestVerifyOwnershipSinMatchDevuelve200(t *testing.T) {
	ts := newInternalTestServer(t)
	ts.verifyOwnership.match = false

	rec := ts.post(t, "/internal/verify-ownership",
		verifyOwnershipBody(uuid.NewString(), base64.StdEncoding.EncodeToString([]byte("criptograma"))))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, se esperaba 200 (%s)", rec.Code, rec.Body.String())
	}

	var body struct {
		Match bool `json:"match"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("la respuesta no es JSON: %v", err)
	}
	if body.Match {
		t.Error("match = true, se esperaba false")
	}
}

func TestVerifyOwnershipRechazaElCuerpoMalFormado(t *testing.T) {
	ts := newInternalTestServer(t)

	rec := ts.post(t, "/internal/verify-ownership", `{"owner_id": 123}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, se esperaba 400 (%s)", rec.Code, rec.Body.String())
	}
	if ts.verifyOwnership.calls != 0 {
		t.Error("el servicio no debería invocarse con un cuerpo mal formado")
	}
}

func TestVerifyOwnershipRechazaOwnerIDQueNoEsUUID(t *testing.T) {
	ts := newInternalTestServer(t)

	rec := ts.post(t, "/internal/verify-ownership",
		verifyOwnershipBody("esto-no-es-un-uuid", base64.StdEncoding.EncodeToString([]byte("criptograma"))))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, se esperaba 400 (%s)", rec.Code, rec.Body.String())
	}
	if ts.verifyOwnership.calls != 0 {
		t.Error("el servicio no debería invocarse con un owner_id inválido")
	}
}

func TestVerifyOwnershipRechazaDNIEncQueNoEsBase64(t *testing.T) {
	ts := newInternalTestServer(t)

	rec := ts.post(t, "/internal/verify-ownership", verifyOwnershipBody(uuid.NewString(), "no-es-base64-!!!"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, se esperaba 400 (%s)", rec.Code, rec.Body.String())
	}
	if ts.verifyOwnership.calls != 0 {
		t.Error("el servicio no debería invocarse con dni_enc inválido")
	}
}

// abortVerifyOwnershipError traduce los dos centinelas de descifrado a
// códigos HTTP distintos, igual que SignUp/SignIn: un criptograma mal
// formado se verifica sin descifrar (400); uno bien formado que no abre es
// indistinguible entre clave desincronizada y manipulación (500).
func TestVerifyOwnershipTraduceLosErroresDeDominio(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"criptograma mal formado", domain.ErrMalformedCryptogram, http.StatusBadRequest},
		{"criptograma que no abre", domain.ErrInvalidCryptogram, http.StatusInternalServerError},
		{"fallo de infraestructura", errors.New("connection reset by peer"), http.StatusInternalServerError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := newInternalTestServer(t)
			ts.verifyOwnership.err = tc.err

			rec := ts.post(t, "/internal/verify-ownership",
				verifyOwnershipBody(uuid.NewString(), base64.StdEncoding.EncodeToString([]byte("criptograma"))))

			if rec.Code != tc.want {
				t.Fatalf("status = %d, se esperaba %d (%s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestVerifyOwnershipDecodificaLasCuatroVariantesDeBase64(t *testing.T) {
	ct := []byte{0xFF, 0xFE, 0xFD, 0x01}

	variantes := map[string]*base64.Encoding{
		"estándar con relleno": base64.StdEncoding,
		"estándar sin relleno": base64.RawStdEncoding,
		"URL-safe con relleno": base64.URLEncoding,
		"URL-safe sin relleno": base64.RawURLEncoding,
	}

	for name, codificacion := range variantes {
		t.Run(name, func(t *testing.T) {
			ts := newInternalTestServer(t)

			rec := ts.post(t, "/internal/verify-ownership", verifyOwnershipBody(uuid.NewString(), codificacion.EncodeToString(ct)))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, se esperaba 200 (%s)", rec.Code, rec.Body.String())
			}
		})
	}
}
