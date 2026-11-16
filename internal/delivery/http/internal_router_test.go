package http_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	delivery "github.com/matiasfelau/vinculo-vial-identity/internal/delivery/http"
	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

const secretoDePrueba = "un-secreto-de-servicio-bien-largo"

// auditDNIServiceMock implementa delivery.AuditDNIService.
type auditDNIServiceMock struct {
	result domain.AuditDNI
	err    error

	calls   int
	userID  uuid.UUID
	alertID uuid.UUID
}

func (m *auditDNIServiceMock) SealDNI(_ context.Context, userID, alertID uuid.UUID) (domain.AuditDNI, error) {
	m.calls++
	m.userID = userID
	m.alertID = alertID
	if m.err != nil {
		return domain.AuditDNI{}, m.err
	}
	return m.result, nil
}

type internalTestServer struct {
	handler  http.Handler
	auditDNI *auditDNIServiceMock
}

func newInternalTestServer(t *testing.T) *internalTestServer {
	t.Helper()

	audit := &auditDNIServiceMock{result: domain.AuditDNI{Sealed: "c2VsbGFkbw==", KeyID: "2026-11"}}
	router, err := delivery.NewInternalRouter(delivery.InternalRouterConfig{
		AuditDNI:     audit,
		ServiceToken: secretoDePrueba,
	})
	if err != nil {
		t.Fatalf("no se pudo armar el router interno: %v", err)
	}
	return &internalTestServer{handler: router, auditDNI: audit}
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

func TestNewInternalRouterExigeElSecretoConfigurado(t *testing.T) {
	if _, err := delivery.NewInternalRouter(delivery.InternalRouterConfig{AuditDNI: &auditDNIServiceMock{}, ServiceToken: ""}); err == nil {
		t.Fatal("se esperaba un error al faltar ServiceToken")
	}
}

func TestNewInternalRouterExigeElServicioDeAuditoria(t *testing.T) {
	cfg := delivery.InternalRouterConfig{ServiceToken: secretoDePrueba}
	if _, err := delivery.NewInternalRouter(cfg); err == nil {
		t.Fatal("se esperaba un error al faltar AuditDNI")
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

// US-14 eliminó POST /internal/verify-ownership: ni con el secreto de servicio
// correcto la ruta resuelve, y el servicio de auditoría no se invoca.
func TestInternalRouterYaNoExponeVerifyOwnership(t *testing.T) {
	ts := newInternalTestServer(t)

	rec := ts.post(t, "/internal/verify-ownership",
		`{"owner_id":"`+uuid.NewString()+`","dni_enc":"Y3JpcHRvZ3JhbWE="}`)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, se esperaba 404 (%s)", rec.Code, rec.Body.String())
	}
	if ts.auditDNI.calls != 0 {
		t.Error("ninguna ruta interna restante debería haberse invocado")
	}
}
