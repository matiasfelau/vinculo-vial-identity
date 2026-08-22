package http_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	delivery "github.com/matiasfelau/vinculo-vial-identity/internal/delivery/http"
)

const secretoDePrueba = "un-secreto-de-servicio-bien-largo"

func newInternalTestServer(t *testing.T) http.Handler {
	t.Helper()

	router, err := delivery.NewInternalRouter(delivery.InternalRouterConfig{ServiceToken: secretoDePrueba})
	if err != nil {
		t.Fatalf("no se pudo armar el router interno: %v", err)
	}
	return router
}

func TestNewInternalRouterExigeElSecretoConfigurado(t *testing.T) {
	if _, err := delivery.NewInternalRouter(delivery.InternalRouterConfig{ServiceToken: ""}); err == nil {
		t.Fatal("se esperaba un error al faltar ServiceToken")
	}
}

func TestInternalHealthzSinElSecretoDevuelve401(t *testing.T) {
	handler := newInternalTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/internal/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

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
	handler := newInternalTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/internal/healthz", nil)
	req.Header.Set(delivery.HeaderInternalServiceToken, "esto-no-es-el-secreto")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, se esperaba 401 (%s)", rec.Code, rec.Body.String())
	}
}

func TestInternalHealthzConElSecretoCorrectoDevuelve200(t *testing.T) {
	handler := newInternalTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/internal/healthz", nil)
	req.Header.Set(delivery.HeaderInternalServiceToken, secretoDePrueba)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, se esperaba 200 (%s)", rec.Code, rec.Body.String())
	}
}

// El status nunca debe delatar si una ruta interna existe: sin el secreto
// correcto, una ruta real y una inventada tienen que responder exactamente
// lo mismo.
func TestInternalRouterDevuelve401AntesDeRevelarSiLaRutaExiste(t *testing.T) {
	handler := newInternalTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/internal/una-ruta-que-no-existe", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, se esperaba 401 (%s)", rec.Code, rec.Body.String())
	}
}

// El router interno y el público son dos *gin.Engine independientes: ninguna
// ruta del contrato público (/api/v1/auth/*) debería resolver acá, ni
// siquiera con el secreto de servicio correcto.
func TestInternalRouterNoExponeLasRutasPublicas(t *testing.T) {
	handler := newInternalTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", nil)
	req.Header.Set(delivery.HeaderInternalServiceToken, secretoDePrueba)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, se esperaba 404 (%s)", rec.Code, rec.Body.String())
	}
}
