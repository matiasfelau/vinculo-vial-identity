package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	delivery "github.com/matiasfelau/vinculo-vial-identity/internal/delivery/http"
)

// estado es una dependencia de prueba cuyo estado cambia entre consultas.
type estado struct {
	state string
	ok    bool
}

func (e *estado) check(name string) delivery.DepCheck {
	return delivery.DepCheck{Name: name, Check: func() (string, bool) { return e.state, e.ok }}
}

func routerConDeps(t *testing.T, ready func(context.Context) error, deps *delivery.DepsHealthHandler) http.Handler {
	t.Helper()

	router, err := delivery.NewRouter(delivery.RouterConfig{
		SignUp:         &serviceMock{userID: uuid.New()},
		SignIn:         &signInServiceMock{},
		Refresh:        &refreshServiceMock{},
		Logout:         &logoutServiceMock{},
		Logger:         slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		ReadinessCheck: ready,
		DepsHealth:     deps,
	})
	if err != nil {
		t.Fatalf("no se pudo armar el router: %v", err)
	}
	return router
}

func get(h http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

type respuestaDeps struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks"`
}

func decodeDeps(t *testing.T, rec *httptest.ResponseRecorder) respuestaDeps {
	t.Helper()
	var r respuestaDeps
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("el cuerpo no es JSON válido: %v (%s)", err, rec.Body.String())
	}
	return r
}

func sanas() (*estado, *estado, *estado) {
	return &estado{"up", true}, &estado{"up", true}, &estado{"closed", true}
}

func depsDe(broker, worker, breaker *estado) *delivery.DepsHealthHandler {
	return delivery.NewDepsHealthHandler(
		broker.check("broker"), worker.check("outbox_worker"), breaker.check("renaper_breaker"),
	)
}

func TestHealthDepsDevuelve200ConTodoSano(t *testing.T) {
	broker, worker, breaker := sanas()
	h := routerConDeps(t, nil, depsDe(broker, worker, breaker))

	rec := get(h, "/health/deps")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, se esperaba 200 (%s)", rec.Code, rec.Body.String())
	}
	r := decodeDeps(t, rec)
	if r.Status != "ok" {
		t.Errorf("status = %q, se esperaba ok", r.Status)
	}
	esperado := map[string]string{"broker": "up", "outbox_worker": "up", "renaper_breaker": "closed"}
	for k, v := range esperado {
		if r.Checks[k] != v {
			t.Errorf("checks[%s] = %q, se esperaba %q", k, r.Checks[k], v)
		}
	}
}

// Cada una de las tres dependencias, por separado, alcanza para degradar.
func TestHealthDepsDevuelve503DegradedSiAlgunaFalla(t *testing.T) {
	casos := map[string]struct {
		degradar func(b, w, r *estado)
		cual     string
		estado   string
	}{
		"broker caído":         {func(b, _, _ *estado) { *b = estado{"down", false} }, "broker", "down"},
		"worker colgado":       {func(_, w, _ *estado) { *w = estado{"stalled", false} }, "outbox_worker", "stalled"},
		"worker detenido":      {func(_, w, _ *estado) { *w = estado{"stopped", false} }, "outbox_worker", "stopped"},
		"breaker abierto":      {func(_, _, r *estado) { *r = estado{"open", false} }, "renaper_breaker", "open"},
		"breaker en half-open": {func(_, _, r *estado) { *r = estado{"half_open", false} }, "renaper_breaker", "half_open"},
	}

	for nombre, tc := range casos {
		t.Run(nombre, func(t *testing.T) {
			broker, worker, breaker := sanas()
			tc.degradar(broker, worker, breaker)
			h := routerConDeps(t, nil, depsDe(broker, worker, breaker))

			rec := get(h, "/health/deps")

			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, se esperaba 503 (%s)", rec.Code, rec.Body.String())
			}
			r := decodeDeps(t, rec)
			if r.Status != "degraded" {
				t.Errorf("status = %q, se esperaba degraded", r.Status)
			}
			if r.Checks[tc.cual] != tc.estado {
				t.Errorf("checks[%s] = %q, se esperaba %q", tc.cual, r.Checks[tc.cual], tc.estado)
			}
			// No corta en el primer fallo: las demás también aparecen.
			if len(r.Checks) != 3 {
				t.Errorf("checks tiene %d entradas, se esperaban las 3 dependencias: %v", len(r.Checks), r.Checks)
			}
		})
	}
}

// El broker deshabilitado es el modo de desarrollo, no una falla.
func TestHealthDepsTrataElBrokerDeshabilitadoComoSano(t *testing.T) {
	_, worker, breaker := sanas()
	h := routerConDeps(t, nil, depsDe(&estado{"disabled", true}, worker, breaker))

	rec := get(h, "/health/deps")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, se esperaba 200 (%s)", rec.Code, rec.Body.String())
	}
	if got := decodeDeps(t, rec).Checks["broker"]; got != "disabled" {
		t.Errorf("checks[broker] = %q, se esperaba disabled", got)
	}
}

// Contrato: /health/deps no afecta al balanceo. Con las tres dependencias
// degradadas, /ready sigue en 200; y a la inversa, una base caída pone /ready
// en 503 sin mover /health/deps.
func TestHealthDepsEsIndependienteDeReady(t *testing.T) {
	t.Run("deps degradado no toca /ready", func(t *testing.T) {
		h := routerConDeps(t, func(context.Context) error { return nil },
			depsDe(&estado{"down", false}, &estado{"stalled", false}, &estado{"open", false}))

		if rec := get(h, "/health/deps"); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("/health/deps = %d, se esperaba 503", rec.Code)
		}
		for _, path := range []string{"/ready", "/readyz", "/healthz"} {
			if rec := get(h, path); rec.Code != http.StatusOK {
				t.Errorf("%s = %d, se esperaba 200 con las dependencias degradadas", path, rec.Code)
			}
		}
	})

	t.Run("base caída no toca /health/deps", func(t *testing.T) {
		broker, worker, breaker := sanas()
		h := routerConDeps(t, func(context.Context) error { return errors.New("la base no responde") },
			depsDe(broker, worker, breaker))

		if rec := get(h, "/ready"); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("/ready = %d, se esperaba 503", rec.Code)
		}
		if rec := get(h, "/health/deps"); rec.Code != http.StatusOK {
			t.Errorf("/health/deps = %d, se esperaba 200: la base no es parte de este chequeo", rec.Code)
		}
	})
}

// Cada consulta evalúa el estado actual: nada se cachea entre llamadas.
func TestHealthDepsReflejaElEstadoActualEnCadaConsulta(t *testing.T) {
	broker, worker, breaker := sanas()
	h := routerConDeps(t, nil, depsDe(broker, worker, breaker))

	if rec := get(h, "/health/deps"); rec.Code != http.StatusOK {
		t.Fatalf("primera consulta = %d, se esperaba 200", rec.Code)
	}
	*broker = estado{"down", false}
	rec := get(h, "/health/deps")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("tras caer el broker = %d, se esperaba 503", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, se esperaba no-store", got)
	}
	*broker = estado{"up", true}
	if rec := get(h, "/health/deps"); rec.Code != http.StatusOK {
		t.Errorf("tras recuperarse = %d, se esperaba 200", rec.Code)
	}
}

func TestHealthDepsNoSeRegistraSinHandler(t *testing.T) {
	h := routerConDeps(t, nil, nil)

	if rec := get(h, "/health/deps"); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, se esperaba 404 sin DepsHealth configurado", rec.Code)
	}
}
