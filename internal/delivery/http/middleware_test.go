package http_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// get emite una petición arbitraria contra el router público y devuelve lo
// que quedó registrado en el log de acceso.
func getYLoguear(t *testing.T, method, path string) (*httptest.ResponseRecorder, string) {
	t.Helper()

	ts := newTestServer(t, nil)

	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, req)

	return rec, ts.logs.String()
}

// Regresión: el log de acceso registraba únicamente c.FullPath(), que es el
// patrón de ruta que matcheó Gin y queda vacío cuando ninguno matcheó. El
// resultado era que un 404 —justo el caso donde hace falta saber qué se
// pidió— se registraba con path vacío, y había que descubrir por prueba y
// error si el problema era un typo, un puerto equivocado o un método
// incorrecto.
func TestElLogDeAccesoRegistraLaRutaPedidaAunqueNoMatcheeNinguna(t *testing.T) {
	rec, logged := getYLoguear(t, http.MethodGet, "/una-ruta-que-no-existe")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, se esperaba 404", rec.Code)
	}
	if !strings.Contains(logged, "path=/una-ruta-que-no-existe") {
		t.Errorf("el log no registra la ruta pedida: %s", logged)
	}
	// El patrón de ruta sí queda vacío, y está bien que así sea: no matcheó
	// ninguno. Lo que no puede pasar es que ese vacío sea lo único registrado.
	if !strings.Contains(logged, `route=""`) {
		t.Errorf("se esperaba route vacío ante un 404: %s", logged)
	}
}

// Mismo caso para un método no permitido: la ruta existe, el método no, y el
// log tiene que decir cuál se pidió.
func TestElLogDeAccesoRegistraLaRutaPedidaAnteUnMetodoNoPermitido(t *testing.T) {
	rec, logged := getYLoguear(t, http.MethodGet, "/api/v1/auth/signup")

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, se esperaba 405", rec.Code)
	}
	if !strings.Contains(logged, "path=/api/v1/auth/signup") {
		t.Errorf("el log no registra la ruta pedida: %s", logged)
	}
	if !strings.Contains(logged, "method=GET") {
		t.Errorf("el log no registra el método pedido: %s", logged)
	}
}

// Cuando la ruta sí matchea, los dos campos se registran y coinciden: `path`
// es lo que pidió el cliente y `route` el patrón que resolvió Gin.
func TestElLogDeAccesoRegistraRutaYPatronCuandoMatchea(t *testing.T) {
	_, logged := getYLoguear(t, http.MethodGet, "/healthz")

	if !strings.Contains(logged, "path=/healthz") {
		t.Errorf("el log no registra la ruta pedida: %s", logged)
	}
	if !strings.Contains(logged, "route=/healthz") {
		t.Errorf("el log no registra el patrón de ruta: %s", logged)
	}
}

// El path lo controla el cliente: un escáner puede pedir una URL
// desmesurada, y eso no tiene por qué inflar el agregador de logs.
func TestElLogDeAccesoAcotaUnPathDesmesurado(t *testing.T) {
	largo := strings.Repeat("a", 300)

	_, logged := getYLoguear(t, http.MethodGet, "/"+largo)

	if strings.Contains(logged, largo) {
		t.Error("el log registró el path completo sin acotarlo")
	}
	if !strings.Contains(logged, "path=/"+strings.Repeat("a", 255)+"…") {
		t.Errorf("el log no registra el path acotado como se esperaba: %s", logged)
	}
}
