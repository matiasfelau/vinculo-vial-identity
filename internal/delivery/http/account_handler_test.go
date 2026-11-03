package http_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	delivery "github.com/matiasfelau/vinculo-vial-identity/internal/delivery/http"
	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/validation"
)

const rutaBaja = "/api/v1/users/me"

type deleteAccountServiceMock struct {
	err error

	calls            int
	receivedUserID   uuid.UUID
	receivedPassword string
}

func (m *deleteAccountServiceMock) Delete(_ context.Context, userID uuid.UUID, password []byte) error {
	m.calls++
	m.receivedUserID = userID
	m.receivedPassword = string(password)
	return m.err
}

// baja arma un DELETE /api/v1/users/me con X-User-Id y el body dado.
func (ts *testServer) baja(t *testing.T, userID, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodDelete, rutaBaja, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if userID != "" {
		req.Header.Set(delivery.HeaderUserID, userID)
	}

	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, req)
	return rec
}

func TestBajaDevuelve204YEntregaUsuarioYContrasena(t *testing.T) {
	ts := newTestServer(t, nil)
	usuario := uuid.New()

	rec := ts.baja(t, usuario.String(), `{"password":"Contraseña-Segura-1"}`)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, se esperaba 204 (%s)", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Errorf("el 204 no lleva cuerpo, se recibió %q", rec.Body.String())
	}
	if ts.deleteSvc.calls != 1 || ts.deleteSvc.receivedUserID != usuario || ts.deleteSvc.receivedPassword != "Contraseña-Segura-1" {
		t.Errorf("el servicio recibió usuario=%v password=%q en %d llamadas", ts.deleteSvc.receivedUserID, ts.deleteSvc.receivedPassword, ts.deleteSvc.calls)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, se esperaba no-store", got)
	}
}

// La baja actúa siempre sobre el usuario de X-User-Id. Sin esa cabecera, o con
// una que no es un UUID, no hay quién autentique la petición: fail-closed.
func TestBajaSinUsuarioAutenticadoDevuelve401(t *testing.T) {
	casos := map[string]string{
		"sin cabecera":   "",
		"no es uuid":     "no-es-uuid",
		"uuid nulo":      uuid.Nil.String(),
		"con espacios":   " " + uuid.NewString(),
		"uuid con ruido": uuid.NewString() + "x",
	}

	for nombre, header := range casos {
		t.Run(nombre, func(t *testing.T) {
			ts := newTestServer(t, nil)

			rec := ts.baja(t, header, `{"password":"Contraseña-Segura-1"}`)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, se esperaba 401", rec.Code)
			}
			if got := decodeError(t, rec)["code"]; got != "UNAUTHORIZED" {
				t.Errorf("code = %v, se esperaba UNAUTHORIZED", got)
			}
			if ts.deleteSvc.calls != 0 {
				t.Errorf("sin usuario autenticado no se debe invocar la baja")
			}
		})
	}
}

func TestBajaConBodyInvalidoDevuelve400(t *testing.T) {
	casos := map[string]string{
		"body ausente":             "",
		"objeto vacío":             `{}`,
		"password vacío":           `{"password":""}`,
		"password nulo":            `{"password":null}`,
		"password no es string":    `{"password":12345678}`,
		"no es JSON":               `contraseña`,
		"JSON truncado":            `{"password":"abc`,
		"campo equivocado":         `{"contraseña":"Contraseña-Segura-1"}`,
		"password demasiado largo": `{"password":"` + strings.Repeat("a", validation.MaxPasswordLength+1) + `"}`,
		"body gigante":             `{"password":"` + strings.Repeat("a", 8<<10) + `"}`,
	}

	for nombre, body := range casos {
		t.Run(nombre, func(t *testing.T) {
			ts := newTestServer(t, nil)

			rec := ts.baja(t, uuid.NewString(), body)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, se esperaba 400 (%s)", rec.Code, rec.Body.String())
			}
			if got := decodeError(t, rec)["code"]; got != "INVALID_BODY" {
				t.Errorf("code = %v, se esperaba INVALID_BODY", got)
			}
			if ts.deleteSvc.calls != 0 {
				t.Errorf("un body inválido no debe llegar al caso de uso")
			}
		})
	}
}

// El largo máximo cuenta caracteres, no bytes: una contraseña de 128 caracteres
// multibyte es válida.
func TestBajaAceptaUnaContrasenaDeLargoMaximoEnCaracteres(t *testing.T) {
	ts := newTestServer(t, nil)
	password := strings.Repeat("ñ", validation.MaxPasswordLength)

	rec := ts.baja(t, uuid.NewString(), fmt.Sprintf(`{"password":%q}`, password))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, se esperaba 204 (%s)", rec.Code, rec.Body.String())
	}
	if ts.deleteSvc.receivedPassword != password {
		t.Errorf("la contraseña no llegó íntegra al caso de uso")
	}
}

func TestBajaConContrasenaIncorrectaDevuelve401(t *testing.T) {
	ts := newTestServer(t, nil)
	ts.deleteSvc.err = domain.ErrInvalidPassword

	rec := ts.baja(t, uuid.NewString(), `{"password":"Contraseña-Equivocada-1"}`)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, se esperaba 401", rec.Code)
	}
	if got := decodeError(t, rec)["code"]; got != "INVALID_PASSWORD" {
		t.Errorf("code = %v, se esperaba INVALID_PASSWORD", got)
	}
}

// Con la base caída o en timeout la respuesta es 503 con Retry-After, también
// cuando el error viene envuelto por las capas de abajo.
func TestBajaConBaseNoDisponibleDevuelve503ConRetryAfter(t *testing.T) {
	ts := newTestServer(t, nil)
	ts.deleteSvc.err = fmt.Errorf("account: no se pudo dar de baja la cuenta: %w", domain.ErrDatabaseUnavailable)

	rec := ts.baja(t, uuid.NewString(), `{"password":"Contraseña-Segura-1"}`)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, se esperaba 503", rec.Code)
	}
	if got := decodeError(t, rec)["code"]; got != "DEPENDENCY_UNAVAILABLE" {
		t.Errorf("code = %v, se esperaba DEPENDENCY_UNAVAILABLE", got)
	}
	if got := rec.Header().Get("Retry-After"); got == "" {
		t.Errorf("falta el encabezado Retry-After en el 503")
	}
}

// Un fallo inesperado es un 500 genérico: el detalle queda en el log y nunca en
// la respuesta.
func TestBajaConFalloInesperadoDevuelve500SinDetalle(t *testing.T) {
	ts := newTestServer(t, nil)
	ts.deleteSvc.err = errors.New("pq: relation \"legal_hold.user_holds\" does not exist")

	rec := ts.baja(t, uuid.NewString(), `{"password":"Contraseña-Segura-1"}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, se esperaba 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "legal_hold") {
		t.Errorf("la respuesta filtra un detalle interno: %s", rec.Body.String())
	}
	if !strings.Contains(ts.logs.String(), "legal_hold") {
		t.Errorf("el detalle del fallo debía quedar en el log")
	}
}

// La respuesta de error sigue el formato vigente: error y code.
func TestBajaRespondeErroresConElFormatoVigente(t *testing.T) {
	ts := newTestServer(t, nil)
	ts.deleteSvc.err = domain.ErrInvalidPassword

	rec := ts.baja(t, uuid.NewString(), `{"password":"Contraseña-Segura-1"}`)

	body := decodeError(t, rec)
	if msg, _ := body["error"].(string); msg == "" {
		t.Errorf("falta el campo error: %v", body)
	}
	if code, _ := body["code"].(string); code == "" {
		t.Errorf("falta el campo code: %v", body)
	}
}

// Ni la contraseña ni el cuerpo llegan a ningún log, tampoco en los rechazos.
func TestBajaNuncaLogueaLaContrasena(t *testing.T) {
	const password = "Contraseña-Muy-Secreta-42"

	casos := map[string]struct {
		svcErr error
		body   string
	}{
		"éxito":                 {nil, `{"password":"` + password + `"}`},
		"contraseña incorrecta": {domain.ErrInvalidPassword, `{"password":"` + password + `"}`},
		"base caída":            {domain.ErrDatabaseUnavailable, `{"password":"` + password + `"}`},
		"fallo inesperado":      {errors.New("falló algo"), `{"password":"` + password + `"}`},
		"JSON truncado":         {nil, `{"password":"` + password},
		"tipo equivocado":       {nil, `{"password":["` + password + `"]}`},
	}

	for nombre, caso := range casos {
		t.Run(nombre, func(t *testing.T) {
			ts := newTestServer(t, nil)
			ts.deleteSvc.err = caso.svcErr

			rec := ts.baja(t, uuid.NewString(), caso.body)

			if strings.Contains(ts.logs.String(), password) {
				t.Errorf("el log contiene la contraseña: %s", ts.logs.String())
			}
			if strings.Contains(rec.Body.String(), password) {
				t.Errorf("la respuesta contiene la contraseña: %s", rec.Body.String())
			}
		})
	}
}

// La ruta solo existe con DELETE: cualquier otro método es un 405.
func TestBajaSoloAceptaDelete(t *testing.T) {
	for _, metodo := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch} {
		t.Run(metodo, func(t *testing.T) {
			ts := newTestServer(t, nil)

			req := httptest.NewRequest(metodo, rutaBaja, strings.NewReader(`{"password":"Contraseña-Segura-1"}`))
			req.Header.Set(delivery.HeaderUserID, uuid.NewString())
			rec := httptest.NewRecorder()
			ts.handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("status = %d, se esperaba 405", rec.Code)
			}
			if ts.deleteSvc.calls != 0 {
				t.Errorf("un método distinto de DELETE no debe llegar al caso de uso")
			}
		})
	}
}

// No existe una ruta por identificador: la baja solo actúa sobre el usuario
// autenticado, así que no hay forma de apuntar a otra cuenta.
func TestBajaNoTieneRutaPorIdentificador(t *testing.T) {
	ts := newTestServer(t, nil)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+uuid.NewString(), strings.NewReader(`{"password":"Contraseña-Segura-1"}`))
	req.Header.Set(delivery.HeaderUserID, uuid.NewString())
	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, se esperaba 404", rec.Code)
	}
	if ts.deleteSvc.calls != 0 {
		t.Errorf("no debe llegar al caso de uso")
	}
}

func TestNewAccountHandlerExigeElServicio(t *testing.T) {
	if _, err := delivery.NewAccountHandler(nil, nil); err == nil {
		t.Error("se esperaba un error sin servicio de baja")
	}
}
