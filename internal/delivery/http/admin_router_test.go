package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	delivery "github.com/matiasfelau/vinculo-vial-identity/internal/delivery/http"
	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

const claveDeAdminDePrueba = "una-clave-de-administracion-bien-larga-0001"

// reviewServiceMock implementa delivery.ReviewAdminService.
type reviewServiceMock struct {
	err error

	page      domain.ReviewCasePage
	decisions []domain.ReviewDecision

	listCalls  int
	listStatus domain.AccountStatus
	listLimit  int
	listCursor string

	unblockCalls int
	unblockUser  uuid.UUID
	reason       string
	operator     string
}

func (m *reviewServiceMock) ListCases(_ context.Context, status domain.AccountStatus, limit int, cursor string) (domain.ReviewCasePage, error) {
	m.listCalls++
	m.listStatus, m.listLimit, m.listCursor = status, limit, cursor
	return m.page, m.err
}

func (m *reviewServiceMock) Unblock(_ context.Context, userID uuid.UUID, reason, operator string) (uuid.UUID, error) {
	m.unblockCalls++
	m.unblockUser, m.reason, m.operator = userID, reason, operator
	if m.err != nil {
		return uuid.Nil, m.err
	}
	return uuid.New(), nil
}

func (m *reviewServiceMock) Decisions(_ context.Context, _ uuid.UUID) ([]domain.ReviewDecision, error) {
	return m.decisions, m.err
}

type adminTestServer struct {
	handler http.Handler
	review  *reviewServiceMock
}

func newAdminTestServer(t *testing.T) *adminTestServer {
	t.Helper()

	review := &reviewServiceMock{}
	router, err := delivery.NewAdminRouter(delivery.AdminRouterConfig{Review: review, APIKey: claveDeAdminDePrueba})
	if err != nil {
		t.Fatalf("no se pudo armar el router de administración: %v", err)
	}
	return &adminTestServer{handler: router, review: review}
}

// do envía la petición con la clave correcta.
func (ts *adminTestServer) do(method, path, body string) *httptest.ResponseRecorder {
	return ts.doWithKey(method, path, body, claveDeAdminDePrueba)
}

func (ts *adminTestServer) doWithKey(method, path, body, key string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set(delivery.HeaderAdminAPIKey, key)
	}
	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, req)
	return rec
}

type adminError struct {
	Error     string `json:"error"`
	Code      string `json:"code"`
	RequestID string `json:"request_id"`
}

func leerError(t *testing.T, rec *httptest.ResponseRecorder) adminError {
	t.Helper()

	var e adminError
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("la respuesta no es JSON (%d): %v", rec.Code, err)
	}
	return e
}

func TestNewAdminRouterExigeLaClaveDeAlMenos32Caracteres(t *testing.T) {
	review := &reviewServiceMock{}
	for _, clave := range []string{"", "corta", strings.Repeat("k", 31)} {
		if _, err := delivery.NewAdminRouter(delivery.AdminRouterConfig{Review: review, APIKey: clave}); err == nil {
			t.Errorf("se esperaba un error con una clave de %d caracteres", len(clave))
		}
	}
	if _, err := delivery.NewAdminRouter(delivery.AdminRouterConfig{Review: review, APIKey: strings.Repeat("k", 32)}); err != nil {
		t.Errorf("una clave de 32 caracteres debería valer: %v", err)
	}
}

func TestNewAdminRouterExigeElServicioDeRevision(t *testing.T) {
	if _, err := delivery.NewAdminRouter(delivery.AdminRouterConfig{APIKey: claveDeAdminDePrueba}); err == nil {
		t.Fatal("se esperaba un error al faltar el servicio de revisión")
	}
}

// Sin clave, con una clave incorrecta, o con una de otro largo: 401 en cualquier
// ruta y método, exista o no, y el servicio nunca se invoca.
func TestAdminSinClaveValidaDevuelve401EnCualquierRuta(t *testing.T) {
	userID := uuid.NewString()
	rutas := []struct{ method, path string }{
		{http.MethodGet, "/admin/v1/review-cases"},
		{http.MethodPost, "/admin/v1/review-cases/" + userID + "/unblock"},
		{http.MethodGet, "/admin/v1/review-cases/" + userID + "/decisions"},
		{http.MethodGet, "/admin/v1/ruta-que-no-existe"},
		{http.MethodDelete, "/admin/v1/review-cases"},
		{http.MethodGet, "/"},
		{http.MethodGet, "/internal/healthz"},
	}
	claves := map[string]string{
		"sin cabecera":       "",
		"clave incorrecta":   strings.Repeat("x", len(claveDeAdminDePrueba)),
		"prefijo de la real": claveDeAdminDePrueba[:len(claveDeAdminDePrueba)-1],
		"la real y de más":   claveDeAdminDePrueba + "x",
	}

	for nombre, clave := range claves {
		for _, r := range rutas {
			t.Run(nombre+" "+r.method+" "+r.path, func(t *testing.T) {
				ts := newAdminTestServer(t)

				rec := ts.doWithKey(r.method, r.path, `{"reason":"un motivo suficiente","operator":"ana"}`, clave)

				if rec.Code != http.StatusUnauthorized {
					t.Fatalf("status = %d, se esperaba 401 (%s)", rec.Code, rec.Body.String())
				}
				if e := leerError(t, rec); e.Code != "UNAUTHORIZED" || e.Error == "" {
					t.Errorf("cuerpo = %+v, se esperaba UNAUTHORIZED con un texto", e)
				}
				if ts.review.listCalls != 0 || ts.review.unblockCalls != 0 {
					t.Error("el servicio no debería invocarse sin clave válida")
				}
			})
		}
	}
}

// El 401 no depende de que la ruta exista: el mismo cuerpo para una ruta real y
// una inexistente, así que el status nunca delata qué rutas expone el servidor.
func TestAdminElCuerpoDel401EsIgualParaRutasRealesEInexistentes(t *testing.T) {
	ts := newAdminTestServer(t)

	real := ts.doWithKey(http.MethodGet, "/admin/v1/review-cases", "", "")
	falsa := ts.doWithKey(http.MethodGet, "/admin/v1/otra-cosa", "", "")

	a, b := leerError(t, real), leerError(t, falsa)
	a.RequestID, b.RequestID = "", ""
	if a != b {
		t.Errorf("los 401 difieren: %+v vs %+v", a, b)
	}
}

func TestAdminConClaveRutaInexistenteDevuelve404YMetodoIncorrectoDevuelve405(t *testing.T) {
	ts := newAdminTestServer(t)

	rec := ts.do(http.MethodGet, "/admin/v1/otra-cosa", "")
	if rec.Code != http.StatusNotFound || leerError(t, rec).Code != "NOT_FOUND" {
		t.Errorf("404 esperado, se obtuvo %d (%s)", rec.Code, rec.Body.String())
	}

	rec = ts.do(http.MethodDelete, "/admin/v1/review-cases", "")
	if rec.Code != http.StatusMethodNotAllowed || leerError(t, rec).Code != "METHOD_NOT_ALLOWED" {
		t.Errorf("405 esperado, se obtuvo %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestAdminNoCacheaLasRespuestas(t *testing.T) {
	ts := newAdminTestServer(t)

	rec := ts.do(http.MethodGet, "/admin/v1/review-cases", "")

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, se esperaba no-store", got)
	}
}

func TestListReviewCasesDevuelveLosCasosYElCursor(t *testing.T) {
	ts := newAdminTestServer(t)
	userID := uuid.New()
	desde := time.Date(2026, 11, 10, 9, 30, 0, 0, time.UTC)
	ultimo := time.Date(2026, 11, 14, 18, 0, 0, 0, time.UTC)
	ts.review.page = domain.ReviewCasePage{
		Items: []domain.ReviewCase{
			{UserID: userID, AccountStatus: domain.AccountStatusUnderReview, ReportCount: 3, ReputationScore: -20, UnderReviewSince: &desde, LastReportedAt: &ultimo},
			{UserID: uuid.New(), AccountStatus: domain.AccountStatusUnderReview},
		},
		NextCursor: "siguiente",
	}

	rec := ts.do(http.MethodGet, "/admin/v1/review-cases", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	var body struct {
		Items      []map[string]any `json:"items"`
		NextCursor *string          `json:"next_cursor"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("respuesta ilegible: %v", err)
	}
	if len(body.Items) != 2 || body.NextCursor == nil || *body.NextCursor != "siguiente" {
		t.Fatalf("cuerpo = %s", rec.Body.String())
	}

	primero := body.Items[0]
	want := map[string]any{
		"user_id":            userID.String(),
		"account_status":     "UNDER_REVIEW",
		"report_count":       float64(3),
		"reputation_score":   float64(-20),
		"under_review_since": "2026-11-10T09:30:00Z",
		"last_reported_at":   "2026-11-14T18:00:00Z",
	}
	for k, v := range want {
		if primero[k] != v {
			t.Errorf("items[0].%s = %v, se esperaba %v", k, primero[k], v)
		}
	}
	// Un caso sin fechas las devuelve como null, no como una fecha vacía.
	segundo := body.Items[1]
	if v, ok := segundo["under_review_since"]; !ok || v != nil {
		t.Errorf("under_review_since = %v, se esperaba null presente", v)
	}
	if v, ok := segundo["last_reported_at"]; !ok || v != nil {
		t.Errorf("last_reported_at = %v, se esperaba null presente", v)
	}
	// Los campos de la respuesta son exactamente los del contrato: ni email ni DNI.
	if len(primero) != 6 {
		t.Errorf("el caso tiene %d campos, se esperaban 6: %v", len(primero), primero)
	}
}

func TestListReviewCasesUsaLosValoresPorDefectoYPasaLosParametros(t *testing.T) {
	ts := newAdminTestServer(t)

	if rec := ts.do(http.MethodGet, "/admin/v1/review-cases", ""); rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	if ts.review.listStatus != domain.AccountStatusUnderReview || ts.review.listLimit != 50 || ts.review.listCursor != "" {
		t.Errorf("por defecto: %v, %d, %q; se esperaba UNDER_REVIEW, 50, vacío", ts.review.listStatus, ts.review.listLimit, ts.review.listCursor)
	}

	rec := ts.do(http.MethodGet, "/admin/v1/review-cases?status=UNDER_REVIEW&limit=7&cursor=abc_-123", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	if ts.review.listLimit != 7 || ts.review.listCursor != "abc_-123" {
		t.Errorf("parámetros = %d, %q; se esperaba 7, abc_-123", ts.review.listLimit, ts.review.listCursor)
	}
}

// Sin siguiente página, next_cursor es null y items es una lista vacía, no null.
func TestListReviewCasesSinCasosDevuelveListaVaciaYCursorNulo(t *testing.T) {
	ts := newAdminTestServer(t)

	rec := ts.do(http.MethodGet, "/admin/v1/review-cases", "")

	if got := strings.TrimSpace(rec.Body.String()); got != `{"items":[],"next_cursor":null}` {
		t.Errorf("cuerpo = %s", got)
	}
}

func TestListReviewCasesRechazaParametrosInvalidos(t *testing.T) {
	cases := map[string]string{
		"status ACTIVE":        "?status=ACTIVE",
		"status vacío":         "?status=",
		"limit cero":           "?limit=0",
		"limit negativo":       "?limit=-1",
		"limit sobre el tope":  "?limit=101",
		"limit no numérico":    "?limit=muchos",
		"limit vacío":          "?limit=",
		"cursor desmesurado":   "?cursor=" + strings.Repeat("a", 129),
		"status en minúsculas": "?status=under_review",
	}
	for nombre, query := range cases {
		t.Run(nombre, func(t *testing.T) {
			ts := newAdminTestServer(t)

			rec := ts.do(http.MethodGet, "/admin/v1/review-cases"+query, "")

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, se esperaba 400 (%s)", rec.Code, rec.Body.String())
			}
			if e := leerError(t, rec); e.Code != "INVALID_QUERY" {
				t.Errorf("code = %q, se esperaba INVALID_QUERY", e.Code)
			}
			if ts.review.listCalls != 0 {
				t.Error("no debería consultar con parámetros inválidos")
			}
		})
	}
}

func TestListReviewCasesConUnCursorQueElServicioRechazaDevuelve400(t *testing.T) {
	ts := newAdminTestServer(t)
	ts.review.err = domain.ErrInvalidCursor

	rec := ts.do(http.MethodGet, "/admin/v1/review-cases?cursor=basura", "")

	if rec.Code != http.StatusBadRequest || leerError(t, rec).Code != "INVALID_QUERY" {
		t.Errorf("se esperaba 400 INVALID_QUERY, se obtuvo %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestUnblockDevuelve204YPasaElMotivoYElOperador(t *testing.T) {
	ts := newAdminTestServer(t)
	userID := uuid.New()

	rec := ts.do(http.MethodPost, "/admin/v1/review-cases/"+userID.String()+"/unblock",
		`{"reason":"Revisada la evidencia: sin fraude","operator":"ana.perez"}`)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, se esperaba 204 (%s)", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Errorf("el 204 no debería tener cuerpo: %q", rec.Body.String())
	}
	if ts.review.unblockUser != userID || ts.review.reason != "Revisada la evidencia: sin fraude" || ts.review.operator != "ana.perez" {
		t.Errorf("el servicio recibió %s, %q, %q", ts.review.unblockUser, ts.review.reason, ts.review.operator)
	}
}

func TestUnblockTraduceLosErroresDelServicio(t *testing.T) {
	cases := []struct {
		nombre string
		err    error
		status int
		code   string
	}{
		{"usuario inexistente", domain.ErrUserNotFound, http.StatusNotFound, "USER_NOT_FOUND"},
		{"no está en revisión", domain.ErrNotUnderReview, http.StatusConflict, "NOT_UNDER_REVIEW"},
		{"decisión inválida", domain.ErrInvalidReviewDecision, http.StatusBadRequest, "INVALID_BODY"},
		{"base caída", domain.ErrDatabaseUnavailable, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE"},
		{"error inesperado", errors.New("boom con datos internos"), http.StatusInternalServerError, "error_interno"},
	}
	for _, c := range cases {
		t.Run(c.nombre, func(t *testing.T) {
			ts := newAdminTestServer(t)
			ts.review.err = c.err

			rec := ts.do(http.MethodPost, "/admin/v1/review-cases/"+uuid.NewString()+"/unblock",
				`{"reason":"un motivo suficiente","operator":"ana"}`)

			if rec.Code != c.status {
				t.Fatalf("status = %d, se esperaba %d (%s)", rec.Code, c.status, rec.Body.String())
			}
			e := leerError(t, rec)
			if e.Code != c.code {
				t.Errorf("code = %q, se esperaba %q", e.Code, c.code)
			}
			if strings.Contains(rec.Body.String(), "boom") {
				t.Errorf("la respuesta filtra el error interno: %s", rec.Body.String())
			}
			if c.status == http.StatusServiceUnavailable && rec.Header().Get("Retry-After") == "" {
				t.Error("el 503 debería llevar Retry-After")
			}
		})
	}
}

func TestUnblockRechazaCuerposInvalidos(t *testing.T) {
	cases := map[string]string{
		"sin cuerpo":         ``,
		"no es JSON":         `esto no es json`,
		"campo desconocido":  `{"reason":"un motivo suficiente","operator":"ana","extra":"x"}`,
		"tipos equivocados":  `{"reason":123,"operator":"ana"}`,
		"cuerpo desmesurado": `{"reason":"` + strings.Repeat("a", 9000) + `","operator":"ana"}`,
	}
	for nombre, body := range cases {
		t.Run(nombre, func(t *testing.T) {
			ts := newAdminTestServer(t)

			rec := ts.do(http.MethodPost, "/admin/v1/review-cases/"+uuid.NewString()+"/unblock", body)

			if rec.Code != http.StatusBadRequest || leerError(t, rec).Code != "INVALID_BODY" {
				t.Errorf("se esperaba 400 INVALID_BODY, se obtuvo %d (%s)", rec.Code, rec.Body.String())
			}
			if ts.review.unblockCalls != 0 {
				t.Error("no debería desbloquear con un cuerpo inválido")
			}
		})
	}
}

// Un id que no es un UUID no puede existir: 404 USER_NOT_FOUND sin llegar al
// servicio.
func TestUnblockConUnIdQueNoEsUUIDDevuelve404(t *testing.T) {
	for _, id := range []string{"no-es-uuid", "123", uuid.Nil.String()} {
		ts := newAdminTestServer(t)

		rec := ts.do(http.MethodPost, "/admin/v1/review-cases/"+id+"/unblock", `{"reason":"un motivo suficiente","operator":"ana"}`)

		if rec.Code != http.StatusNotFound || leerError(t, rec).Code != "USER_NOT_FOUND" {
			t.Errorf("id %q: se esperaba 404 USER_NOT_FOUND, se obtuvo %d (%s)", id, rec.Code, rec.Body.String())
		}
		if ts.review.unblockCalls != 0 {
			t.Errorf("id %q: no debería llegar al servicio", id)
		}
	}
}

func TestReviewDecisionsDevuelveElHistorial(t *testing.T) {
	ts := newAdminTestServer(t)
	decidida := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	ts.review.decisions = []domain.ReviewDecision{
		{ID: uuid.New(), UserID: uuid.New(), Decision: "UNBLOCK", Reason: "Sin fraude comprobado", Operator: "ana", DecidedAt: decidida},
	}

	rec := ts.do(http.MethodGet, "/admin/v1/review-cases/"+uuid.NewString()+"/decisions", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	var body struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("respuesta ilegible: %v", err)
	}
	if len(body.Items) != 1 {
		t.Fatalf("items = %d, se esperaba 1", len(body.Items))
	}
	want := map[string]any{"decision": "UNBLOCK", "reason": "Sin fraude comprobado", "operator": "ana", "decided_at": "2026-11-15T12:00:00Z"}
	for k, v := range want {
		if body.Items[0][k] != v {
			t.Errorf("items[0].%s = %v, se esperaba %v", k, body.Items[0][k], v)
		}
	}
	if len(body.Items[0]) != len(want) {
		t.Errorf("el item tiene campos de más: %v", body.Items[0])
	}
}

func TestReviewDecisionsSinHistorialDevuelveListaVacia(t *testing.T) {
	ts := newAdminTestServer(t)

	for _, id := range []string{uuid.NewString(), "no-es-uuid"} {
		rec := ts.do(http.MethodGet, "/admin/v1/review-cases/"+id+"/decisions", "")

		if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"items":[]}` {
			t.Errorf("id %q: se obtuvo %d %s", id, rec.Code, rec.Body.String())
		}
	}
}

func TestReviewDecisionsConLaBaseCaidaDevuelve503(t *testing.T) {
	ts := newAdminTestServer(t)
	ts.review.err = domain.ErrDatabaseUnavailable

	rec := ts.do(http.MethodGet, "/admin/v1/review-cases/"+uuid.NewString()+"/decisions", "")

	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Errorf("se esperaba 503 con Retry-After, se obtuvo %d", rec.Code)
	}
}

func TestListReviewCasesConErrorInesperadoDevuelve500SinDetalle(t *testing.T) {
	ts := newAdminTestServer(t)
	ts.review.err = errors.New("fallo interno con detalle")

	rec := ts.do(http.MethodGet, "/admin/v1/review-cases", "")

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, se esperaba 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "detalle") {
		t.Errorf("la respuesta filtra el error interno: %s", rec.Body.String())
	}
}

// La petición lleva el X-Request-ID del llamador y el error lo devuelve en
// request_id, para correlacionar con el log.
func TestAdminElErrorLlevaElRequestID(t *testing.T) {
	ts := newAdminTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/review-cases?limit=0", nil)
	req.Header.Set(delivery.HeaderAdminAPIKey, claveDeAdminDePrueba)
	req.Header.Set(delivery.HeaderRequestID, "req-1234")
	rec := httptest.NewRecorder()

	ts.handler.ServeHTTP(rec, req)

	if got := leerError(t, rec).RequestID; got != "req-1234" {
		t.Errorf("request_id = %q, se esperaba req-1234", got)
	}
}
