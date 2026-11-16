package http

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// Códigos de error del router de administración (US-17), en mayúsculas como los
// de US-11 y US-13. UNAUTHORIZED, INVALID_BODY, USER_NOT_FOUND y
// DEPENDENCY_UNAVAILABLE son los mismos de las otras rutas.
const (
	// codeNotUnderReview es el 409 del desbloqueo de una cuenta que no está en
	// revisión.
	codeNotUnderReview = "NOT_UNDER_REVIEW"
	// codeInvalidQuery es el 400 del listado con un parámetro que no cumple el
	// contrato: status, limit o cursor.
	codeInvalidQuery = "INVALID_QUERY"
	// codeAdminNotFound y codeAdminMethodNotAllowed son el 404 y el 405 de una
	// ruta que no existe, una vez pasada la clave.
	codeAdminNotFound         = "NOT_FOUND"
	codeAdminMethodNotAllowed = "METHOD_NOT_ALLOWED"
)

const (
	// defaultReviewCasesLimit es el tamaño de página del listado de casos cuando
	// no se pide otro.
	defaultReviewCasesLimit = 50
	// maxReviewCasesLimit es el tope del tamaño de página.
	maxReviewCasesLimit = 100
	// maxCursorLength acota el cursor que se acepta: el real mide menos de 60.
	maxCursorLength = 128
)

// ReviewAdminService es el puerto que necesita el handler de administración,
// declarado del lado del consumidor por el mismo motivo que SignUpService.
type ReviewAdminService interface {
	ListCases(ctx context.Context, status domain.AccountStatus, limit int, cursor string) (domain.ReviewCasePage, error)
	Unblock(ctx context.Context, userID uuid.UUID, reason, operator string) (uuid.UUID, error)
	Decisions(ctx context.Context, userID uuid.UUID) ([]domain.ReviewDecision, error)
}

// AdminHandler atiende las rutas /admin/*. Es un tipo distinto de Handler y de
// InternalHandler: su autenticación es una clave de administración y nada de lo
// que devuelve incluye datos personales.
type AdminHandler struct {
	review ReviewAdminService
	logger *slog.Logger
}

// NewAdminHandler construye el handler de administración.
func NewAdminHandler(review ReviewAdminService, logger *slog.Logger) (*AdminHandler, error) {
	if review == nil {
		return nil, errors.New("http: falta el servicio de revisión de casos")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &AdminHandler{review: review, logger: logger}, nil
}

// adminErrorResponse es la forma de los errores del router de administración:
// { error, code }, más el id de petición para correlacionar con el log. No lleva
// los campos de errorResponse que son para clientes de la app.
type adminErrorResponse struct {
	Error     string `json:"error"`
	Code      string `json:"code"`
	RequestID string `json:"request_id,omitempty"`
}

type reviewCaseResponse struct {
	UserID           string  `json:"user_id"`
	AccountStatus    string  `json:"account_status"`
	ReportCount      int     `json:"report_count"`
	ReputationScore  int     `json:"reputation_score"`
	UnderReviewSince *string `json:"under_review_since"`
	LastReportedAt   *string `json:"last_reported_at"`
}

type reviewCasesResponse struct {
	Items      []reviewCaseResponse `json:"items"`
	NextCursor *string              `json:"next_cursor"`
}

// unblockRequest es el cuerpo del desbloqueo. Los largos los valida el servicio.
type unblockRequest struct {
	Reason   string `json:"reason"`
	Operator string `json:"operator"`
}

type reviewDecisionResponse struct {
	Decision  string `json:"decision"`
	Reason    string `json:"reason"`
	Operator  string `json:"operator"`
	DecidedAt string `json:"decided_at"`
}

type reviewDecisionsResponse struct {
	Items []reviewDecisionResponse `json:"items"`
}

// ListReviewCases atiende GET /admin/v1/review-cases.
//
//	200 — {items, next_cursor}, del caso más viejo al más nuevo.
//	400 INVALID_QUERY — status distinto de UNDER_REVIEW, limit fuera de 1..100 o
//	      un cursor que no es uno devuelto por el servicio.
//	503 DEPENDENCY_UNAVAILABLE — la base no responde, con Retry-After.
func (h *AdminHandler) ListReviewCases(c *gin.Context) {
	if status := c.DefaultQuery("status", string(domain.AccountStatusUnderReview)); status != string(domain.AccountStatusUnderReview) {
		h.abort(c, http.StatusBadRequest, codeInvalidQuery, "status solo admite UNDER_REVIEW")
		return
	}

	limit := defaultReviewCasesLimit
	if raw, ok := c.GetQuery("limit"); ok {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > maxReviewCasesLimit {
			h.abort(c, http.StatusBadRequest, codeInvalidQuery, "limit debe ser un entero entre 1 y "+strconv.Itoa(maxReviewCasesLimit))
			return
		}
		limit = n
	}

	cursor := c.Query("cursor")
	if len(cursor) > maxCursorLength {
		h.abort(c, http.StatusBadRequest, codeInvalidQuery, "cursor inválido")
		return
	}

	page, err := h.review.ListCases(c.Request.Context(), domain.AccountStatusUnderReview, limit, cursor)
	if err != nil {
		h.abortError(c, "listar los casos de revisión", err)
		return
	}

	resp := reviewCasesResponse{Items: make([]reviewCaseResponse, 0, len(page.Items))}
	for _, item := range page.Items {
		resp.Items = append(resp.Items, reviewCaseResponse{
			UserID:           item.UserID.String(),
			AccountStatus:    string(item.AccountStatus),
			ReportCount:      item.ReportCount,
			ReputationScore:  item.ReputationScore,
			UnderReviewSince: formatTimePtr(item.UnderReviewSince),
			LastReportedAt:   formatTimePtr(item.LastReportedAt),
		})
	}
	if page.NextCursor != "" {
		resp.NextCursor = &page.NextCursor
	}
	c.JSON(http.StatusOK, resp)
}

// Unblock atiende POST /admin/v1/review-cases/{user_id}/unblock.
//
//	204 — la cuenta volvió a ACTIVE y la decisión quedó registrada.
//	400 INVALID_BODY — cuerpo ilegible, con campos desconocidos, o un motivo
//	      (10 a 500 caracteres) u operador (1 a 100) fuera de rango.
//	404 USER_NOT_FOUND — la cuenta no existe, o el id no es un UUID.
//	409 NOT_UNDER_REVIEW — la cuenta no está en revisión.
//	503 DEPENDENCY_UNAVAILABLE — la base no responde, con Retry-After.
//
// El motivo no se loguea: lo escribe una persona y puede nombrar a otra.
func (h *AdminHandler) Unblock(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil || userID == uuid.Nil {
		h.abort(c, http.StatusNotFound, codeUserNotFound, "el usuario no existe")
		return
	}

	var req unblockRequest
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		h.abort(c, http.StatusBadRequest, codeInvalidBody, "el cuerpo debe ser un JSON con reason y operator")
		return
	}

	if _, err := h.review.Unblock(c.Request.Context(), userID, req.Reason, req.Operator); err != nil {
		h.abortError(c, "desbloquear la cuenta", err)
		return
	}
	c.Status(http.StatusNoContent)
}

// ReviewDecisions atiende GET /admin/v1/review-cases/{user_id}/decisions.
//
//	200 — {items}, de la decisión más nueva a la más vieja; vacío si no hay.
//	503 DEPENDENCY_UNAVAILABLE — la base no responde, con Retry-After.
func (h *AdminHandler) ReviewDecisions(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil || userID == uuid.Nil {
		// Un id que no es un UUID no puede tener historial.
		c.JSON(http.StatusOK, reviewDecisionsResponse{Items: []reviewDecisionResponse{}})
		return
	}

	decisions, err := h.review.Decisions(c.Request.Context(), userID)
	if err != nil {
		h.abortError(c, "leer el historial de decisiones", err)
		return
	}

	resp := reviewDecisionsResponse{Items: make([]reviewDecisionResponse, 0, len(decisions))}
	for _, d := range decisions {
		resp.Items = append(resp.Items, reviewDecisionResponse{
			Decision:  d.Decision,
			Reason:    d.Reason,
			Operator:  d.Operator,
			DecidedAt: d.DecidedAt.UTC().Format(time.RFC3339),
		})
	}
	c.JSON(http.StatusOK, resp)
}

func formatTimePtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}

// abortError traduce los errores del servicio a su respuesta HTTP. Ninguna rama
// devuelve el error subyacente; el detalle queda en el log, sin el motivo.
func (h *AdminHandler) abortError(c *gin.Context, op string, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalidReviewDecision):
		h.abort(c, http.StatusBadRequest, codeInvalidBody, "reason debe tener entre 10 y 500 caracteres y operator entre 1 y 100")
	case errors.Is(err, domain.ErrInvalidCursor):
		h.abort(c, http.StatusBadRequest, codeInvalidQuery, "cursor inválido")
	case errors.Is(err, domain.ErrUserNotFound):
		h.abort(c, http.StatusNotFound, codeUserNotFound, "el usuario no existe")
	case errors.Is(err, domain.ErrNotUnderReview):
		h.abort(c, http.StatusConflict, codeNotUnderReview, "la cuenta no está en revisión")
	case errors.Is(err, domain.ErrDatabaseUnavailable):
		h.logger.WarnContext(c.Request.Context(), "base de datos no disponible en la administración",
			slog.String("request_id", requestIDOf(c)),
			slog.String("operacion", op),
			slog.String("error", err.Error()),
		)
		c.Header("Retry-After", retryAfterSeconds)
		h.abort(c, http.StatusServiceUnavailable, codeDependencyUnavailable, "el servicio no está disponible, reintentar en unos segundos")
	default:
		h.logger.ErrorContext(c.Request.Context(), "fallo no esperado en la administración",
			slog.String("request_id", requestIDOf(c)),
			slog.String("operacion", op),
			slog.String("error", err.Error()),
		)
		h.abort(c, http.StatusInternalServerError, codeInternal, "error interno")
	}
}

func (h *AdminHandler) abort(c *gin.Context, status int, code, message string) {
	c.AbortWithStatusJSON(status, adminErrorResponse{Error: message, Code: code, RequestID: requestIDOf(c)})
}
