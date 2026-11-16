package http

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// AuditDNIService es el puerto que necesita el handler interno para
// POST /internal/audit/dni (US-11, Audit), declarado del lado del consumidor por
// el mismo motivo que SignUpService.
type AuditDNIService interface {
	SealDNI(ctx context.Context, userID, alertID uuid.UUID) (domain.AuditDNI, error)
}

// InternalHandler atiende las rutas /internal/*. Es deliberadamente un tipo
// distinto de Handler: la autenticación (secreto de servicio, no sesión de
// usuario) y el perfil de riesgo de sus logs (nunca DNI, solo owner_id) son
// ajenos al resto del servicio, y no tiene sentido que comparta el mismo
// constructor obligado a las cuatro dependencias de /api/v1/auth/*.
type InternalHandler struct {
	auditDNI AuditDNIService
	logger   *slog.Logger
}

// NewInternalHandler construye el handler interno.
func NewInternalHandler(auditDNI AuditDNIService, logger *slog.Logger) (*InternalHandler, error) {
	if auditDNI == nil {
		return nil, errors.New("http: falta el servicio de sellado del DNI para Audit")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &InternalHandler{auditDNI: auditDNI, logger: logger}, nil
}

// AuditDNI atiende POST /internal/audit/dni.
//
//	200 — {dni_enc_audit, audit_key_id}: el DNI del usuario sellado hacia Audit,
//	      con el `info` atado a alert_id.
//	400 INVALID_BODY — el cuerpo no es JSON interpretable, o user_id o alert_id
//	      faltan o no son un UUID válido.
//	404 USER_NOT_FOUND — el usuario no existe.
//	503 DEPENDENCY_UNAVAILABLE — la base de datos propia no está disponible, con
//	      Retry-After.
//	500 — falla algo interno distinto.
//
// El 401 por la falta del secreto de servicio lo produce el middleware del
// router interno.
//
// Ningún log de este handler lleva el DNI, el criptograma ni el par user_id y
// alert_id: ese vínculo solo tiene que existir en el registro de Audit. Los
// fallos se correlacionan por request id.
func (h *InternalHandler) AuditDNI(c *gin.Context) {
	var req auditDNIRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WarnContext(c.Request.Context(), "cuerpo de audit/dni no es JSON interpretable",
			slog.String("request_id", requestIDOf(c)),
			slog.String("error", err.Error()),
		)
		h.abort(c, http.StatusBadRequest, codeInvalidBody, "el cuerpo debe ser un JSON con los campos user_id y alert_id")
		return
	}

	userID, userErr := uuid.Parse(req.UserID)
	alertID, alertErr := uuid.Parse(req.AlertID)
	if userErr != nil || alertErr != nil || userID == uuid.Nil || alertID == uuid.Nil {
		h.logger.WarnContext(c.Request.Context(), "user_id o alert_id de audit/dni no son UUID válidos",
			slog.String("request_id", requestIDOf(c)),
		)
		h.abort(c, http.StatusBadRequest, codeInvalidBody, "user_id y alert_id deben ser UUID válidos")
		return
	}

	sealed, err := h.auditDNI.SealDNI(c.Request.Context(), userID, alertID)
	if err != nil {
		h.abortAuditDNIError(c, err)
		return
	}

	c.JSON(http.StatusOK, auditDNIResponse{DNIEncAudit: sealed.Sealed, AuditKeyID: sealed.KeyID})
}

// abortAuditDNIError traduce los errores de AuditDNIService a su respuesta HTTP.
// Ninguna rama devuelve el error subyacente: el detalle queda en el log del
// servidor, sin el DNI ni el criptograma.
func (h *InternalHandler) abortAuditDNIError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, domain.ErrUserNotFound):
		h.logger.WarnContext(c.Request.Context(), "audit/dni de un usuario que no existe",
			slog.String("request_id", requestIDOf(c)),
		)
		h.abort(c, http.StatusNotFound, codeUserNotFound, "el usuario no existe")

	case errors.Is(err, domain.ErrDatabaseUnavailable):
		h.logger.WarnContext(c.Request.Context(), "base de datos no disponible en audit/dni",
			slog.String("request_id", requestIDOf(c)),
			slog.String("error", err.Error()),
		)
		c.Header("Retry-After", retryAfterSeconds)
		h.abort(c, http.StatusServiceUnavailable, codeDependencyUnavailable, "el servicio no está disponible, reintentar en unos segundos")

	default:
		h.logger.ErrorContext(c.Request.Context(), "fallo no esperado en audit/dni",
			slog.String("request_id", requestIDOf(c)),
			slog.String("error", err.Error()),
		)
		h.abort(c, http.StatusInternalServerError, codeInternal, "error interno")
	}
}

func (h *InternalHandler) abort(c *gin.Context, status int, code, message string) {
	c.AbortWithStatusJSON(status, errorResponse{
		Code:      code,
		Error:     message,
		Message:   message,
		RequestID: requestIDOf(c),
	})
}
