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

// VerifyOwnershipService es el puerto que necesita el handler interno para
// POST /internal/verify-ownership (US-04), declarado del lado del
// consumidor por el mismo motivo que SignUpService.
type VerifyOwnershipService interface {
	VerifyOwnership(ctx context.Context, ownerID uuid.UUID, cryptogram []byte) (match bool, err error)
}

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
	verifyOwnership VerifyOwnershipService
	auditDNI        AuditDNIService
	logger          *slog.Logger
}

// NewInternalHandler construye el handler interno.
func NewInternalHandler(verifyOwnership VerifyOwnershipService, auditDNI AuditDNIService, logger *slog.Logger) (*InternalHandler, error) {
	if verifyOwnership == nil {
		return nil, errors.New("http: falta el servicio de verificación de titularidad")
	}
	if auditDNI == nil {
		return nil, errors.New("http: falta el servicio de sellado del DNI para Audit")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &InternalHandler{verifyOwnership: verifyOwnership, auditDNI: auditDNI, logger: logger}, nil
}

// VerifyOwnership atiende POST /internal/verify-ownership.
//
//	200 — siempre que el cuerpo sea interpretable y el criptograma descifre:
//	      {match: true} o {match: false}. Nunca ningún otro dato: ni el DNI,
//	      ni el email, ni por qué dio false.
//	400 — el cuerpo no es JSON interpretable, owner_id no es un UUID válido,
//	      dni_enc no es base64, o el criptograma no tiene la forma de un
//	      mensaje HPKE.
//	503 — la base de datos propia no está disponible.
//	500 — el criptograma no descifra (clave desincronizada o manipulación),
//	      o falla algo interno distinto.
//
// La autenticación de servicio a servicio (X-Internal-Service-Token) la
// exige el middleware del router interno antes de que la petición llegue
// acá: este handler nunca produce un 401 ni un 403 por su cuenta.
func (h *InternalHandler) VerifyOwnership(c *gin.Context) {
	var req verifyOwnershipRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WarnContext(c.Request.Context(), "cuerpo de verify-ownership no es JSON interpretable",
			slog.String("request_id", requestIDOf(c)),
			slog.String("error", err.Error()),
		)
		h.abort(c, http.StatusBadRequest, codeInvalidRequest, "el cuerpo debe ser un JSON con los campos owner_id y dni_enc")
		return
	}

	ownerID, err := uuid.Parse(req.OwnerID)
	if err != nil {
		h.logger.WarnContext(c.Request.Context(), "owner_id de verify-ownership no es un UUID válido",
			slog.String("request_id", requestIDOf(c)),
		)
		h.abort(c, http.StatusBadRequest, codeInvalidRequest, "owner_id debe ser un UUID válido")
		return
	}

	cryptogram, err := decodeBase64(req.DNIEnc)
	if err != nil {
		h.logger.WarnContext(c.Request.Context(), "dni_enc de verify-ownership no es base64 válido",
			slog.String("request_id", requestIDOf(c)),
			slog.String("owner_id", ownerID.String()),
		)
		h.abort(c, http.StatusBadRequest, codeInvalidRequest, "dni_enc debe ser base64")
		return
	}

	match, err := h.verifyOwnership.VerifyOwnership(c.Request.Context(), ownerID, cryptogram)
	if err != nil {
		h.abortVerifyOwnershipError(c, err, ownerID)
		return
	}

	c.JSON(http.StatusOK, verifyOwnershipResponse{Match: match})
}

// abortVerifyOwnershipError traduce los centinelas de domain que puede
// devolver VerifyOwnershipService a códigos HTTP.
//
// Solo dos categorías vienen del descifrado —igual que en SignUp/SignIn—:
// un criptograma mal formado se verifica sin tocar la clave privada (400);
// uno bien formado que no abre es indistinguible entre clave desincronizada
// y manipulación (500). Cualquier otro error es un fallo de infraestructura
// (p. ej. el repositorio), también 500.
func (h *InternalHandler) abortVerifyOwnershipError(c *gin.Context, err error, ownerID uuid.UUID) {
	switch {
	case errors.Is(err, domain.ErrMalformedCryptogram):
		h.logger.WarnContext(c.Request.Context(), "dni_enc mal formado en verify-ownership",
			slog.String("request_id", requestIDOf(c)),
			slog.String("owner_id", ownerID.String()),
		)
		h.abort(c, http.StatusBadRequest, codeInvalidRequest, "el criptograma no tiene el formato esperado")

	case errors.Is(err, domain.ErrInvalidCryptogram):
		h.logger.ErrorContext(c.Request.Context(), "no se pudo descifrar dni_enc en verify-ownership",
			slog.String("request_id", requestIDOf(c)),
			slog.String("owner_id", ownerID.String()),
		)
		h.abort(c, http.StatusInternalServerError, codeInternal, "error interno")

	case errors.Is(err, domain.ErrDatabaseUnavailable):
		h.logger.WarnContext(c.Request.Context(), "base de datos no disponible en verify-ownership",
			slog.String("request_id", requestIDOf(c)),
			slog.String("owner_id", ownerID.String()),
			slog.String("error", err.Error()),
		)
		h.abort(c, http.StatusServiceUnavailable, codeUpstreamUnavailable, "el servicio no está disponible, reintentar en unos segundos")

	default:
		h.logger.ErrorContext(c.Request.Context(), "fallo no esperado en verify-ownership",
			slog.String("request_id", requestIDOf(c)),
			slog.String("owner_id", ownerID.String()),
			slog.String("error", err.Error()),
		)
		h.abort(c, http.StatusInternalServerError, codeInternal, "error interno")
	}
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
// router interno, igual que en verify-ownership.
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
