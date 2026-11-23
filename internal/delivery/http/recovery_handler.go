package http

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/validation"
)

// maxRecoveryBodyBytes es el tope del cuerpo de los endpoints de email y de los
// dos primeros pasos de la recuperación: un sobre HPKE con un email, un DNI o un
// código son unos cientos de bytes. La revalidación (complete) lleva una selfie y
// usa el tope del alta.
const maxRecoveryBodyBytes int64 = 8 << 10

// EmailVerificationService es el puerto que necesita el handler para la
// verificación del email del alta (US-13), declarado del lado del consumidor por
// el mismo motivo que SignUpService.
type EmailVerificationService interface {
	// Request atiende el pedido del código: nil siempre que el email sea válido,
	// exista o no una cuenta.
	Request(ctx context.Context, ephemeralPublicKey, ciphertext []byte) error
	// Confirm verifica el código y devuelve el token que consume el alta.
	Confirm(ctx context.Context, ephemeralPublicKey, ciphertext []byte) (token string, expiresIn time.Duration, err error)
}

// PasswordResetService es el puerto que necesita el handler para la recuperación
// de contraseña (US-13).
type PasswordResetService interface {
	// Request atiende el pedido del código: nil siempre que el DNI sea válido,
	// exista o no la cuenta.
	Request(ctx context.Context, ephemeralPublicKey, ciphertext []byte) error
	// Confirm verifica el código y devuelve el reset_token.
	Confirm(ctx context.Context, ephemeralPublicKey, ciphertext []byte) (token string, expiresIn time.Duration, err error)
	// Complete revalida la identidad y cambia la contraseña.
	Complete(ctx context.Context, ephemeralPublicKey, ciphertext []byte) error
}

// RecoveryHandler atiende la verificación de email del alta y la recuperación de
// contraseña (US-13). Los cinco endpoints reciben el sobre HPKE vigente y usan el
// formato de error vigente.
type RecoveryHandler struct {
	emailVerification EmailVerificationService
	passwordReset     PasswordResetService
	logger            *slog.Logger
}

// NewRecoveryHandler construye el handler.
func NewRecoveryHandler(emailVerification EmailVerificationService, passwordReset PasswordResetService, logger *slog.Logger) (*RecoveryHandler, error) {
	if emailVerification == nil {
		return nil, errors.New("http: falta el servicio de verificación de email")
	}
	if passwordReset == nil {
		return nil, errors.New("http: falta el servicio de recuperación de contraseña")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &RecoveryHandler{emailVerification: emailVerification, passwordReset: passwordReset, logger: logger}, nil
}

// RequestEmailVerification atiende POST /api/v1/auth/email-verifications.
//
//	202 — siempre que el email sea válido, exista o no una cuenta con él.
//	400 datos_invalidos — email mal formado.
//	400 solicitud_invalida — sobre HPKE ausente o mal formado.
//	503 dependencia_no_disponible — la base no responde; con Retry-After.
func (h *RecoveryHandler) RequestEmailVerification(c *gin.Context) {
	eph, ct, ok := h.envelope(c, "pedido de verificación de email")
	if !ok {
		return
	}
	if err := h.emailVerification.Request(c.Request.Context(), eph, ct); err != nil {
		h.abortError(c, err)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{})
}

// ConfirmEmailVerification atiende POST /api/v1/auth/email-verifications/confirm.
//
//	200 — { verification_token, expires_in }, con los segundos de vida del token.
//	400 INVALID_CODE — incorrecto, vencido, usado, inexistente o sin intentos:
//	    indistinguibles.
//	400 solicitud_invalida — sobre HPKE ausente o mal formado.
//	503 dependencia_no_disponible — la base no responde; con Retry-After.
func (h *RecoveryHandler) ConfirmEmailVerification(c *gin.Context) {
	eph, ct, ok := h.envelope(c, "confirmación de verificación de email")
	if !ok {
		return
	}
	token, expiresIn, err := h.emailVerification.Confirm(c.Request.Context(), eph, ct)
	if err != nil {
		h.abortError(c, err)
		return
	}
	c.JSON(http.StatusOK, emailVerificationConfirmResponse{
		VerificationToken: token,
		ExpiresIn:         int64(expiresIn / time.Second),
	})
}

// RequestPasswordReset atiende POST /api/v1/auth/password-resets.
//
//	202 — siempre que el DNI sea válido, exista o no la cuenta.
//	400 datos_invalidos — DNI mal formado.
//	400 solicitud_invalida — sobre HPKE ausente o mal formado.
//	503 dependencia_no_disponible — la base no responde; con Retry-After.
func (h *RecoveryHandler) RequestPasswordReset(c *gin.Context) {
	eph, ct, ok := h.envelope(c, "pedido de recuperación")
	if !ok {
		return
	}
	if err := h.passwordReset.Request(c.Request.Context(), eph, ct); err != nil {
		h.abortError(c, err)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{})
}

// ConfirmPasswordReset atiende POST /api/v1/auth/password-resets/confirm.
//
//	200 — { reset_token, expires_in }, con los segundos de vida del token.
//	400 INVALID_CODE — igual que en la verificación de email.
//	400 solicitud_invalida — sobre HPKE ausente o mal formado.
//	503 dependencia_no_disponible — la base no responde; con Retry-After.
func (h *RecoveryHandler) ConfirmPasswordReset(c *gin.Context) {
	eph, ct, ok := h.envelope(c, "confirmación de recuperación")
	if !ok {
		return
	}
	token, expiresIn, err := h.passwordReset.Confirm(c.Request.Context(), eph, ct)
	if err != nil {
		h.abortError(c, err)
		return
	}
	c.JSON(http.StatusOK, passwordResetConfirmResponse{
		ResetToken: token,
		ExpiresIn:  int64(expiresIn / time.Second),
	})
}

// CompletePasswordReset atiende POST /api/v1/auth/password-resets/complete.
//
//	204 — contraseña cambiada y sesiones cerradas.
//	400 INVALID_RESET_TOKEN — ausente, vencido, usado o sin intentos.
//	400 datos_invalidos — contraseña o campos inválidos, con el mismo detalle que
//	    el alta.
//	400 identidad_no_verificada — RENAPER rechaza o el DNI escaneado no es el de
//	    la cuenta; descuenta un intento del token.
//	400 solicitud_invalida — sobre HPKE ausente o mal formado.
//	503 dependencia_no_disponible — la base o RENAPER no responden; con
//	    Retry-After y sin descontar intentos.
func (h *RecoveryHandler) CompletePasswordReset(c *gin.Context) {
	eph, ct, ok := h.envelope(c, "revalidación de identidad")
	if !ok {
		return
	}
	if err := h.passwordReset.Complete(c.Request.Context(), eph, ct); err != nil {
		h.abortError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// envelope lee y decodifica el sobre HPKE, y aborta con 400 solicitud_invalida si
// falta o está mal formado. operation nombra el endpoint en el log.
func (h *RecoveryHandler) envelope(c *gin.Context, operation string) (ephemeralPublicKey, ciphertext []byte, ok bool) {
	var req hpkeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Todavía no hay nada descifrado: err.Error() de un bind fallido describe
		// sintaxis JSON o un tipo que no matchea, nunca el contenido de un campo.
		h.logger.WarnContext(c.Request.Context(), "cuerpo no es JSON interpretable",
			slog.String("request_id", requestIDOf(c)),
			slog.String("operacion", operation),
			slog.String("error", err.Error()),
		)
		abortRequest(c, http.StatusBadRequest, codeInvalidRequest,
			"el cuerpo debe ser un JSON con los campos ephemeral_public_key y ciphertext", nil)
		return nil, nil, false
	}

	ephemeralPublicKey, ok = decodeField(c, h.logger, "ephemeral_public_key", req.EphemeralPublicKey)
	if !ok {
		return nil, nil, false
	}
	ciphertext, ok = decodeField(c, h.logger, "ciphertext", req.Ciphertext)
	if !ok {
		return nil, nil, false
	}
	return ephemeralPublicKey, ciphertext, true
}

// abortError traduce los errores de los casos de uso de US-13 a su respuesta
// HTTP. Ninguna rama devuelve el error subyacente: el detalle queda en el log del
// servidor, correlacionable por request id, y nunca incluye emails, DNI, códigos
// ni tokens.
func (h *RecoveryHandler) abortError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalidInput):
		// Se detallan los campos rechazados, con su código y mensaje, y nunca los
		// valores: validation.FieldError no tiene dónde guardar uno.
		var verrs validation.Errors
		_ = errors.As(err, &verrs)
		attrs := make([]slog.Attr, 0, len(verrs)+1)
		attrs = append(attrs, slog.String("request_id", requestIDOf(c)))
		for _, fe := range verrs {
			attrs = append(attrs, slog.Group(fe.Field,
				slog.String("code", fe.Code),
				slog.String("message", fe.Message),
			))
		}
		h.logger.LogAttrs(c.Request.Context(), slog.LevelWarn, "datos rechazados por validación", attrs...)
		abortRequest(c, http.StatusBadRequest, codeInvalidInput, "los datos no son válidos", verrs)

	case errors.Is(err, domain.ErrInvalidCode):
		abortRequest(c, http.StatusBadRequest, codeInvalidCode, "el código no es válido", nil)

	case errors.Is(err, domain.ErrInvalidResetToken):
		abortRequest(c, http.StatusBadRequest, codeInvalidResetToken, "el token de recuperación no es válido", nil)

	case errors.Is(err, domain.ErrIdentityNotVerified):
		// Genérico a propósito: precisar si falló el DNI, el trámite, el sexo o la
		// selfie facilitaría tantear los datos de otra persona.
		abortRequest(c, http.StatusBadRequest, codeIdentityNotVerified, "no fue posible verificar la identidad", nil)

	case errors.Is(err, domain.ErrMalformedCryptogram):
		h.logger.WarnContext(c.Request.Context(), "mensaje HPKE mal formado",
			slog.String("request_id", requestIDOf(c)),
			slog.String("error", err.Error()),
		)
		abortRequest(c, http.StatusBadRequest, codeInvalidRequest, "el mensaje cifrado no tiene el formato esperado", nil)

	case errors.Is(err, domain.ErrInvalidCryptogram):
		// 500 por decisión de US-01: un cliente legítimo siempre cifra con la clave
		// pública vigente, así que un fallo acá es desincronización de claves o
		// manipulación.
		h.logger.ErrorContext(c.Request.Context(), "no se pudo descifrar el mensaje HPKE",
			slog.String("request_id", requestIDOf(c)),
		)
		abortRequest(c, http.StatusInternalServerError, codeInternal, "error interno", nil)

	case errors.Is(err, domain.ErrDatabaseUnavailable), errors.Is(err, domain.ErrUpstreamUnavailable):
		// 503 con Retry-After: la base o RENAPER no responden. Ninguna dependencia
		// caída descuenta intentos (los casos de uso no llegan a registrarlos).
		h.logger.WarnContext(c.Request.Context(), "dependencia no disponible",
			slog.String("request_id", requestIDOf(c)),
			slog.String("error", err.Error()),
		)
		c.Header("Retry-After", retryAfterSeconds)
		abortRequest(c, http.StatusServiceUnavailable, codeUpstreamUnavailable,
			"el servicio no está disponible, reintentar en unos segundos", nil)

	case errors.Is(err, domain.ErrUpstreamInvalidResponse):
		// Igual que en el alta: RENAPER respondió, pero con un error de su lado o un
		// cuerpo fuera de contrato.
		h.logger.ErrorContext(c.Request.Context(), "respuesta inválida del upstream",
			slog.String("request_id", requestIDOf(c)),
			slog.String("error", err.Error()),
		)
		abortRequest(c, http.StatusBadGateway, codeUpstreamError,
			"el servicio no está disponible, reintentar en unos segundos", nil)

	default:
		h.logger.ErrorContext(c.Request.Context(), "fallo no esperado en la verificación de email o la recuperación",
			slog.String("request_id", requestIDOf(c)),
			slog.String("error", err.Error()),
		)
		abortRequest(c, http.StatusInternalServerError, codeInternal, "error interno", nil)
	}
}
