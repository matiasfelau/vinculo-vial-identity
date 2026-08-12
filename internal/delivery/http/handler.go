// Package http expone el caso de uso de registro sobre HTTP/REST.
//
// El servicio vive detrás de vinculo-vial-gateway: Kong ya validó App
// Attestation antes de que la petición llegue acá, así que este handler no
// revalida atestación. Sí asume que todo lo demás puede ser hostil.
package http

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/validation"
)

// SignUpService es el puerto que necesita el handler, declarado del lado del
// consumidor para no arrastrar el paquete de servicio en los tests.
type SignUpService interface {
	SignUp(ctx context.Context, cryptogram []byte) (uuid.UUID, error)
}

// Handler atiende el alta de vecinos.
type Handler struct {
	signUp SignUpService
	logger *slog.Logger
}

// NewHandler construye el handler.
func NewHandler(svc SignUpService, logger *slog.Logger) (*Handler, error) {
	if svc == nil {
		return nil, errors.New("http: falta el servicio de registro")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{signUp: svc, logger: logger}, nil
}

// SignUp atiende POST /api/v1/auth/signup.
//
//	201 — alta exitosa, sin tokens (la sesión es US-02).
//	400 — el cuerpo no es interpretable o los datos descifrados no validan.
//	409 — el email o el DNI ya existen, con mensaje genérico.
//	500 — el criptograma no descifra o falla algo interno.
func (h *Handler) SignUp(c *gin.Context) {
	var req signUpRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.abort(c, http.StatusBadRequest, codeInvalidRequest, "el cuerpo debe ser un JSON con el campo cryptogram", nil)
		return
	}

	if req.Cryptogram == "" {
		h.abort(c, http.StatusBadRequest, codeInvalidRequest, "el campo cryptogram es obligatorio", nil)
		return
	}

	cryptogram, err := base64.StdEncoding.DecodeString(req.Cryptogram)
	if err != nil {
		h.abort(c, http.StatusBadRequest, codeInvalidRequest, "el campo cryptogram debe ser base64 estándar", nil)
		return
	}

	userID, err := h.signUp.SignUp(c.Request.Context(), cryptogram)
	if err != nil {
		h.abortWithDomainError(c, err)
		return
	}

	c.JSON(http.StatusCreated, signUpResponse{UserID: userID.String()})
}

// abortWithDomainError traduce los centinelas de domain a códigos HTTP.
//
// Ninguna rama devuelve el error subyacente: el detalle queda en el log del
// servidor, correlacionable por request id, y el cliente solo recibe la
// categoría del fallo.
func (h *Handler) abortWithDomainError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalidInput):
		// Es el único caso en que se detalla algo: los campos rechazados, con
		// su código, para que la app corrija el formulario en un solo intento.
		// Los valores rechazados nunca se incluyen.
		var verrs validation.Errors
		_ = errors.As(err, &verrs)
		h.abort(c, http.StatusBadRequest, codeInvalidInput, "los datos de registro no son válidos", verrs)

	case errors.Is(err, domain.ErrDuplicateUser):
		// Mensaje deliberadamente ambiguo: decir si colisionó el email o el DNI
		// permitiría averiguar si una persona concreta está registrada.
		h.abort(c, http.StatusConflict, codeConflict, "no es posible completar el registro con los datos provistos", nil)

	case errors.Is(err, domain.ErrInvalidCryptogram):
		// 500 por decisión de US-01: un cliente legítimo siempre cifra con la
		// clave pública vigente, así que un fallo acá es desincronización de
		// claves o manipulación. El cuerpo no revela nada criptográfico.
		h.logger.ErrorContext(c.Request.Context(), "no se pudo descifrar el criptograma",
			slog.String("request_id", requestIDOf(c)),
		)
		h.abort(c, http.StatusInternalServerError, codeInternal, "error interno", nil)

	default:
		h.logger.ErrorContext(c.Request.Context(), "fallo no esperado en el registro",
			slog.String("request_id", requestIDOf(c)),
			slog.String("error", err.Error()),
		)
		h.abort(c, http.StatusInternalServerError, codeInternal, "error interno", nil)
	}
}

func (h *Handler) abort(c *gin.Context, status int, code, message string, details validation.Errors) {
	c.AbortWithStatusJSON(status, errorResponse{
		Code:      code,
		Error:     message,
		Details:   details,
		RequestID: requestIDOf(c),
	})
}
