package http

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/secure"
	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/validation"
)

// HeaderUserID es la cabecera con el identificador del usuario autenticado que
// Kong inyecta tras validar el JWT (plugin token-offloading). Kong la pisa en
// cada petición: lo que mande el cliente no llega acá.
const HeaderUserID = "X-User-Id"

// maxAccountBodyBytes es el tope del cuerpo de la baja de cuenta. El cuerpo es
// un JSON con una contraseña de a lo sumo validation.MaxPasswordLength
// caracteres: unos pocos cientos de bytes, así que no hace falta el tope de
// DefaultMaxBodyBytes, pensado para el alta con selfie.
const maxAccountBodyBytes int64 = 4 << 10

// retryAfterSeconds es el valor del encabezado Retry-After del 503 de la baja:
// cuánto espera el cliente antes de reintentar si la base no respondió.
const retryAfterSeconds = "5"

// DeleteAccountService es el puerto que necesita el handler para la baja de
// cuenta (US-11), declarado del lado del consumidor por el mismo motivo que
// SignUpService.
type DeleteAccountService interface {
	Delete(ctx context.Context, userID uuid.UUID, password []byte) error
}

// AccountHandler atiende la gestión de la cuenta del usuario autenticado.
type AccountHandler struct {
	deleteAccount DeleteAccountService
	logger        *slog.Logger
}

// NewAccountHandler construye el handler.
func NewAccountHandler(deleteAccount DeleteAccountService, logger *slog.Logger) (*AccountHandler, error) {
	if deleteAccount == nil {
		return nil, errors.New("http: falta el servicio de baja de cuenta")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &AccountHandler{deleteAccount: deleteAccount, logger: logger}, nil
}

// Delete atiende DELETE /api/v1/users/me.
//
//	204 — baja realizada. También si el usuario ya no existe: la baja es
//	      idempotente y no revela nada.
//	400 INVALID_BODY — body ausente, ilegible o sin password.
//	401 INVALID_PASSWORD — la contraseña no coincide.
//	401 UNAUTHORIZED — la petición no trae un X-User-Id válido.
//	500 — falla algo interno; no queda nada hecho.
//	503 DEPENDENCY_UNAVAILABLE — la base no respondió, con Retry-After.
//
// El 401 por JWT ausente o inválido y el 429 por rate limit los produce Kong;
// nunca llegan a este handler. La autorización no se delega del todo en Kong:
// la baja actúa siempre sobre el usuario de X-User-Id, sin ningún identificador
// en la ruta ni en el body, así que no hay forma de pedir la baja de otra
// cuenta.
func (h *AccountHandler) Delete(c *gin.Context) {
	userID, ok := h.authenticatedUser(c)
	if !ok {
		return
	}

	var req deleteAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// El cuerpo es la contraseña: err.Error() de un bind fallido describe
		// sintaxis JSON o un tipo que no matchea, nunca el valor del campo.
		h.logger.WarnContext(c.Request.Context(), "cuerpo de la baja no es JSON interpretable",
			slog.String("request_id", requestIDOf(c)),
			slog.String("error", err.Error()),
		)
		abortRequest(c, http.StatusBadRequest, codeInvalidBody, "el cuerpo debe ser un JSON con el campo password", nil)
		return
	}

	// Fail-fast en la frontera: una contraseña vacía o más larga que cualquiera
	// que el alta acepte no puede ser la de ninguna cuenta, y se rechaza antes de
	// pagar una derivación de Argon2.
	if req.Password == "" || utf8.RuneCountInString(req.Password) > validation.MaxPasswordLength {
		abortRequest(c, http.StatusBadRequest, codeInvalidBody, "el campo password es obligatorio", nil)
		return
	}

	password := []byte(req.Password)
	defer secure.Wipe(password)

	if err := h.deleteAccount.Delete(c.Request.Context(), userID, password); err != nil {
		h.abortDeleteError(c, err)
		return
	}

	c.Status(http.StatusNoContent)
}

// authenticatedUser lee el usuario autenticado de X-User-Id. Fail-closed: sin la
// cabecera, o con una que no es un UUID, la petición se rechaza.
func (h *AccountHandler) authenticatedUser(c *gin.Context) (uuid.UUID, bool) {
	userID, err := uuid.Parse(c.GetHeader(HeaderUserID))
	if err != nil || userID == uuid.Nil {
		h.logger.WarnContext(c.Request.Context(), "baja sin usuario autenticado: falta o es inválido X-User-Id",
			slog.String("request_id", requestIDOf(c)),
		)
		abortRequest(c, http.StatusUnauthorized, codeUnauthorized, "no autenticado", nil)
		return uuid.Nil, false
	}
	return userID, true
}

// abortDeleteError traduce los errores de la baja a su respuesta HTTP. Ninguna
// rama devuelve el error subyacente: el detalle queda en el log del servidor,
// correlacionable por request id.
func (h *AccountHandler) abortDeleteError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalidPassword):
		abortRequest(c, http.StatusUnauthorized, codeInvalidPassword, "la contraseña no es correcta", nil)

	case errors.Is(err, domain.ErrDatabaseUnavailable):
		h.logger.WarnContext(c.Request.Context(), "base de datos no disponible",
			slog.String("request_id", requestIDOf(c)),
			slog.String("error", err.Error()),
		)
		c.Header("Retry-After", retryAfterSeconds)
		abortRequest(c, http.StatusServiceUnavailable, codeDependencyUnavailable,
			"el servicio no está disponible, reintentar en unos segundos", nil)

	default:
		h.logger.ErrorContext(c.Request.Context(), "fallo no esperado en la baja de cuenta",
			slog.String("request_id", requestIDOf(c)),
			slog.String("error", err.Error()),
		)
		abortRequest(c, http.StatusInternalServerError, codeInternal, "error interno", nil)
	}
}
