package http

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

// HeaderAdminAPIKey es la cabecera donde el operador envía la clave de
// administración en cada petición a /admin/*.
const HeaderAdminAPIKey = "X-Admin-Api-Key"

// minAdminAPIKeyLength es el piso de entropía de la clave: es un secreto
// compartido comparado byte a byte, así que su largo es toda la defensa contra
// que alguien lo adivine. pkg/config lo exige igual en el arranque; se repite acá
// para que el router no se pueda armar con una clave débil desde otro llamador.
const minAdminAPIKeyLength = 32

// adminMaxBodyBytes es el tope del cuerpo del router de administración. El mayor
// es el del desbloqueo: un motivo de 500 caracteres (hasta 2 KiB en UTF-8) y un
// operador de 100. No tiene sentido heredar el de 10 MiB del router público, que
// existe por la selfie del alta.
const adminMaxBodyBytes = 8 << 10

// AdminRouterConfig son los parámetros de armado del router de administración
// (US-17).
//
// Se sirve en su propio *http.Server y su propio puerto (ver cmd/api): Kong no lo
// expone, y en el compose de desarrollo solo se publica en 127.0.0.1. En AWS solo
// se alcanza desde la VPC. APIKey es la autenticación de toda ruta; no hay un rol
// de administrador ni sesión de usuario.
type AdminRouterConfig struct {
	Review ReviewAdminService
	Logger *slog.Logger
	// APIKey es la clave que toda petición debe traer en HeaderAdminAPIKey: al
	// menos 32 caracteres, distinta de INTERNAL_SERVICE_TOKEN.
	APIKey string
	Debug  bool
}

// NewAdminRouter arma el router de administración.
func NewAdminRouter(cfg AdminRouterConfig) (*gin.Engine, error) {
	if len(cfg.APIKey) < minAdminAPIKeyLength {
		return nil, errors.New("http: la clave de administración (ADMIN_API_KEY) debe tener al menos 32 caracteres")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	handler, err := NewAdminHandler(cfg.Review, logger)
	if err != nil {
		return nil, err
	}

	if cfg.Debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()

	r.RedirectTrailingSlash = false
	r.RedirectFixedPath = false
	r.HandleMethodNotAllowed = true

	if err := r.SetTrustedProxies(nil); err != nil {
		return nil, err
	}

	r.Use(requestID(), accessLog(logger), recovery(logger), requireAdminAPIKey(cfg.APIKey, logger), limitBody(adminMaxBodyBytes), noStore())

	v1 := r.Group("/admin/v1")
	v1.GET("/review-cases", handler.ListReviewCases)
	v1.POST("/review-cases/:user_id/unblock", handler.Unblock)
	v1.GET("/review-cases/:user_id/decisions", handler.ReviewDecisions)

	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, adminErrorResponse{Error: "recurso no encontrado", Code: codeAdminNotFound, RequestID: requestIDOf(c)})
	})
	r.NoMethod(func(c *gin.Context) {
		c.JSON(http.StatusMethodNotAllowed, adminErrorResponse{Error: "método no permitido", Code: codeAdminMethodNotAllowed, RequestID: requestIDOf(c)})
	})

	return r, nil
}

// requireAdminAPIKey exige, en toda petición, la clave de administración.
//
// Se aplica antes de que el router resuelva si la ruta existe: sin la clave
// correcta el status es 401 tanto si el path es real como si no, así que nunca
// delata qué rutas expone este servidor.
//
// La comparación es a tiempo constante y sobre los SHA-256 de ambos valores: así
// ni el contenido ni el largo de la clave real influyen en el tiempo de respuesta.
func requireAdminAPIKey(key string, logger *slog.Logger) gin.HandlerFunc {
	want := sha256.Sum256([]byte(key))
	return func(c *gin.Context) {
		got := sha256.Sum256([]byte(c.GetHeader(HeaderAdminAPIKey)))

		if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			logger.WarnContext(c.Request.Context(), "petición a una ruta de administración sin clave válida",
				slog.String("request_id", requestIDOf(c)),
				slog.String("path", requestPath(c)),
			)
			c.AbortWithStatusJSON(http.StatusUnauthorized, adminErrorResponse{
				Error:     "no autorizado",
				Code:      codeUnauthorized,
				RequestID: requestIDOf(c),
			})
			return
		}

		c.Next()
	}
}
