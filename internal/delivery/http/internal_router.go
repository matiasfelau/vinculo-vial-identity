package http

import (
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

// HeaderInternalServiceToken es la cabecera donde vinculo-vial-vehicle debe
// enviar el secreto compartido de servicio a servicio en cada petición a
// /internal/*. No es un token de sesión de usuario ni lo emite este
// servicio: es un valor estático, provisto por configuración en los dos
// extremos.
const HeaderInternalServiceToken = "X-Internal-Service-Token"

// InternalRouterConfig son los parámetros de armado del router de las rutas
// /internal/* (POST /internal/verify-ownership de US-04 y POST
// /internal/audit/dni de US-11).
//
// Este router se sirve por separado de NewRouter, en su propio *http.Server y
// su propio puerto (ver cmd/api): ni Kong ni el docker-compose de este
// servicio lo publican fuera de la red interna. Esa separación de puerto es
// una condición necesaria pero no suficiente —dentro de la red Docker
// cualquier contenedor puede alcanzar cualquier puerto de otro—, así que
// requireServiceToken exige además, en toda petición, el secreto de
// ServiceToken como segunda capa de la defensa en profundidad. Las dos capas
// son independientes: aunque el puerto interno quedara mal aislado en algún
// entorno, el secreto seguiría bloqueando a un contenedor que no lo conozca.
type InternalRouterConfig struct {
	// VerifyOwnership es el caso de uso de POST /internal/verify-ownership
	// (US-04).
	VerifyOwnership VerifyOwnershipService
	// AuditDNI es el caso de uso de POST /internal/audit/dni (US-11, Audit).
	AuditDNI AuditDNIService
	Logger   *slog.Logger
	// ServiceToken es el secreto que toda petición a /internal/* debe traer
	// en HeaderInternalServiceToken. Es obligatorio: sin él, este router
	// sería exactamente el oráculo de verificación de DNI por fuerza bruta
	// que el aislamiento existe para evitar.
	ServiceToken string
	MaxBodyBytes int64
	Debug        bool
}

// NewInternalRouter arma el router interno.
//
// A diferencia de NewRouter, acá el secreto de servicio se exige en toda
// ruta, incluida /internal/healthz: este puerto no lo consulta ningún
// balanceador externo —el orquestador usa /ready del router público para
// decidir si el proceso está listo—, así que no hay necesidad operativa de
// dejar una excepción, y cada excepción es superficie de menos que proteger.
func NewInternalRouter(cfg InternalRouterConfig) (*gin.Engine, error) {
	if cfg.ServiceToken == "" {
		return nil, errors.New("http: falta el secreto de servicio del router interno (INTERNAL_SERVICE_TOKEN)")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	handler, err := NewInternalHandler(cfg.VerifyOwnership, cfg.AuditDNI, logger)
	if err != nil {
		return nil, err
	}

	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultMaxBodyBytes
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

	r.Use(requestID(), accessLog(logger), recovery(logger), requireServiceToken(cfg.ServiceToken, logger), limitBody(maxBody), noStore())

	r.GET("/internal/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	r.POST("/internal/verify-ownership", handler.VerifyOwnership)
	r.POST("/internal/audit/dni", handler.AuditDNI)

	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, errorResponse{Code: codeInvalidRequest, Error: "recurso no encontrado", RequestID: requestIDOf(c)})
	})
	r.NoMethod(func(c *gin.Context) {
		c.JSON(http.StatusMethodNotAllowed, errorResponse{Code: codeInvalidRequest, Error: "método no permitido", RequestID: requestIDOf(c)})
	})

	return r, nil
}

// requireServiceToken exige, en toda petición, el secreto de servicio a
// servicio configurado. Es la segunda capa de la defensa en profundidad de
// /internal/* que describe InternalRouterConfig.
//
// Al aplicarse antes de que el router resuelva si la ruta existe, una
// petición sin el secreto correcto recibe 401 tanto si el path es real como
// si no: el status nunca delata qué rutas expone este servidor.
//
// La comparación es a tiempo constante: el largo del valor recibido no es
// secreto en sí mismo —viaja sin cifrar en la propia cabecera—, así que
// compararlo antes no reintroduce el problema, pero el contenido nunca se
// compara con un operador (`==`) que corte en el primer byte distinto.
func requireServiceToken(token string, logger *slog.Logger) gin.HandlerFunc {
	want := []byte(token)
	return func(c *gin.Context) {
		got := []byte(c.GetHeader(HeaderInternalServiceToken))

		if len(got) != len(want) || subtle.ConstantTimeCompare(got, want) != 1 {
			logger.WarnContext(c.Request.Context(), "petición a una ruta interna sin secreto de servicio válido",
				slog.String("request_id", requestIDOf(c)),
				slog.String("path", requestPath(c)),
			)
			c.AbortWithStatusJSON(http.StatusUnauthorized, errorResponse{
				Code:      codeUnauthorizedService,
				Error:     "no autorizado",
				RequestID: requestIDOf(c),
			})
			return
		}

		c.Next()
	}
}
