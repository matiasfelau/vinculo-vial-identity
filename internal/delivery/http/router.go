package http

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

// DefaultMaxBodyBytes es el tope del cuerpo aceptado.
//
// Desde que el payload incluye una selfie, el cuerpo ya no ronda los cientos de
// bytes de antes: validation.MaxSelfieBytes (4 MiB) en base64 son ~5.3 MiB, y
// todo el JSON —selfie incluida— se vuelve a envolver en base64 una vez más como
// `ciphertext` del mensaje HPKE, sumando otro ~33%. 10 MiB deja margen sobre ese
// cálculo sin habilitar que el endpoint reciba archivos arbitrariamente grandes.
const DefaultMaxBodyBytes int64 = 10 << 20

// RouterConfig son los parámetros de armado del router.
type RouterConfig struct {
	SignUp  SignUpService
	SignIn  SignInService
	Refresh RefreshService
	Logout  LogoutService
	Logger  *slog.Logger
	// ReadinessCheck reporta si las dependencias externas responden. Si es nil,
	// /ready se limita a informar que el proceso está vivo.
	ReadinessCheck func(context.Context) error
	// MaxBodyBytes limita el cuerpo de las peticiones. Si es 0 se usa el valor
	// por defecto.
	MaxBodyBytes int64
	// Debug habilita el modo verboso de Gin. Fuera de desarrollo debe quedar en
	// false: el modo debug imprime las rutas y los detalles de binding.
	Debug bool
}

// NewRouter arma el router con sus middlewares y rutas.
func NewRouter(cfg RouterConfig) (*gin.Engine, error) {
	handler, err := NewHandler(cfg.SignUp, cfg.SignIn, cfg.Refresh, cfg.Logout, cfg.Logger)
	if err != nil {
		return nil, err
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
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

	// gin.New y no gin.Default: el logger por defecto escribe texto sin
	// estructura a stdout y duplicaría el log de acceso estructurado.
	r := gin.New()

	// Sin redirecciones implícitas: una ruta mal escrita debe dar 404 o 405, no
	// un 301 que la app siga a ciegas reenviando el criptograma.
	r.RedirectTrailingSlash = false
	r.RedirectFixedPath = false
	r.HandleMethodNotAllowed = true

	// No se confía en las cabeceras de proxy para derivar la IP del cliente: el
	// servicio no la usa para nada y creerle a un X-Forwarded-For que el cliente
	// controla solo serviría para envenenar los logs.
	if err := r.SetTrustedProxies(nil); err != nil {
		return nil, err
	}

	r.Use(requestID(), accessLog(logger), recovery(logger))

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	readyHandler := func(c *gin.Context) {
		if cfg.ReadinessCheck != nil {
			if err := cfg.ReadinessCheck(c.Request.Context()); err != nil {
				logger.ErrorContext(c.Request.Context(), "dependencia no disponible",
					slog.String("error", err.Error()),
				)
				// El motivo queda en el log: el cuerpo de la respuesta lo puede leer
				// cualquiera que alcance el puerto.
				c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unavailable"})
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	}

	r.GET("/ready", readyHandler)
	r.GET("/readyz", readyHandler)

	auth := r.Group("/api/v1/auth", limitBody(maxBody), noStore())
	auth.POST("/signup", handler.SignUp)
	auth.POST("/signin", handler.SignIn)
	auth.POST("/refresh", handler.Refresh)
	auth.POST("/logout", handler.Logout)

	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, errorResponse{Code: codeInvalidRequest, Error: "recurso no encontrado", RequestID: requestIDOf(c)})
	})
	r.NoMethod(func(c *gin.Context) {
		c.JSON(http.StatusMethodNotAllowed, errorResponse{Code: codeInvalidRequest, Error: "método no permitido", RequestID: requestIDOf(c)})
	})

	return r, nil
}
