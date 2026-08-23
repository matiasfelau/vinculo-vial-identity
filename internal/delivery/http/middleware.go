package http

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// HeaderRequestID es la cabecera de correlación que propaga el gateway.
const HeaderRequestID = "X-Request-ID"

const contextRequestID = "request_id"

// requestID reutiliza el identificador que ya trae la petición desde Kong y solo
// genera uno nuevo si falta, para que una traza atraviese gateway y servicio sin
// cortarse.
func requestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader(HeaderRequestID)
		if id == "" || len(id) > 128 {
			// Un valor desmesurado es basura del cliente: se descarta en vez de
			// propagarlo a los logs.
			id = uuid.NewString()
		}

		c.Set(contextRequestID, id)
		c.Writer.Header().Set(HeaderRequestID, id)
		c.Next()
	}
}

func requestIDOf(c *gin.Context) string {
	if id, ok := c.Get(contextRequestID); ok {
		if s, ok := id.(string); ok {
			return s
		}
	}
	return ""
}

// accessLog registra una línea estructurada por petición.
//
// Deliberadamente no toca el cuerpo: en /signup el cuerpo es el criptograma y,
// más allá de estar cifrado, loguearlo dejaría material criptográfico en el
// agregador de logs sin ninguna utilidad para diagnosticar.
//
// Se registran dos campos distintos para la ubicación de la petición, porque
// responden preguntas distintas:
//
//   - `path`: la URL que pidió el cliente, siempre presente.
//   - `route`: el patrón de ruta que matcheó Gin, vacío cuando ninguno lo hizo.
//
// Registrar solo `route` —como se hacía antes— dejaba en blanco justo las
// peticiones que más hace falta diagnosticar: un 404 o un 405 no matchean
// ninguna ruta, así que el log no decía qué se había pedido. Ese vacío es lo
// que obliga a descubrir por prueba y error si el problema es un typo en el
// path, un puerto equivocado o un método incorrecto.
func accessLog(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		attrs := []slog.Attr{
			slog.String("request_id", requestIDOf(c)),
			slog.String("method", c.Request.Method),
			slog.String("path", requestPath(c)),
			slog.String("route", c.FullPath()),
			slog.Int("status", c.Writer.Status()),
			slog.Duration("latency", time.Since(start)),
		}

		level := slog.LevelInfo
		if c.Writer.Status() >= http.StatusInternalServerError {
			level = slog.LevelError
		}

		logger.LogAttrs(c.Request.Context(), level, "petición http", attrs...)
	}
}

// maxLoggedPathLength acota lo que se registra del path pedido. Las rutas
// reales de este servicio no llegan a 40 caracteres, así que este tope solo
// alcanza a un cliente que pide una URL desmesurada —un escáner, típicamente—
// y evita que eso infle el agregador de logs. El mismo criterio que aplica
// requestID sobre el valor de X-Request-ID.
const maxLoggedPathLength = 256

// requestPath devuelve la ruta pedida por el cliente, acotada.
//
// Se toma URL.Path y no RequestURI: Path excluye la query string, que este
// servicio no usa en ningún endpoint y que no tiene por qué terminar en un
// log si alguna vez se agrega un endpoint que sí la reciba.
func requestPath(c *gin.Context) string {
	path := c.Request.URL.Path
	if len(path) > maxLoggedPathLength {
		return path[:maxLoggedPathLength] + "…"
	}
	return path
}

// recovery convierte un panic en un 500 genérico y deja el stack en el log.
//
// El stack nunca viaja en la respuesta: expone rutas de archivos y estructura
// interna del binario.
func recovery(logger *slog.Logger) gin.HandlerFunc {
	return gin.CustomRecoveryWithWriter(nil, func(c *gin.Context, recovered any) {
		logger.ErrorContext(c.Request.Context(), "panic atendiendo la petición",
			slog.String("request_id", requestIDOf(c)),
			slog.String("path", requestPath(c)),
			slog.String("route", c.FullPath()),
			slog.Any("panic", recovered),
		)

		c.AbortWithStatusJSON(http.StatusInternalServerError, errorResponse{
			Code:      codeInternal,
			Error:     "error interno",
			RequestID: requestIDOf(c),
		})
	})
}

// limitBody acota el cuerpo que se está dispuesto a leer.
//
// El criptograma de un alta son unos cientos de bytes; sin este tope, un cliente
// podría hacer que el servicio consuma memoria arbitraria antes siquiera de
// intentar descifrar.
func limitBody(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}

// noStore evita que la respuesta de un endpoint de autenticación quede cacheada
// en un proxy intermedio.
func noStore() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Cache-Control", "no-store")
		c.Writer.Header().Set("Pragma", "no-cache")
		c.Next()
	}
}
