package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// DepCheck es el chequeo de una dependencia de /health/deps. Check devuelve el
// estado observable —"up", "down", "closed", "open", "disabled"…— y si ese
// estado es sano. El estado va al cuerpo de la respuesta, así que nunca debe
// llevar detalle de un error ni datos de la dependencia: solo el nombre del
// estado.
type DepCheck struct {
	Name  string
	Check func() (state string, ok bool)
}

// DepsHealthHandler atiende GET /health/deps: el estado de las dependencias
// que NO son la base propia —el broker, el worker del outbox y el circuit
// breaker hacia RENAPER—. Responde 200 con "status":"ok" si todas están sanas
// y 503 con "status":"degraded" si alguna no lo está.
//
// Es deliberadamente una ruta aparte de /ready (contrato de resiliencia):
// /ready es el path del healthcheck activo de Kong y solo chequea la base
// propia, porque sacar a Identity del balanceo por un fallo del broker o de
// RENAPER dejaría sin servicio a endpoints que no los usan. Este handler es
// para diagnóstico y monitoreo; su 503 no afecta al balanceo.
type DepsHealthHandler struct {
	checks []DepCheck
}

// NewDepsHealthHandler construye el handler con los chequeos dados.
func NewDepsHealthHandler(checks ...DepCheck) *DepsHealthHandler {
	return &DepsHealthHandler{checks: checks}
}

// Handle evalúa todos los chequeos —nunca corta en el primero que falla, para
// que la respuesta muestre el panorama completo— y responde.
func (h *DepsHealthHandler) Handle(c *gin.Context) {
	checks := make(map[string]string, len(h.checks))
	degraded := false

	for _, dep := range h.checks {
		state, ok := dep.Check()
		checks[dep.Name] = state
		if !ok {
			degraded = true
		}
	}

	// Un estado que cambia con cada consulta no debe quedar en ningún caché.
	c.Header("Cache-Control", "no-store")

	if degraded {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "degraded", "checks": checks})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "checks": checks})
}
