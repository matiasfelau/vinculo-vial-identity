// Package renaper implementa el puerto domain.RenaperService: la verificación
// de identidad contra RENAPER (Registro Nacional de las Personas) que exige el
// alta.
//
// Hoy solo existe el Mock. No hay todavía credenciales ni contrato acordado con
// la API real de RENAPER; cuando se integre, el cliente real va a vivir en este
// mismo paquete, detrás de la misma interfaz, sin que el resto del servicio se
// entere del cambio.
package renaper

import (
	"context"
	"time"
)

// DefaultMockLatency es la demora que simula el Mock cuando no se configura una
// propia. RENAPER es un servicio externo real; un mock instantáneo escondería en
// desarrollo problemas de timeout y cancelación que sí van a aparecer en
// producción.
const DefaultMockLatency = 500 * time.Millisecond

// Mock implementa domain.RenaperService sin llamar a ningún servicio externo:
// espera Latency (o DefaultMockLatency si no se configura) y siempre confirma
// la identidad.
//
// Existe para desarrollo y para levantar el servicio de punta a punta sin
// credenciales de RENAPER. A diferencia de NoopPublisher —que es inocuo en
// producción porque perder un evento es recuperable—, este Mock aprobaría
// cualquier identidad sin verificar nada: no debe usarse fuera de desarrollo.
// Quien lo cablea (hoy, cmd/api/main.go) es responsable de dejarlo bien visible
// en el log de arranque.
type Mock struct {
	// Latency es la demora simulada. Si es cero se usa DefaultMockLatency.
	Latency time.Duration
}

// ValidateIdentity espera Latency y devuelve (true, nil) sin inspeccionar los
// argumentos: no hay todavía nada real contra qué validarlos.
//
// Respeta la cancelación del contexto en vez de bloquear un shutdown ordenado o
// el timeout de una petición hasta que se cumpla la latencia simulada, igual que
// haría un cliente HTTP real contra RENAPER.
func (m *Mock) ValidateIdentity(ctx context.Context, dni, tramite, sexo, selfie []byte) (bool, error) {
	latency := m.Latency
	if latency <= 0 {
		latency = DefaultMockLatency
	}

	timer := time.NewTimer(latency)
	defer timer.Stop()

	select {
	case <-timer.C:
		return true, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}
