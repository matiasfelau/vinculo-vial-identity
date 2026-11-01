package renaper

import (
	"context"
	"time"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// withTimeout envuelve un domain.RenaperService para acotar cada consulta a
// un plazo propio, en vez de depender enteramente del contexto de la petición
// HTTP entrante: ese contexto no tiene por qué dejarle a esta dependencia un
// presupuesto razonable dentro del total de /auth/signup, y sin un timeout
// propio una RENAPER lenta o caída queda limitada únicamente por los defaults
// —a menudo infinitos— del transporte subyacente.
type withTimeout struct {
	next    domain.RenaperService
	timeout time.Duration
}

// WithTimeout decora next para que cada ValidateIdentity corra bajo un
// context.WithTimeout propio. Si el contexto recibido ya trae un deadline más
// cercano, ese deadline sigue rigiendo: WithTimeout solo acota, nunca extiende.
//
// Aplica tanto al Mock de hoy —que ya respeta la cancelación del contexto, ver
// mock.go— como al cliente real que lo reemplace detrás de la misma interfaz.
func WithTimeout(next domain.RenaperService, timeout time.Duration) domain.RenaperService {
	return &withTimeout{next: next, timeout: timeout}
}

func (w *withTimeout) ValidateIdentity(ctx context.Context, dni, tramite, sexo, selfie []byte) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()

	return w.next.ValidateIdentity(ctx, dni, tramite, sexo, selfie)
}
