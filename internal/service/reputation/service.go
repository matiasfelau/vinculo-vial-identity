// Package reputation implementa los casos de uso de US-08 sobre la reputación
// de los usuarios. Depende únicamente de los puertos de domain, igual que el
// resto de internal/service, para poder ejercitarse entero con dobles, sin
// Postgres ni RabbitMQ.
package reputation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// EventTypeAlertRejected es el tipo del evento que Alert publica al rechazar
// una alerta tras el veredicto RED de IA.
const EventTypeAlertRejected = "alert.rejected"

// RejectionDeps son las dependencias de RejectionService.
type RejectionDeps struct {
	Repo domain.ReputationRepository
	// Consumer identifica a quien procesa el evento en la clave de
	// deduplicación: la cola de trabajo.
	Consumer string
	// FraudPenalty son los puntos que se restan a la reputación por cada
	// alerta rechazada por fraude (FRAUD_PENALTY).
	FraudPenalty int
	Logger       *slog.Logger
	// Now es el reloj; si es nil usa time.Now.
	Now func() time.Time
}

// RejectionService es el caso de uso de alert.rejected: penalizar al emisor
// de una alerta rechazada por fraude.
type RejectionService struct {
	deps RejectionDeps
}

// NewRejectionService valida las dependencias y construye el servicio.
func NewRejectionService(d RejectionDeps) (*RejectionService, error) {
	switch {
	case d.Repo == nil:
		return nil, errors.New("reputation: falta el repositorio de reputación")
	case d.Consumer == "":
		return nil, errors.New("reputation: falta el nombre del consumidor")
	case d.FraudPenalty < 0:
		return nil, errors.New("reputation: la penalización por fraude no puede ser negativa")
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &RejectionService{deps: d}, nil
}

// Apply procesa un rechazo. Resta FraudPenalty solo si algún código de motivo
// es de fraude (domain.HasFraudReasonCode); un rechazo sin fraude, como
// EVIDENCE_UNREADABLE, igual se registra como procesado y no cambia la
// reputación.
//
// Es idempotente: la entrega es at-least-once, y el repositorio descarta el
// evento si su eventId ya se procesó para este consumidor. Un usuario
// inexistente no es un error: se loguea y se da el evento por procesado.
// Cualquier error de infraestructura se devuelve para que el consumidor
// reintente.
func (s *RejectionService) Apply(ctx context.Context, rejection domain.AlertRejection) error {
	penalty := 0
	if domain.HasFraudReasonCode(rejection.ReasonCodes) {
		penalty = s.deps.FraudPenalty
	}

	result, err := s.deps.Repo.ApplyRejection(ctx, domain.ProcessedEvent{
		EventID:     rejection.EventID,
		Consumer:    s.deps.Consumer,
		EventType:   EventTypeAlertRejected,
		ProcessedAt: s.deps.Now().UTC(),
	}, rejection.UserID, penalty)
	if err != nil {
		return fmt.Errorf("reputation: no se pudo aplicar el rechazo del evento %s: %w", rejection.EventID, err)
	}

	switch result {
	case domain.RejectionDuplicate:
		s.deps.Logger.InfoContext(ctx, "rechazo ya procesado: se descarta el duplicado",
			slog.String("event_id", rejection.EventID.String()))
	case domain.RejectionUserNotFound:
		s.deps.Logger.WarnContext(ctx, "rechazo de un usuario inexistente: no hay a quién penalizar",
			slog.String("event_id", rejection.EventID.String()),
			slog.String("user_id", rejection.UserID.String()))
	case domain.RejectionApplied:
		s.deps.Logger.InfoContext(ctx, "rechazo aplicado",
			slog.String("event_id", rejection.EventID.String()),
			slog.String("user_id", rejection.UserID.String()),
			slog.Int("penalty", penalty))
	}
	return nil
}
