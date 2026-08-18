package events

import (
	"context"
	"log/slog"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// NoopPublisher descarta los eventos y deja constancia en el log.
//
// El broker es un recurso global de la plataforma y no forma parte del
// docker-compose de este servicio. Sin esta implementación, levantar el entorno
// local exigiría un RabbitMQ corriendo; con ella, el alta funciona de punta a
// punta y cada evento descartado queda registrado, que es exactamente lo que se
// quiere en desarrollo y nunca en producción.
type NoopPublisher struct {
	logger *slog.Logger
}

// NewNoopPublisher construye el publisher inerte.
func NewNoopPublisher(logger *slog.Logger) *NoopPublisher {
	if logger == nil {
		logger = slog.Default()
	}
	return &NoopPublisher{logger: logger}
}

// PublishUserCreated registra el evento que se habría publicado.
func (p *NoopPublisher) PublishUserCreated(ctx context.Context, evt domain.UserCreated) error {
	p.logger.WarnContext(ctx, "publisher inerte: el evento no se publicó",
		slog.String("event_type", EventTypeUserCreated),
		slog.String("user_id", evt.UserID.String()),
	)
	return nil
}

// Close no tiene nada que liberar.
func (p *NoopPublisher) Close() error { return nil }
