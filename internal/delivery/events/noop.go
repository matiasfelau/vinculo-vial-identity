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

// PublishSessionsRevoked registra el evento que se habría publicado.
func (p *NoopPublisher) PublishSessionsRevoked(ctx context.Context, evt domain.SessionsRevoked) error {
	p.logger.WarnContext(ctx, "publisher inerte: el evento no se publicó",
		slog.String("event_type", EventTypeSessionsRevoked),
		slog.String("user_id", evt.UserID.String()),
	)
	return nil
}

// PublishUserStatusChanged registra el evento que se habría publicado.
func (p *NoopPublisher) PublishUserStatusChanged(ctx context.Context, evt domain.UserStatusChanged) error {
	p.logger.WarnContext(ctx, "publisher inerte: el evento no se publicó",
		slog.String("event_type", EventTypeUserStatusChanged),
		slog.String("user_id", evt.UserID.String()),
	)
	return nil
}

// PublishUserDeleted registra el evento que se habría publicado.
func (p *NoopPublisher) PublishUserDeleted(ctx context.Context, evt domain.UserDeleted) error {
	p.logger.WarnContext(ctx, "publisher inerte: el evento no se publicó",
		slog.String("event_type", EventTypeUserDeleted),
		slog.String("user_id", evt.UserID.String()),
	)
	return nil
}

// Status informa que el broker está deshabilitado: es el modo de desarrollo,
// que la configuración rechaza con APP_ENV=production. Deshabilitado no es una
// falla, así que /health/deps no lo cuenta como degradación.
func (p *NoopPublisher) Status() (string, bool) { return "disabled", true }

// Close no tiene nada que liberar.
func (p *NoopPublisher) Close() error { return nil }
