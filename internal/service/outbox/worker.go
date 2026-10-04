// Package outbox implementa el worker en background que publica los eventos
// persistidos por el patrón Transactional Outbox de la Defensa Activa de
// US-03 (US-06), desacoplando la publicación del camino síncrono de
// /refresh. Depende únicamente de los puertos de domain, igual que el resto
// de los paquetes de internal/service, para poder ejercitarse entero con
// dobles, sin Postgres ni RabbitMQ.
package outbox

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// eventTypeSessionsRevoked es el único tipo de evento que hoy pasa por el
// outbox: la Defensa Activa de US-03. Coincide con el tipo con que lo arma
// session.RefreshService.
const eventTypeSessionsRevoked = "user.sessions.revoked"

// Worker publica en background los eventos pendientes del outbox.
type Worker struct {
	repo      domain.OutboxRepository
	publisher domain.EventPublisher
	batchSize int
	logger    *slog.Logger
}

// NewWorker construye un Worker. batchSize acota cuántos eventos se intentan
// publicar por ciclo; logger puede ser nil (usa slog.Default()).
func NewWorker(repo domain.OutboxRepository, publisher domain.EventPublisher, batchSize int, logger *slog.Logger) *Worker {
	if logger == nil {
		logger = slog.Default()
	}
	return &Worker{repo: repo, publisher: publisher, batchSize: batchSize, logger: logger}
}

// ProcessBatch intenta publicar hasta batchSize eventos pendientes y
// devuelve cuántos se publicaron con éxito. Se expone aparte de Run para
// poder testearlo sin depender de un ticker real.
//
// Un evento se marca enviado solo después de que el broker lo confirme
// (publisher confirms, ver internal/delivery/events). Si falla el publish, o
// si el publish se confirma pero el propio MarkSent falla, el evento queda
// pendiente y el próximo ciclo lo reintenta —a costa de una posible
// publicación duplicada en ese segundo caso, mitigada porque el evento
// reutiliza el mismo EventID entre reintentos (ver domain.SessionsRevoked)
// para que un consumidor que deduplique por event_id no lo cuente dos veces.
func (w *Worker) ProcessBatch(ctx context.Context) (int, error) {
	events, err := w.repo.FetchPending(ctx, w.batchSize)
	if err != nil {
		return 0, fmt.Errorf("outbox worker: no se pudo obtener los eventos pendientes: %w", err)
	}

	sent := 0
	for _, event := range events {
		pubErr := w.publish(ctx, event)

		if pubErr != nil {
			w.logger.ErrorContext(ctx, "outbox worker: no se pudo publicar, se reintentará",
				slog.String("event_id", event.ID.String()),
				slog.String("error", pubErr.Error()),
			)
			if markErr := w.repo.MarkFailed(ctx, event.ID, pubErr.Error()); markErr != nil {
				w.logger.ErrorContext(ctx, "outbox worker: no se pudo registrar el intento fallido",
					slog.String("event_id", event.ID.String()),
					slog.String("error", markErr.Error()),
				)
			}
			continue
		}

		if err := w.repo.MarkSent(ctx, event.ID); err != nil {
			w.logger.ErrorContext(ctx, "outbox worker: publicado pero no se pudo marcar como enviado; se reintentará",
				slog.String("event_id", event.ID.String()),
				slog.String("error", err.Error()),
			)
			continue
		}
		sent++
	}

	return sent, nil
}

// publish traduce una fila de outbox al evento de dominio que corresponde a
// su tipo y lo publica. Un tipo desconocido o un payload que no se puede
// interpretar son errores como cualquier otro: el evento queda pendiente con
// el motivo en last_error, en lugar de publicarse con datos inventados.
func (w *Worker) publish(ctx context.Context, event domain.OutboxEvent) error {
	switch event.Type {
	case eventTypeSessionsRevoked:
		var payload struct {
			UserID string `json:"user_id"`
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			return fmt.Errorf("outbox worker: payload de %s ilegible: %w", event.Type, err)
		}
		userID, err := uuid.Parse(payload.UserID)
		if err != nil {
			return fmt.Errorf("outbox worker: user_id de %s inválido: %w", event.Type, err)
		}
		evt := domain.NewSessionsRevoked(event.ID, userID, domain.SessionsRevokedReason(payload.Reason))
		return w.publisher.PublishSessionsRevoked(ctx, evt)

	default:
		return fmt.Errorf("outbox worker: tipo de evento desconocido: %s", event.Type)
	}
}

// Run ejecuta ProcessBatch en un loop con el intervalo dado, hasta que ctx
// se cancele (apagado del servicio, ver cmd/api/main.go).
func (w *Worker) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := w.ProcessBatch(ctx); err != nil {
				w.logger.ErrorContext(ctx, "outbox worker: error al procesar el lote",
					slog.String("error", err.Error()),
				)
			}
		}
	}
}
