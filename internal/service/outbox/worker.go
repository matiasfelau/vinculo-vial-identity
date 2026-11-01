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
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// eventTypeSessionsRevoked es el tipo del evento de la Defensa Activa de
// US-03. Coincide con el tipo con que lo arma session.RefreshService. El otro
// tipo que pasa por el outbox es domain.EventTypeUserStatusChanged (US-08).
const eventTypeSessionsRevoked = "user.sessions.revoked"

// connectionKeeper lo implementa el publisher real: restablece la conexión con
// el broker si está caída. El inerte no lo implementa y no lo necesita.
type connectionKeeper interface {
	EnsureConnected(ctx context.Context) error
}

// Worker publica en background los eventos pendientes del outbox.
type Worker struct {
	repo      domain.OutboxRepository
	publisher domain.EventPublisher
	batchSize int
	logger    *slog.Logger
	now       func() time.Time

	// Estado observable por /health/deps (ver Status). Lo escribe Run; lo lee
	// cualquiera.
	mu             sync.Mutex
	running        bool
	interval       time.Duration
	startedAt      time.Time
	lastCycleStart time.Time
	lastCycleErr   error
}

// minStaleAfter es el piso del plazo sin ciclos tras el cual Status da al
// worker por colgado. Un ciclo con el broker caído puede durar legítimamente
// decenas de segundos —hasta batchSize publicaciones fallidas de a
// RABBITMQ_PUBLISH_TIMEOUT—, así que el plazo no puede ser solo un múltiplo
// del intervalo.
const minStaleAfter = time.Minute

// NewWorker construye un Worker. batchSize acota cuántos eventos se intentan
// publicar por ciclo; logger puede ser nil (usa slog.Default()).
func NewWorker(repo domain.OutboxRepository, publisher domain.EventPublisher, batchSize int, logger *slog.Logger) *Worker {
	if logger == nil {
		logger = slog.Default()
	}
	return &Worker{repo: repo, publisher: publisher, batchSize: batchSize, logger: logger, now: time.Now}
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

	// Sin nada que publicar, el worker aprovecha el ciclo para mantener viva la
	// conexión con el broker: la reconexión de publicar es perezosa, y sin esto
	// el estado del broker en /health/deps no se recuperaría tras una caída
	// hasta el próximo evento.
	if len(events) == 0 {
		w.keepConnected(ctx)
		return 0, nil
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

// keepConnected restablece la conexión del publisher si hace falta. Un fallo
// no es un error del ciclo: lo informa /health/deps y se reintenta en el
// próximo; se registra en DEBUG para no inundar el log cada intervalo.
func (w *Worker) keepConnected(ctx context.Context) {
	keeper, ok := w.publisher.(connectionKeeper)
	if !ok {
		return
	}
	if err := keeper.EnsureConnected(ctx); err != nil {
		w.logger.DebugContext(ctx, "outbox worker: no se pudo restablecer la conexión con el broker",
			slog.String("error", err.Error()),
		)
	}
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

	case domain.EventTypeUserStatusChanged:
		var payload struct {
			UserID        string `json:"user_id"`
			AccountStatus string `json:"account_status"`
			Reason        string `json:"reason"`
		}
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			return fmt.Errorf("outbox worker: payload de %s ilegible: %w", event.Type, err)
		}
		userID, err := uuid.Parse(payload.UserID)
		if err != nil {
			return fmt.Errorf("outbox worker: user_id de %s inválido: %w", event.Type, err)
		}
		if payload.AccountStatus == "" || payload.Reason == "" {
			return fmt.Errorf("outbox worker: %s sin account_status o reason", event.Type)
		}
		evt := domain.NewUserStatusChanged(event.ID, userID, domain.AccountStatus(payload.AccountStatus), domain.UserStatusReason(payload.Reason))
		return w.publisher.PublishUserStatusChanged(ctx, evt)

	default:
		return fmt.Errorf("outbox worker: tipo de evento desconocido: %s", event.Type)
	}
}

// Run ejecuta ProcessBatch en un loop con el intervalo dado, hasta que ctx
// se cancele (apagado del servicio, ver cmd/api/main.go).
func (w *Worker) Run(ctx context.Context, interval time.Duration) {
	w.mu.Lock()
	w.running = true
	w.interval = interval
	w.startedAt = w.now()
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		w.running = false
		w.mu.Unlock()
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.mu.Lock()
			w.lastCycleStart = w.now()
			w.mu.Unlock()

			_, err := w.ProcessBatch(ctx)

			w.mu.Lock()
			w.lastCycleErr = err
			w.mu.Unlock()
			if err != nil {
				w.logger.ErrorContext(ctx, "outbox worker: error al procesar el lote",
					slog.String("error", err.Error()),
				)
			}
		}
	}
}

// Status informa la salud del worker para /health/deps. Devuelve el estado y
// si es sano:
//
//   - "up": corriendo, con ciclos al día y el último pudo leer el outbox.
//   - "down": el último ciclo no pudo leer el outbox (la base falla), así que
//     nada se está drenando.
//   - "stalled": corriendo, pero sin iniciar un ciclo hace más de
//     max(5 × intervalo, 1 minuto): el loop está colgado.
//   - "stopped": Run no arrancó o ya terminó.
//
// Que el broker esté caído no pone al worker en "down": un publish fallido deja
// el evento pendiente y el worker sigue sano reintentando; esa dependencia la
// informa el chequeo del broker.
func (w *Worker) Status() (string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.running {
		return "stopped", false
	}
	if w.lastCycleErr != nil {
		return "down", false
	}

	referencia := w.startedAt
	if !w.lastCycleStart.IsZero() {
		referencia = w.lastCycleStart
	}
	vencido := 5 * w.interval
	if vencido < minStaleAfter {
		vencido = minStaleAfter
	}
	if w.now().Sub(referencia) > vencido {
		return "stalled", false
	}
	return "up", true
}
