package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// toOutboxModel traduce un domain.OutboxEvent a su proyección de
// persistencia, siempre en estado pendiente: lo usa
// SessionRepository.RevokeAllByUserID para insertarlo en la misma
// transacción que la revocación.
func toOutboxModel(e *domain.OutboxEvent) *outboxEventModel {
	return &outboxEventModel{
		ID:        e.ID,
		Type:      e.Type,
		Payload:   e.Payload,
		Status:    outboxStatusPending,
		CreatedAt: e.CreatedAt,
	}
}

func (m *outboxEventModel) toDomain() domain.OutboxEvent {
	return domain.OutboxEvent{
		ID:        m.ID,
		Type:      m.Type,
		Payload:   m.Payload,
		CreatedAt: m.CreatedAt,
	}
}

// OutboxRepository implementa domain.OutboxRepository sobre GORM/PostgreSQL.
// Solo lee y actualiza filas: quien las inserta es SessionRepository, dentro
// de su propia transacción (ver RevokeAllByUserID).
type OutboxRepository struct {
	db *gorm.DB
}

// migrateLegacyOutbox es la migración explícita de outbox_events desde el
// esquema tipado de #41 (columnas user_id y reason) al genérico actual (type +
// payload jsonb). AutoMigrate no la cubre: nunca borra columnas, y las dos
// columnas viejas son NOT NULL, así que en cualquier base que haya corrido #41
// todo INSERT nuevo fallaría por falta de valor en user_id/reason.
//
// No se limita a borrarlas: antes convierte cada fila existente —pendiente o
// enviada— al formato nuevo, porque borrar user_id/reason a secas dejaría a los
// eventos pendientes sin contenido que publicar, y AutoMigrate tampoco podría
// agregar type/payload NOT NULL sobre una tabla con filas. Es idempotente: sin
// ninguna de las dos columnas viejas no toca la tabla (ni la bloquea).
const migrateLegacyOutbox = `
DO $$
BEGIN
	IF to_regclass('outbox_events') IS NULL THEN
		RETURN;
	END IF;

	IF NOT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_schema = current_schema()
			AND table_name = 'outbox_events'
			AND column_name IN ('user_id', 'reason')
	) THEN
		RETURN;
	END IF;

	IF EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_schema = current_schema()
			AND table_name = 'outbox_events' AND column_name = 'user_id'
	) AND EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_schema = current_schema()
			AND table_name = 'outbox_events' AND column_name = 'reason'
	) THEN
		ALTER TABLE outbox_events
			ADD COLUMN IF NOT EXISTS type varchar(64),
			ADD COLUMN IF NOT EXISTS payload jsonb;

		UPDATE outbox_events
		SET type = 'user.sessions.revoked',
			payload = jsonb_build_object('user_id', user_id::text, 'reason', reason)
		WHERE type IS NULL OR payload IS NULL;

		ALTER TABLE outbox_events
			ALTER COLUMN type SET NOT NULL,
			ALTER COLUMN payload SET NOT NULL;
	END IF;

	ALTER TABLE outbox_events
		DROP COLUMN IF EXISTS user_id,
		DROP COLUMN IF EXISTS reason;
END $$;
`

// NewOutboxRepository construye el repositorio y ejecuta AutoMigrate.
//
// outbox_events no declara una clave foránea hacia users (a diferencia de
// sessions): es una tabla de infraestructura interna, no un dato de negocio
// que deba desaparecer en cascada, así que puede migrarse en cualquier orden
// respecto de NewUserRepository/NewSessionRepository.
func NewOutboxRepository(ctx context.Context, db *gorm.DB) (*OutboxRepository, error) {
	if db == nil {
		return nil, errors.New("postgres: se requiere una conexión GORM")
	}

	if err := db.WithContext(ctx).Exec(migrateLegacyOutbox).Error; err != nil {
		return nil, fmt.Errorf("postgres: no se pudo migrar outbox_events desde el esquema tipado: %w", err)
	}

	if err := db.WithContext(ctx).AutoMigrate(&outboxEventModel{}); err != nil {
		return nil, fmt.Errorf("postgres: falló la migración del esquema de outbox_events: %w", err)
	}

	return &OutboxRepository{db: db}, nil
}

// FetchPending devuelve hasta limit eventos todavía no enviados, ordenados
// por antigüedad (los más viejos primero), para no dejar eventos varados
// detrás de un alud de eventos nuevos.
func (r *OutboxRepository) FetchPending(ctx context.Context, limit int) ([]domain.OutboxEvent, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	var rows []outboxEventModel
	if err := r.db.WithContext(ctx).
		Where("status = ?", outboxStatusPending).
		Order("created_at ASC").
		Limit(limit).
		Find(&rows).Error; err != nil {
		return nil, classifyDBError(err)
	}

	events := make([]domain.OutboxEvent, len(rows))
	for i, row := range rows {
		events[i] = row.toDomain()
	}
	return events, nil
}

// MarkSent registra que el evento se publicó y el broker lo confirmó
// (publisher confirms).
func (r *OutboxRepository) MarkSent(ctx context.Context, id uuid.UUID) error {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	now := time.Now().UTC()
	err := r.db.WithContext(ctx).Model(&outboxEventModel{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"status":  outboxStatusSent,
			"sent_at": now,
		}).Error
	return classifyDBError(err)
}

// MarkFailed registra un intento fallido sin cambiar el estado pendiente: el
// worker lo va a reintentar en el próximo ciclo, reutilizando el mismo id
// como EventID (ver domain.SessionsRevoked).
func (r *OutboxRepository) MarkFailed(ctx context.Context, id uuid.UUID, lastErr string) error {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	err := r.db.WithContext(ctx).Model(&outboxEventModel{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"attempts":   gorm.Expr("attempts + 1"),
			"last_error": lastErr,
		}).Error
	return classifyDBError(err)
}
