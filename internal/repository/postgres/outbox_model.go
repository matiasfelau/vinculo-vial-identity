package postgres

import (
	"time"

	"github.com/google/uuid"
)

// Estados posibles de outboxEventModel.Status.
const (
	outboxStatusPending = "pending"
	outboxStatusSent    = "sent"
)

// outboxEventModel es la representación GORM de la tabla outbox_events: el
// patrón Transactional Outbox de la Defensa Activa de US-03 (ver
// domain.OutboxEvent). No tiene contraparte de dominio 1:1 porque es un
// detalle de implementación interno del outbox, nunca se expone fuera de
// este paquete más que a través de domain.OutboxEvent.
type outboxEventModel struct {
	ID        uuid.UUID  `gorm:"column:id;type:uuid;primaryKey"`
	Type      string     `gorm:"column:type;type:varchar(64);not null"`
	Payload   []byte     `gorm:"column:payload;type:jsonb;not null"`
	Status    string     `gorm:"column:status;type:varchar(16);not null;default:pending;index:idx_outbox_events_status_created_at,priority:1"`
	Attempts  int        `gorm:"column:attempts;not null;default:0"`
	LastError *string    `gorm:"column:last_error;type:text"`
	CreatedAt time.Time  `gorm:"column:created_at;type:timestamptz;not null;index:idx_outbox_events_status_created_at,priority:2"`
	SentAt    *time.Time `gorm:"column:sent_at;type:timestamptz"`
}

// TableName fija el nombre de la tabla en lugar de depender de la
// pluralización automática de GORM.
func (outboxEventModel) TableName() string { return "outbox_events" }
