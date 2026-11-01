package postgres

import (
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// processedEventModel es la representación GORM de processed_events: la marca
// de deduplicación de los consumidores (at-least-once). La clave primaria
// compuesta (event_id, consumer) es la restricción de unicidad que hace
// idempotente al consumidor: el mismo evento entregado dos veces a la misma
// cola choca contra ella.
type processedEventModel struct {
	EventID     uuid.UUID `gorm:"column:event_id;type:uuid;primaryKey"`
	Consumer    string    `gorm:"column:consumer;type:varchar(128);primaryKey"`
	EventType   string    `gorm:"column:event_type;type:varchar(64);not null"`
	ProcessedAt time.Time `gorm:"column:processed_at;type:timestamptz;not null"`
}

// TableName fija el nombre de la tabla en lugar de depender de la
// pluralización automática de GORM.
func (processedEventModel) TableName() string { return "processed_events" }

func toProcessedEventModel(e domain.ProcessedEvent) *processedEventModel {
	return &processedEventModel{
		EventID:     e.EventID,
		Consumer:    e.Consumer,
		EventType:   e.EventType,
		ProcessedAt: e.ProcessedAt.UTC(),
	}
}
