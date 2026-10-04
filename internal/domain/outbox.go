package domain

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// OutboxEvent es un evento de dominio pendiente de publicar.
type OutboxEvent struct {
	ID        uuid.UUID
	Type      string
	Payload   json.RawMessage
	CreatedAt time.Time
}

// NewOutboxEvent encapsula un payload en un OutboxEvent genérico.
func NewOutboxEvent(eventType string, payload any) (OutboxEvent, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return OutboxEvent{}, err
	}
	return OutboxEvent{
		ID:      uuid.New(),
		Type:    eventType,
		Payload: b,
	}, nil
}
