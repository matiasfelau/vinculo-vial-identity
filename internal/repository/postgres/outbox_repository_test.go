// Tests internos al paquete: ejercitan el mapeo entidad↔modelo del outbox,
// igual que user_repository_test.go y session_repository_test.go.
//
// Las sentencias contra PostgreSQL quedan fuera de los tests unitarios; se
// cubren con el docker-compose local.
package postgres

import (
	"time"

	"testing"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

func TestNewOutboxRepositoryRechazaConexionNula(t *testing.T) {
	if _, err := NewOutboxRepository(t.Context(), nil); err == nil {
		t.Error("se esperaba un error al construir sin conexión")
	}
}

func TestOutboxTableName(t *testing.T) {
	if got := (outboxEventModel{}).TableName(); got != "outbox_events" {
		t.Errorf("tabla = %q, se esperaba %q", got, "outbox_events")
	}
}

func TestToOutboxModelSiempreQuedaPendiente(t *testing.T) {
	evt := &domain.OutboxEvent{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		Reason:    domain.SessionsRevokedReasonReuseDetected,
		CreatedAt: time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC),
	}

	m := toOutboxModel(evt)

	if m.ID != evt.ID {
		t.Errorf("id = %v, se esperaba %v", m.ID, evt.ID)
	}
	if m.UserID != evt.UserID {
		t.Errorf("user_id = %v, se esperaba %v", m.UserID, evt.UserID)
	}
	if m.Reason != string(evt.Reason) {
		t.Errorf("reason = %q, se esperaba %q", m.Reason, evt.Reason)
	}
	if m.Status != outboxStatusPending {
		t.Errorf("status = %q, se esperaba %q", m.Status, outboxStatusPending)
	}
	if !m.CreatedAt.Equal(evt.CreatedAt) {
		t.Errorf("created_at = %v, se esperaba %v", m.CreatedAt, evt.CreatedAt)
	}
}

// El mapeo entidad↔modelo tiene que ser simétrico: lo que el worker lee de
// FetchPending debe reconstruir exactamente el evento que se persistió.
func TestMapeoDeOutboxEsSimetrico(t *testing.T) {
	original := domain.OutboxEvent{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		Reason:    domain.SessionsRevokedReasonReuseDetected,
		CreatedAt: time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC),
	}

	got := toOutboxModel(&original).toDomain()

	if got != original {
		t.Errorf("ida y vuelta = %+v, se esperaba %+v", got, original)
	}
}
