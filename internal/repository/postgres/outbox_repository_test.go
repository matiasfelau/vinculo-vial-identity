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
	evt, _ := domain.NewOutboxEvent("user.sessions.revoked", domain.NewSessionsRevoked(uuid.New(), uuid.New(), domain.SessionsRevokedReasonReuseDetected))
	evt.CreatedAt = time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)

	m := toOutboxModel(&evt)

	if m.ID != evt.ID {
		t.Errorf("id = %v, se esperaba %v", m.ID, evt.ID)
	}
	if m.Type != evt.Type {
		t.Errorf("type = %q, se esperaba %q", m.Type, evt.Type)
	}
	if string(m.Payload) != string(evt.Payload) {
		t.Errorf("payload = %s, se esperaba %s", string(m.Payload), string(evt.Payload))
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
	original, _ := domain.NewOutboxEvent("user.sessions.revoked", domain.NewSessionsRevoked(uuid.New(), uuid.New(), domain.SessionsRevokedReasonReuseDetected))
	original.CreatedAt = time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)

	got := toOutboxModel(&original).toDomain()

	if got.ID != original.ID || got.Type != original.Type || string(got.Payload) != string(original.Payload) || !got.CreatedAt.Equal(original.CreatedAt) {
		t.Errorf("ida y vuelta = %+v, se esperaba %+v", got, original)
	}
}
