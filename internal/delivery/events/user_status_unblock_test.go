package events

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// El sobre del desbloqueo manual (US-17) lleva ACTIVE y MANUAL_UNBLOCK en el
// payload, con el actor nulo como el resto de los user.status.changed: Alert lee
// account_status y no mira el motivo ni el actor.
func TestUserStatusChangedEnvelopeDelDesbloqueoManual(t *testing.T) {
	usuario := uuid.MustParse("6f2a4c1e-9d3b-4f5a-8c7d-1e2f3a4b5c6d")
	evt := domain.NewUserStatusChanged(uuid.New(), usuario, domain.AccountStatusActive, domain.UserStatusReasonManualUnblock)

	env := newUserStatusChangedEnvelope(evt, DefaultProducer, emitido)

	if env.EventType != "user.status.changed" || env.Actor != nil {
		t.Errorf("eventType = %q, actor = %v; se esperaba user.status.changed y actor nulo", env.EventType, env.Actor)
	}
	body, err := json.Marshal(env.Payload)
	if err != nil {
		t.Fatalf("no se pudo serializar: %v", err)
	}
	want := `{"user_id":"6f2a4c1e-9d3b-4f5a-8c7d-1e2f3a4b5c6d","account_status":"ACTIVE","reason":"MANUAL_UNBLOCK"}`
	if string(body) != want {
		t.Errorf("payload = %s, se esperaba %s", body, want)
	}
}
