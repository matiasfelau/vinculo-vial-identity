package events

import (
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

func cambioDeEstado() domain.UserStatusChanged {
	return domain.NewUserStatusChanged(
		uuid.MustParse("a1b2c3d4-e5f6-4789-9abc-def012345678"),
		uuid.MustParse("6f2a4c1e-9d3b-4f5a-8c7d-1e2f3a4b5c6d"),
		domain.AccountStatusUnderReview,
		domain.UserStatusReasonReportsThreshold,
	)
}

// El sobre cumple el contrato: eventType y routing key user.status.changed,
// actor nulo (es un hecho del sistema) y payload en snake_case.
func TestUserStatusChangedEnvelopeCumpleElContrato(t *testing.T) {
	env := newUserStatusChangedEnvelope(cambioDeEstado(), DefaultProducer, emitido)

	if env.EventType != "user.status.changed" {
		t.Errorf("eventType = %q, se esperaba user.status.changed", env.EventType)
	}
	if env.Producer != DefaultProducer {
		t.Errorf("producer = %q, se esperaba %q", env.Producer, DefaultProducer)
	}
	if env.Actor != nil {
		t.Errorf("actor = %q, se esperaba nulo", *env.Actor)
	}
	if got, err := time.Parse(time.RFC3339Nano, env.Timestamp); err != nil || !got.Equal(emitido) {
		t.Errorf("timestamp = %q (err %v), se esperaba %v", env.Timestamp, err, emitido)
	}

	body, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("no se pudo serializar: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("JSON inválido: %v", err)
	}
	if actor, presente := decoded["actor"]; !presente || actor != nil {
		t.Errorf("actor = %v (presente=%v): debe serializarse como null explícito", actor, presente)
	}
	payload, _ := decoded["payload"].(map[string]any)
	want := map[string]any{
		"user_id":        "6f2a4c1e-9d3b-4f5a-8c7d-1e2f3a4b5c6d",
		"account_status": "UNDER_REVIEW",
		"reason":         "REPORTS_THRESHOLD",
	}
	if len(payload) != len(want) {
		t.Errorf("payload = %v, se esperaban solo %v", payload, want)
	}
	for k, v := range want {
		if payload[k] != v {
			t.Errorf("payload[%s] = %v, se esperaba %v", k, payload[k], v)
		}
	}
}

// El eventId es el de la fila del outbox y no cambia entre reintentos.
func TestUserStatusChangedEnvelopeReutilizaElEventID(t *testing.T) {
	evt := cambioDeEstado()
	primero := newUserStatusChangedEnvelope(evt, DefaultProducer, emitido)
	segundo := newUserStatusChangedEnvelope(evt, DefaultProducer, emitido.Add(time.Minute))

	if primero.EventID != evt.EventID.String() || segundo.EventID != primero.EventID {
		t.Errorf("eventId = %q / %q, se esperaba %q en ambos", primero.EventID, segundo.EventID, evt.EventID)
	}
}

func TestNoopPublisherDejaConstanciaDeUserStatusChanged(t *testing.T) {
	logs := &strings.Builder{}
	p := NewNoopPublisher(slog.New(slog.NewTextHandler(logs, nil)))

	evt := cambioDeEstado()
	if err := p.PublishUserStatusChanged(t.Context(), evt); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	registro := logs.String()
	if !strings.Contains(registro, EventTypeUserStatusChanged) || !strings.Contains(registro, evt.UserID.String()) || !strings.Contains(registro, "WARN") {
		t.Errorf("el log debería nombrar el evento y el usuario en WARN: %s", registro)
	}
}
