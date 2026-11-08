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

var bajaEn = time.Date(2026, 11, 2, 15, 4, 5, 123456789, time.UTC)

func unaBajaDeCuenta() domain.UserDeleted {
	return domain.NewUserDeleted(
		uuid.MustParse("a1b2c3d4-e5f6-4789-9abc-def012345678"),
		uuid.MustParse("6f2a4c1e-9d3b-4f5a-8c7d-1e2f3a4b5c6d"),
		bajaEn,
	)
}

// El sobre cumple el contrato de US-11: eventType y routing key user.deleted,
// el usuario dado de baja como actor, y un payload con solo deleted_at.
func TestUserDeletedEnvelopeCumpleElContrato(t *testing.T) {
	env := newUserDeletedEnvelope(unaBajaDeCuenta(), DefaultProducer, emitido)

	if env.EventType != "user.deleted" {
		t.Errorf("eventType = %q, se esperaba user.deleted", env.EventType)
	}
	if env.Producer != DefaultProducer {
		t.Errorf("producer = %q, se esperaba %q", env.Producer, DefaultProducer)
	}
	if env.Actor == nil || *env.Actor != "6f2a4c1e-9d3b-4f5a-8c7d-1e2f3a4b5c6d" {
		t.Errorf("actor = %v, se esperaba el usuario dado de baja", env.Actor)
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
	payload, _ := decoded["payload"].(map[string]any)
	if len(payload) != 1 {
		t.Fatalf("payload = %v, se esperaba solo deleted_at", payload)
	}
	deletedAt, _ := payload["deleted_at"].(string)
	if got, err := time.Parse(time.RFC3339, deletedAt); err != nil || !got.Equal(bajaEn) {
		t.Errorf("deleted_at = %q (err %v), se esperaba %v en RFC3339", deletedAt, err, bajaEn)
	}
}

// El payload no lleva el usuario ni ningún dato personal: el usuario va como
// actor, y nada más viaja por el bus.
func TestUserDeletedEnvelopeNoLlevaDatosPersonales(t *testing.T) {
	body, err := json.Marshal(newUserDeletedEnvelope(unaBajaDeCuenta(), DefaultProducer, emitido))
	if err != nil {
		t.Fatalf("no se pudo serializar: %v", err)
	}

	var decoded map[string]any
	_ = json.Unmarshal(body, &decoded)
	payload, _ := decoded["payload"].(map[string]any)
	for _, prohibido := range []string{"user_id", "email", "dni", "password", "account_status", "reputation_score"} {
		if _, hay := payload[prohibido]; hay {
			t.Errorf("el payload no debería llevar %q: %v", prohibido, payload)
		}
	}
}

// El eventId es el de la fila del outbox y no cambia entre reintentos.
func TestUserDeletedEnvelopeReutilizaElEventID(t *testing.T) {
	evt := unaBajaDeCuenta()
	primero := newUserDeletedEnvelope(evt, DefaultProducer, emitido)
	segundo := newUserDeletedEnvelope(evt, DefaultProducer, emitido.Add(time.Minute))

	if primero.EventID != evt.EventID.String() || segundo.EventID != primero.EventID {
		t.Errorf("eventId = %q / %q, se esperaba %q en ambos", primero.EventID, segundo.EventID, evt.EventID)
	}
	// deleted_at es el de la baja, no el de cada intento de publicación.
	if primero.Payload != segundo.Payload {
		t.Errorf("el payload cambió entre reintentos: %v / %v", primero.Payload, segundo.Payload)
	}
}

func TestNoopPublisherDejaConstanciaDeUserDeleted(t *testing.T) {
	logs := &strings.Builder{}
	p := NewNoopPublisher(slog.New(slog.NewTextHandler(logs, nil)))

	evt := unaBajaDeCuenta()
	if err := p.PublishUserDeleted(t.Context(), evt); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	registro := logs.String()
	if !strings.Contains(registro, EventTypeUserDeleted) || !strings.Contains(registro, evt.UserID.String()) || !strings.Contains(registro, "WARN") {
		t.Errorf("el log debería nombrar el evento y el usuario en WARN: %s", registro)
	}
}
