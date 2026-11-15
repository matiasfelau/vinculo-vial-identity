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

var (
	idDelEvento   = uuid.MustParse("a1b2c3d4-e5f6-4789-9abc-def012345678")
	idDelActor    = uuid.MustParse("6f2a4c1e-9d3b-4f5a-8c7d-1e2f3a4b5c6d")
	venceElCodigo = time.Date(2026, 11, 2, 15, 14, 5, 0, time.UTC)
)

func emailConCodigo() domain.EmailRequested {
	return domain.EmailRequested{
		EventID: idDelEvento,
		EmailRequest: domain.EmailRequest{
			Template: domain.EmailTemplatePasswordReset, To: "vecino@example.com", Code: "042917",
			ExpiresAt: &venceElCodigo, Actor: &idDelActor,
		},
	}
}

func serializado(t *testing.T, env Envelope) map[string]any {
	t.Helper()
	body, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("no se pudo serializar: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("JSON inválido: %v", err)
	}
	return decoded
}

// El sobre cumple el contrato de US-13: eventType y routing key email.requested,
// y el payload { template, to, code, expires_at } con expires_at en RFC3339.
func TestEmailRequestedEnvelopeCumpleElContrato(t *testing.T) {
	env := newEmailRequestedEnvelope(emailConCodigo(), DefaultProducer, emitido)

	if env.EventType != "email.requested" || EventTypeEmailRequested != "email.requested" {
		t.Errorf("eventType = %q, se esperaba email.requested", env.EventType)
	}
	if env.EventID != idDelEvento.String() {
		t.Errorf("eventId = %q: tiene que ser el de la fila del outbox", env.EventID)
	}
	if env.Producer != DefaultProducer {
		t.Errorf("producer = %q", env.Producer)
	}
	if got, err := time.Parse(time.RFC3339Nano, env.Timestamp); err != nil || !got.Equal(emitido) {
		t.Errorf("timestamp = %q (err %v)", env.Timestamp, err)
	}

	payload, _ := serializado(t, env)["payload"].(map[string]any)
	if len(payload) != 4 {
		t.Fatalf("payload = %v, se esperaban exactamente template, to, code y expires_at", payload)
	}
	if payload["template"] != "PASSWORD_RESET" || payload["to"] != "vecino@example.com" || payload["code"] != "042917" {
		t.Errorf("payload = %v", payload)
	}
	if got, _ := payload["expires_at"].(string); got != "2026-11-02T15:14:05Z" {
		t.Errorf("expires_at = %q, se esperaba RFC3339", got)
	}
}

func TestEmailRequestedEnvelopeLlevaElActorSoloSiHayUsuario(t *testing.T) {
	con := newEmailRequestedEnvelope(emailConCodigo(), DefaultProducer, emitido)
	if con.Actor == nil || *con.Actor != idDelActor.String() {
		t.Errorf("actor = %v, se esperaba el usuario", con.Actor)
	}

	sin := emailConCodigo()
	sin.Actor = nil
	env := newEmailRequestedEnvelope(sin, DefaultProducer, emitido)
	if env.Actor != nil {
		t.Errorf("actor = %v, se esperaba nulo", *env.Actor)
	}
	if v, hay := serializado(t, env)["actor"]; !hay || v != nil {
		t.Errorf("actor serializado = %v (presente=%v), se esperaba null explícito", v, hay)
	}
}

// Sin código ni vencimiento (ACCOUNT_EXISTS, PASSWORD_CHANGED) el payload los
// lleva como null, no los omite.
func TestEmailRequestedEnvelopeSinCodigoLlevaNull(t *testing.T) {
	evt := domain.EmailRequested{
		EventID:      idDelEvento,
		EmailRequest: domain.EmailRequest{Template: domain.EmailTemplateAccountExists, To: "vecino@example.com"},
	}

	payload, _ := serializado(t, newEmailRequestedEnvelope(evt, DefaultProducer, emitido))["payload"].(map[string]any)

	for _, campo := range []string{"code", "expires_at"} {
		if v, hay := payload[campo]; !hay || v != nil {
			t.Errorf("%s = %v (presente=%v), se esperaba null", campo, v, hay)
		}
	}
	if payload["template"] != "ACCOUNT_EXISTS" {
		t.Errorf("template = %v", payload["template"])
	}
}

// El publisher inerte deja constancia del evento descartado, pero nunca del
// destinatario ni del código: ese log es de desarrollo y aun así no es lugar para
// ellos.
func TestNoopPublisherNoLogueaElDestinatarioNiElCodigo(t *testing.T) {
	logs := &strings.Builder{}
	p := NewNoopPublisher(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))

	if err := p.PublishEmailRequested(t.Context(), emailConCodigo()); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	out := logs.String()
	if !strings.Contains(out, "email.requested") || !strings.Contains(out, "PASSWORD_RESET") || !strings.Contains(out, "WARN") {
		t.Errorf("el log debería nombrar el evento y la plantilla, en WARN: %s", out)
	}
	for _, secreto := range []string{"vecino@example.com", "042917", "example.com"} {
		if strings.Contains(out, secreto) {
			t.Errorf("el log contiene %q: %s", secreto, out)
		}
	}
}
