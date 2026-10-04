// Tests internos: ejercitan el armado del sobre y la configuración, que es la
// lógica propia del paquete. La conversación AMQP queda fuera de los tests
// unitarios: requiere un broker real.
package events

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

var emitido = time.Date(2026, 8, 12, 15, 30, 1, 0, time.UTC)

func eventoDeRevocacion() domain.SessionsRevoked {
	return domain.NewSessionsRevoked(
		uuid.MustParse("a1b2c3d4-e5f6-4789-9abc-def012345678"),
		uuid.MustParse("6f2a4c1e-9d3b-4f5a-8c7d-1e2f3a4b5c6d"),
		domain.SessionsRevokedReasonReuseDetected,
	)
}

// El eventId no se genera al armar el sobre: viene del patrón Transactional
// Outbox (domain.OutboxEvent.ID) y tiene que
// reutilizarse tal cual entre reintentos del worker, para que un consumidor
// que deduplique por event_id no cuente dos veces una publicación
// reintentada.
func TestNewSessionsRevokedEnvelopeReutilizaElEventID(t *testing.T) {
	evt := eventoDeRevocacion()
	env := newSessionsRevokedEnvelope(evt, DefaultProducer, emitido)

	if env.EventID != evt.EventID.String() {
		t.Errorf("eventId = %q, se esperaba que reutilizara %q", env.EventID, evt.EventID.String())
	}
}

func TestNewSessionsRevokedEnvelopeCompletaElSobreEstandar(t *testing.T) {
	env := newSessionsRevokedEnvelope(eventoDeRevocacion(), DefaultProducer, emitido)

	if _, err := uuid.Parse(env.EventID); err != nil {
		t.Errorf("eventId = %q, se esperaba un UUID: %v", env.EventID, err)
	}
	if env.EventType != EventTypeSessionsRevoked {
		t.Errorf("eventType = %q, se esperaba %q", env.EventType, EventTypeSessionsRevoked)
	}
	if env.Producer != DefaultProducer {
		t.Errorf("producer = %q, se esperaba %q", env.Producer, DefaultProducer)
	}
	if got, err := time.Parse(time.RFC3339Nano, env.Timestamp); err != nil {
		t.Errorf("timestamp = %q, se esperaba RFC3339: %v", env.Timestamp, err)
	} else if !got.Equal(emitido) {
		t.Errorf("timestamp = %v, se esperaba %v", got, emitido)
	}
}

// El actor lleva el UUID del usuario afectado: es la referencia que Notification necesita para dar de baja los tokens FCM
// de la cuenta afectada.
func TestSessionsRevokedEnvelopeLlevaElActor(t *testing.T) {
	evt := eventoDeRevocacion()
	env := newSessionsRevokedEnvelope(evt, DefaultProducer, emitido)

	if env.Actor == nil {
		t.Fatal("actor = nil, se esperaba el UUID del usuario")
	}
	if *env.Actor != evt.UserID.String() {
		t.Errorf("actor = %q, se esperaba %q", *env.Actor, evt.UserID.String())
	}
}

// El payload no lleva PII ni derivados del DNI: solo el motivo, acotado a un
// enum, que es lo único que fija el contrato de US-06.
func TestSessionsRevokedEnvelopeNoLlevaPII(t *testing.T) {
	body, err := json.Marshal(newSessionsRevokedEnvelope(eventoDeRevocacion(), DefaultProducer, emitido))
	if err != nil {
		t.Fatalf("no se pudo serializar: %v", err)
	}

	var sobre map[string]json.RawMessage
	if err := json.Unmarshal(body, &sobre); err != nil {
		t.Fatalf("el sobre no es JSON válido: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(sobre["payload"], &payload); err != nil {
		t.Fatalf("el payload no es JSON válido: %v", err)
	}

	if len(payload) != 1 {
		t.Errorf("el payload tiene %d campos, el contrato define solo reason: %s", len(payload), sobre["payload"])
	}
	if got := payload["reason"]; got != string(domain.SessionsRevokedReasonReuseDetected) {
		t.Errorf("reason = %v, se esperaba %q", got, domain.SessionsRevokedReasonReuseDetected)
	}

	serializado := string(body)
	for _, campo := range []string{"email", "dni", "password", "refreshtokenhash", "dnihashed"} {
		if strings.Contains(strings.ToLower(serializado), `"`+campo) {
			t.Errorf("el sobre expone un campo %q: %s", campo, serializado)
		}
	}
}

func TestConfigAplicaValoresPorDefecto(t *testing.T) {
	cfg := Config{URL: "amqp://localhost"}

	cfg.applyDefaults()

	if cfg.Exchange != DefaultExchange {
		t.Errorf("exchange = %q, se esperaba %q", cfg.Exchange, DefaultExchange)
	}
	if cfg.Producer != DefaultProducer {
		t.Errorf("producer = %q, se esperaba %q", cfg.Producer, DefaultProducer)
	}
	if cfg.PublishTimeout != DefaultPublishTimeout {
		t.Errorf("publish timeout = %v, se esperaba %v", cfg.PublishTimeout, DefaultPublishTimeout)
	}
	if cfg.DialTimeout != DefaultDialTimeout {
		t.Errorf("dial timeout = %v, se esperaba %v", cfg.DialTimeout, DefaultDialTimeout)
	}
	if cfg.Heartbeat != DefaultHeartbeat {
		t.Errorf("heartbeat = %v, se esperaba %v", cfg.Heartbeat, DefaultHeartbeat)
	}
}

func TestConfigRespetaLosValoresExplicitos(t *testing.T) {
	cfg := Config{
		URL:            "amqp://localhost",
		Exchange:       "otro.exchange",
		Producer:       "otro-productor",
		PublishTimeout: time.Second,
		DialTimeout:    2 * time.Second,
		Heartbeat:      3 * time.Second,
	}
	esperado := cfg

	cfg.applyDefaults()

	if cfg != esperado {
		t.Errorf("config = %+v, se esperaba %+v", cfg, esperado)
	}
}

func TestNewPublisherExigeLaURL(t *testing.T) {
	if _, err := NewPublisher(Config{}, nil); err == nil {
		t.Error("se esperaba un error al construir sin URL del broker")
	}
}

// La URL del broker lleva usuario y contraseña.
func TestScrubURLRedactaLasCredenciales(t *testing.T) {
	const url = "amqp://identity:sup3rs3cr3t@rabbit:5672/"

	got := scrubURL(fmt.Errorf("dial tcp: no se pudo conectar a %s", url), url)

	if got == nil {
		t.Fatal("se esperaba un error")
	}
	if strings.Contains(got.Error(), "sup3rs3cr3t") {
		t.Errorf("el error filtra la credencial: %q", got)
	}
}

func TestScrubURLPreservaErroresSinCredencial(t *testing.T) {
	original := errors.New("connection refused")

	if got := scrubURL(original, "amqp://user:pass@rabbit:5672/"); !errors.Is(got, original) {
		t.Errorf("se esperaba el error original intacto, se obtuvo %v", got)
	}
	if got := scrubURL(nil, "amqp://rabbit"); got != nil {
		t.Errorf("se esperaba nil, se obtuvo %v", got)
	}
}

func TestNewSessionsRevokedEnvelopeNormalizaLasMarcasDeTiempoAUTC(t *testing.T) {
	art := time.FixedZone("ART", -3*60*60)

	env := newSessionsRevokedEnvelope(eventoDeRevocacion(), DefaultProducer, emitido.In(art))

	if !strings.HasSuffix(env.Timestamp, "Z") {
		t.Errorf("timestamp = %q, se esperaba UTC", env.Timestamp)
	}
	if _, ok := env.Payload.(sessionsRevokedPayload); !ok {
		t.Fatalf("payload = %T, se esperaba sessionsRevokedPayload", env.Payload)
	}
}
