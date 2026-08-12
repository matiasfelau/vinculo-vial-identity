// Tests internos: ejercitan el armado del sobre y la configuración, que es la
// lógica propia del paquete. La conversación AMQP queda fuera de los tests
// unitarios, según lo acordado en CLAUDE.md.
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

var (
	ocurrido = time.Date(2026, 8, 12, 15, 30, 0, 0, time.UTC)
	emitido  = time.Date(2026, 8, 12, 15, 30, 1, 0, time.UTC)
)

func eventoDeAlta() domain.UserRegistered {
	return domain.UserRegistered{
		UserID:        uuid.MustParse("6f2a4c1e-9d3b-4f5a-8c7d-1e2f3a4b5c6d"),
		AccountStatus: domain.AccountStatusActive,
		OccurredAt:    ocurrido,
	}
}

func TestNewEnvelopeCompletaElSobreEstandar(t *testing.T) {
	env := newEnvelope(eventoDeAlta(), DefaultProducer, emitido)

	if _, err := uuid.Parse(env.EventID); err != nil {
		t.Errorf("eventId = %q, se esperaba un UUID: %v", env.EventID, err)
	}
	if env.EventType != EventTypeUserRegistered {
		t.Errorf("eventType = %q, se esperaba %q", env.EventType, EventTypeUserRegistered)
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

func TestNewEnvelopeGeneraUnEventIDPorEvento(t *testing.T) {
	evt := eventoDeAlta()

	primero := newEnvelope(evt, DefaultProducer, emitido)
	segundo := newEnvelope(evt, DefaultProducer, emitido)

	// El eventId es la clave de deduplicación del consumidor: repetirlo haría
	// que un alta legítima se descartara como duplicado.
	if primero.EventID == segundo.EventID {
		t.Error("dos sobres distintos no pueden compartir eventId")
	}
}

// El actor es el user_hash de la plataforma. En US-01 el usuario se crea en la
// propia petición, así que no hay X-User-Hash que propagar y se define como el
// UUID: opaco, estable y no enumerable.
func TestActorEsElIdentificadorOpacoDelUsuario(t *testing.T) {
	evt := eventoDeAlta()

	env := newEnvelope(evt, DefaultProducer, emitido)

	if env.Actor != evt.UserID.String() {
		t.Errorf("actor = %q, se esperaba %q", env.Actor, evt.UserID)
	}
}

// Publicar el Blind Index destruiría la propiedad que le da sentido: es el
// índice de búsqueda del dato más sensible del sistema.
func TestElSobreNoLlevaPII(t *testing.T) {
	evt := eventoDeAlta()

	body, err := json.Marshal(newEnvelope(evt, DefaultProducer, emitido))
	if err != nil {
		t.Fatalf("no se pudo serializar: %v", err)
	}

	serializado := string(body)
	prohibidos := map[string]string{
		"email":        "vecino@vinculovial.ar",
		"DNI en claro": "30123456",
		"Blind Index":  "5f4dcc3b5aa765d61d8327deb882cf99",
		"DNI cifrado":  "Y2lmcmFkbw==",
	}
	for nombre, valor := range prohibidos {
		if strings.Contains(serializado, valor) {
			t.Errorf("el sobre incluye %s: %s", nombre, serializado)
		}
	}
	for _, campo := range []string{"email", "dni", "password"} {
		if strings.Contains(strings.ToLower(serializado), `"`+campo) {
			t.Errorf("el sobre expone un campo %q: %s", campo, serializado)
		}
	}
}

// Los consumidores dependen de estos nombres: cambiarlos rompe el contrato de
// la plataforma.
func TestFormaSerializadaDelSobre(t *testing.T) {
	body, err := json.Marshal(newEnvelope(eventoDeAlta(), DefaultProducer, emitido))
	if err != nil {
		t.Fatalf("no se pudo serializar: %v", err)
	}

	var sobre map[string]json.RawMessage
	if err := json.Unmarshal(body, &sobre); err != nil {
		t.Fatalf("el sobre no es JSON válido: %v", err)
	}

	for _, campo := range []string{"eventId", "eventType", "timestamp", "producer", "actor", "payload"} {
		if _, ok := sobre[campo]; !ok {
			t.Errorf("falta el campo %q del sobre estándar: %s", campo, body)
		}
	}

	var payload map[string]any
	if err := json.Unmarshal(sobre["payload"], &payload); err != nil {
		t.Fatalf("el payload no es JSON válido: %v", err)
	}
	for _, campo := range []string{"userId", "accountStatus", "registeredAt"} {
		if _, ok := payload[campo]; !ok {
			t.Errorf("falta el campo %q del payload: %s", campo, sobre["payload"])
		}
	}
	if got := payload["accountStatus"]; got != string(domain.AccountStatusActive) {
		t.Errorf("accountStatus = %v, se esperaba %q", got, domain.AccountStatusActive)
	}
}

func TestNewEnvelopeNormalizaLasMarcasDeTiempoAUTC(t *testing.T) {
	art := time.FixedZone("ART", -3*60*60)
	evt := eventoDeAlta()
	evt.OccurredAt = ocurrido.In(art)

	env := newEnvelope(evt, DefaultProducer, emitido.In(art))

	if !strings.HasSuffix(env.Timestamp, "Z") {
		t.Errorf("timestamp = %q, se esperaba UTC", env.Timestamp)
	}

	payload, ok := env.Payload.(userRegisteredPayload)
	if !ok {
		t.Fatalf("payload = %T, se esperaba userRegisteredPayload", env.Payload)
	}
	if !strings.HasSuffix(payload.RegisteredAt, "Z") {
		t.Errorf("registeredAt = %q, se esperaba UTC", payload.RegisteredAt)
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
