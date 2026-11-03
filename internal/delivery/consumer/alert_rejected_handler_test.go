package consumer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// registro ordena lo que pasa en la base y lo que se le dice al broker, para
// verificar que el ack llega después del commit.
type registro struct {
	mu      sync.Mutex
	eventos []string
}

func (r *registro) anotar(e string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.eventos = append(r.eventos, e)
}

func (r *registro) copia() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.eventos)
}

// aplicadorFalso implementa RejectionApplier. "commit" se anota cuando el caso
// de uso terminó bien, que es cuando la transacción real ya se confirmó.
type aplicadorFalso struct {
	err       error
	registro  *registro
	recibidos []domain.AlertRejection
}

func (a *aplicadorFalso) Apply(_ context.Context, r domain.AlertRejection) error {
	a.recibidos = append(a.recibidos, r)
	if a.err != nil {
		return a.err
	}
	if a.registro != nil {
		a.registro.anotar("commit")
	}
	return nil
}

// ackerOrdenado anota el ack en el mismo registro que el aplicador.
type ackerOrdenado struct {
	acker
	registro *registro
}

func (a *ackerOrdenado) Ack(tag uint64, multiple bool) error {
	a.registro.anotar("ack")
	return a.acker.Ack(tag, multiple)
}

func (a *ackerOrdenado) Nack(tag uint64, multiple, requeue bool) error {
	a.registro.anotar("nack")
	return a.acker.Nack(tag, multiple, requeue)
}

func cuerpoRechazo(t *testing.T, eventID uuid.UUID, actor any, payload any) []byte {
	t.Helper()

	body, err := json.Marshal(map[string]any{
		"eventId":   eventID.String(),
		"eventType": "alert.rejected",
		"actor":     actor,
		"payload":   payload,
	})
	if err != nil {
		t.Fatalf("no se pudo armar el cuerpo: %v", err)
	}
	return body
}

func payloadDeRechazo(codes ...string) map[string]any {
	return map[string]any{"alert_id": uuid.NewString(), "reason_codes": codes}
}

// consumidorDeRechazos arma un Consumer real con el handler real y dobles del
// caso de uso y de la DLQ.
func consumidorDeRechazos(t *testing.T, aplicador *aplicadorFalso, dlq *dlqFalsa) *Consumer {
	t.Helper()

	return consumidorDeRechazosConLogger(t, aplicador, dlq, loggerMudo())
}

// consumidorDeRechazosConLogger es consumidorDeRechazos con el logger del
// handler a elección, para las pruebas que inspeccionan lo que se loguea.
func consumidorDeRechazosConLogger(t *testing.T, aplicador *aplicadorFalso, dlq *dlqFalsa, logger *slog.Logger) *Consumer {
	t.Helper()

	h, err := NewAlertRejectedHandler(aplicador, logger)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	c, err := NewConsumer(nuevoCanalFalso(), dlq, Spec{
		Queue: colaDePrueba, EventType: tipoDePrueba, MaxRetries: maxReintentosDePrueba, Handler: h,
	}, loggerMudo())
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	return c
}

func TestAlertRejectedEntregaElRechazoAlCasoDeUso(t *testing.T) {
	aplicador, dlq := &aplicadorFalso{}, &dlqFalsa{}
	c := consumidorDeRechazos(t, aplicador, dlq)

	eventID, emisor := uuid.New(), uuid.New()
	d, a := entrega(cuerpoRechazo(t, eventID, emisor.String(), payloadDeRechazo("PLATE_MISMATCH", "EVIDENCE_UNREADABLE")), 0)
	c.process(t.Context(), d)

	if acks, nacks, _ := a.contadores(); acks != 1 || nacks != 0 {
		t.Errorf("acks=%d nacks=%d, se esperaba un único ack", acks, nacks)
	}
	if len(aplicador.recibidos) != 1 {
		t.Fatalf("rechazos aplicados = %d, se esperaba 1", len(aplicador.recibidos))
	}
	got := aplicador.recibidos[0]
	if got.EventID != eventID || got.UserID != emisor {
		t.Errorf("rechazo = %+v, se esperaba el evento %v del emisor %v", got, eventID, emisor)
	}
	if !slices.Equal(got.ReasonCodes, []string{"PLATE_MISMATCH", "EVIDENCE_UNREADABLE"}) {
		t.Errorf("códigos = %v", got.ReasonCodes)
	}
	if dlq.derivados() != 0 {
		t.Errorf("un rechazo válido no va a la dlq")
	}
}

// La alerta de un emisor dado de baja tiene issuer_id = NULL y su alert.rejected
// sale sin actor: no hay a quién penalizar. El mensaje se confirma sin efecto y
// nunca va a la DLQ ni se reintenta.
func TestAlertRejectedSinActorSeConfirmaSinEfecto(t *testing.T) {
	cuerpoSinClave, err := json.Marshal(map[string]any{
		"eventId":   uuid.NewString(),
		"eventType": "alert.rejected",
		"payload":   payloadDeRechazo("NO_VEHICLE"),
	})
	if err != nil {
		t.Fatalf("no se pudo armar el cuerpo: %v", err)
	}

	casos := map[string][]byte{
		"actor null":         cuerpoRechazo(t, uuid.New(), nil, payloadDeRechazo("NO_VEHICLE")),
		"sin clave actor":    cuerpoSinClave,
		"rechazo sin fraude": cuerpoRechazo(t, uuid.New(), nil, payloadDeRechazo("EVIDENCE_UNREADABLE")),
	}

	for nombre, cuerpo := range casos {
		t.Run(nombre, func(t *testing.T) {
			aplicador, dlq := &aplicadorFalso{}, &dlqFalsa{}
			c := consumidorDeRechazos(t, aplicador, dlq)

			d, a := entrega(cuerpo, 0)
			c.process(t.Context(), d)

			if len(aplicador.recibidos) != 0 {
				t.Errorf("sin actor no hay a quién penalizar: no se debe aplicar nada")
			}
			if acks, nacks, _ := a.contadores(); acks != 1 || nacks != 0 {
				t.Errorf("acks=%d nacks=%d, se esperaba un único ack", acks, nacks)
			}
			if dlq.llamadas != 0 {
				t.Errorf("la falta de actor no manda el mensaje a la dlq")
			}
		})
	}
}

// El ack sin actor deja constancia en INFO, con el eventId y sin más datos.
func TestAlertRejectedSinActorDejaConstanciaEnInfo(t *testing.T) {
	var salida bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&salida, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c := consumidorDeRechazosConLogger(t, &aplicadorFalso{}, &dlqFalsa{}, logger)

	eventID := uuid.New()
	d, _ := entrega(cuerpoRechazo(t, eventID, nil, payloadDeRechazo("NO_VEHICLE")), 0)
	c.process(t.Context(), d)

	log := salida.String()
	if !strings.Contains(log, "level=INFO") || !strings.Contains(log, eventID.String()) {
		t.Errorf("se esperaba un log INFO con el eventId, hubo: %q", log)
	}
	if strings.Contains(log, "level=WARN") || strings.Contains(log, "level=ERROR") {
		t.Errorf("la falta de actor es un caso esperado, no un aviso ni un error: %q", log)
	}
}

// Sin actor no se salta la validación: un payload inválido es un defecto del
// productor y va a la DLQ aunque el actor falte.
func TestAlertRejectedSinActorConPayloadInvalidoVaALaDLQ(t *testing.T) {
	casos := map[string]any{
		"sin payload":          nil,
		"payload no es objeto": "texto",
		"sin alert_id":         map[string]any{"reason_codes": []string{"NO_VEHICLE"}},
		"sin reason_codes":     map[string]any{"alert_id": uuid.NewString()},
		"reason_codes vacío":   payloadDeRechazo(),
	}

	for nombre, payload := range casos {
		t.Run(nombre, func(t *testing.T) {
			aplicador, dlq := &aplicadorFalso{}, &dlqFalsa{}
			c := consumidorDeRechazos(t, aplicador, dlq)

			d, a := entrega(cuerpoRechazo(t, uuid.New(), nil, payload), 0)
			c.process(t.Context(), d)

			if len(aplicador.recibidos) != 0 {
				t.Errorf("un mensaje inválido no debe llegar al caso de uso")
			}
			if acks, nacks, _ := a.contadores(); acks != 1 || nacks != 0 {
				t.Errorf("acks=%d nacks=%d, se esperaba ack tras derivar a la dlq", acks, nacks)
			}
			if dlq.derivados() != 1 || dlq.colas[0] != colaDePrueba {
				t.Errorf("se esperaba una derivación a %q, hubo %v", colaDePrueba, dlq.colas)
			}
		})
	}
}

func TestAlertRejectedInvalidoVaDirectoALaDLQ(t *testing.T) {
	casos := map[string]struct {
		actor   any
		payload any
	}{
		"actor que no es uuid":     {"no-es-uuid", payloadDeRechazo("NO_VEHICLE")},
		"actor uuid nulo":          {uuid.Nil.String(), payloadDeRechazo("NO_VEHICLE")},
		"actor vacío":              {"", payloadDeRechazo("NO_VEHICLE")},
		"sin payload":              {uuid.NewString(), nil},
		"payload no es objeto":     {uuid.NewString(), "texto"},
		"sin alert_id":             {uuid.NewString(), map[string]any{"reason_codes": []string{"NO_VEHICLE"}}},
		"alert_id no es uuid":      {uuid.NewString(), map[string]any{"alert_id": "x", "reason_codes": []string{"NO_VEHICLE"}}},
		"sin reason_codes":         {uuid.NewString(), map[string]any{"alert_id": uuid.NewString()}},
		"reason_codes vacío":       {uuid.NewString(), payloadDeRechazo()},
		"reason_codes no es lista": {uuid.NewString(), map[string]any{"alert_id": uuid.NewString(), "reason_codes": "NO_VEHICLE"}},
		"reason_code vacío":        {uuid.NewString(), payloadDeRechazo("NO_VEHICLE", "")},
	}

	for nombre, caso := range casos {
		t.Run(nombre, func(t *testing.T) {
			aplicador, dlq := &aplicadorFalso{}, &dlqFalsa{}
			c := consumidorDeRechazos(t, aplicador, dlq)

			d, a := entrega(cuerpoRechazo(t, uuid.New(), caso.actor, caso.payload), 0)
			c.process(t.Context(), d)

			if len(aplicador.recibidos) != 0 {
				t.Errorf("un mensaje inválido no debe llegar al caso de uso")
			}
			if acks, nacks, _ := a.contadores(); acks != 1 || nacks != 0 {
				t.Errorf("acks=%d nacks=%d, se esperaba ack tras derivar a la dlq", acks, nacks)
			}
			if dlq.derivados() != 1 {
				t.Errorf("derivados = %d, se esperaba 1", dlq.derivados())
			}
		})
	}
}

// Un error de base es transitorio: nack sin requeue, y la DLQ solo cuando se
// agotan los reintentos, con la cola de trabajo como routing key.
func TestAlertRejectedConErrorDeBaseHaceNackYAlAgotarVaALaDLQ(t *testing.T) {
	aplicador, dlq := &aplicadorFalso{err: domain.ErrDatabaseUnavailable}, &dlqFalsa{}
	c := consumidorDeRechazos(t, aplicador, dlq)
	body := cuerpoRechazo(t, uuid.New(), uuid.NewString(), payloadDeRechazo("NO_VEHICLE"))

	d, a := entrega(body, 0)
	c.process(t.Context(), d)
	acks, nacks, requeues := a.contadores()
	if acks != 0 || nacks != 1 || requeues != 0 {
		t.Errorf("acks=%d nacks=%d requeues=%d, se esperaba un nack sin requeue", acks, nacks, requeues)
	}
	if dlq.derivados() != 0 {
		t.Errorf("con reintentos disponibles no va a la dlq")
	}

	d, a = entrega(body, maxReintentosDePrueba)
	c.process(t.Context(), d)
	if acks, nacks, _ := a.contadores(); acks != 1 || nacks != 0 {
		t.Errorf("agotados los reintentos: acks=%d nacks=%d, se esperaba ack tras la dlq", acks, nacks)
	}
	if dlq.derivados() != 1 || dlq.colas[0] != colaDePrueba {
		t.Errorf("se esperaba una derivación a %q, hubo %v", colaDePrueba, dlq.colas)
	}
}

// El ack llega después del commit, nunca antes.
func TestAlertRejectedConfirmaDespuesDelCommit(t *testing.T) {
	reg := &registro{}
	aplicador := &aplicadorFalso{registro: reg}
	c := consumidorDeRechazos(t, aplicador, &dlqFalsa{})

	d, _ := entrega(cuerpoRechazo(t, uuid.New(), uuid.NewString(), payloadDeRechazo("NO_VEHICLE")), 0)
	d.Acknowledger = &ackerOrdenado{registro: reg}
	c.process(t.Context(), d)

	if got := reg.copia(); !slices.Equal(got, []string{"commit", "ack"}) {
		t.Errorf("orden = %v, se esperaba [commit ack]", got)
	}
}

// Si la base falla no hay ack: solo nack.
func TestAlertRejectedConErrorDeBaseNoConfirma(t *testing.T) {
	reg := &registro{}
	aplicador := &aplicadorFalso{registro: reg, err: errors.New("deadlock")}
	c := consumidorDeRechazos(t, aplicador, &dlqFalsa{})

	d, _ := entrega(cuerpoRechazo(t, uuid.New(), uuid.NewString(), payloadDeRechazo("NO_VEHICLE")), 0)
	d.Acknowledger = &ackerOrdenado{registro: reg}
	c.process(t.Context(), d)

	if got := reg.copia(); !slices.Equal(got, []string{"nack"}) {
		t.Errorf("orden = %v, se esperaba solo [nack]", got)
	}
}

func TestNewAlertRejectedHandlerExigeElCasoDeUso(t *testing.T) {
	if _, err := NewAlertRejectedHandler(nil, loggerMudo()); err == nil {
		t.Error("se esperaba un error sin caso de uso")
	}
}
