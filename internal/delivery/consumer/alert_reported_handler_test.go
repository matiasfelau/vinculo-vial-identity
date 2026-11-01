package consumer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

const colaDeReportes = "identity.alert-reported.q"

// reportadorFalso implementa ReportApplier.
type reportadorFalso struct {
	err       error
	registro  *registro
	recibidos []domain.AlertReport
}

func (a *reportadorFalso) Apply(_ context.Context, r domain.AlertReport) error {
	a.recibidos = append(a.recibidos, r)
	if a.err != nil {
		return a.err
	}
	if a.registro != nil {
		a.registro.anotar("commit")
	}
	return nil
}

func cuerpoReporte(t *testing.T, eventID uuid.UUID, actor any, payload any) []byte {
	t.Helper()

	body, err := json.Marshal(map[string]any{
		"eventId":   eventID.String(),
		"eventType": "alert.reported",
		"actor":     actor,
		"payload":   payload,
	})
	if err != nil {
		t.Fatalf("no se pudo armar el cuerpo: %v", err)
	}
	return body
}

func payloadDeReporte(reason string) map[string]any {
	return map[string]any{"alert_id": uuid.NewString(), "reason": reason}
}

func consumidorDeReportes(t *testing.T, aplicador *reportadorFalso, dlq *dlqFalsa) *Consumer {
	t.Helper()

	return consumidorDeReportesConLogger(t, aplicador, dlq, loggerMudo())
}

// consumidorDeReportesConLogger es consumidorDeReportes con el logger del
// handler a elección, para las pruebas que inspeccionan lo que se loguea.
func consumidorDeReportesConLogger(t *testing.T, aplicador *reportadorFalso, dlq *dlqFalsa, logger *slog.Logger) *Consumer {
	t.Helper()

	h, err := NewAlertReportedHandler(aplicador, logger)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	c, err := NewConsumer(nuevoCanalFalso(), dlq, Spec{
		Queue: colaDeReportes, EventType: "alert.reported", MaxRetries: maxReintentosDePrueba, Handler: h,
	}, loggerMudo())
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	return c
}

func TestAlertReportedEntregaElReporteAlCasoDeUso(t *testing.T) {
	for _, motivo := range []string{"FALSE_ALERT", "SPAM"} {
		t.Run(motivo, func(t *testing.T) {
			aplicador, dlq := &reportadorFalso{}, &dlqFalsa{}
			c := consumidorDeReportes(t, aplicador, dlq)

			eventID, reportado := uuid.New(), uuid.New()
			d, a := entrega(cuerpoReporte(t, eventID, reportado.String(), payloadDeReporte(motivo)), 0)
			c.process(t.Context(), d)

			if acks, nacks, _ := a.contadores(); acks != 1 || nacks != 0 {
				t.Errorf("acks=%d nacks=%d, se esperaba un único ack", acks, nacks)
			}
			if len(aplicador.recibidos) != 1 {
				t.Fatalf("reportes aplicados = %d, se esperaba 1", len(aplicador.recibidos))
			}
			got := aplicador.recibidos[0]
			if got.EventID != eventID || got.UserID != reportado || got.Reason != motivo {
				t.Errorf("reporte = %+v", got)
			}
			if dlq.derivados() != 0 {
				t.Errorf("un reporte válido no va a la dlq")
			}
		})
	}
}

// La alerta de un emisor dado de baja tiene issuer_id = NULL y su alert.reported
// sale sin actor: no hay a quién poner en revisión. El mensaje se confirma sin
// efecto y nunca va a la DLQ ni se reintenta.
func TestAlertReportedSinActorSeConfirmaSinEfecto(t *testing.T) {
	cuerpoSinClave, err := json.Marshal(map[string]any{
		"eventId":   uuid.NewString(),
		"eventType": "alert.reported",
		"payload":   payloadDeReporte("SPAM"),
	})
	if err != nil {
		t.Fatalf("no se pudo armar el cuerpo: %v", err)
	}

	casos := map[string][]byte{
		"actor null":         cuerpoReporte(t, uuid.New(), nil, payloadDeReporte("SPAM")),
		"sin clave actor":    cuerpoSinClave,
		"motivo FALSE_ALERT": cuerpoReporte(t, uuid.New(), nil, payloadDeReporte("FALSE_ALERT")),
	}

	for nombre, cuerpo := range casos {
		t.Run(nombre, func(t *testing.T) {
			aplicador, dlq := &reportadorFalso{}, &dlqFalsa{}
			c := consumidorDeReportes(t, aplicador, dlq)

			d, a := entrega(cuerpo, 0)
			c.process(t.Context(), d)

			if len(aplicador.recibidos) != 0 {
				t.Errorf("sin actor no hay a quién poner en revisión: no se debe aplicar nada")
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
func TestAlertReportedSinActorDejaConstanciaEnInfo(t *testing.T) {
	var salida bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&salida, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c := consumidorDeReportesConLogger(t, &reportadorFalso{}, &dlqFalsa{}, logger)

	eventID := uuid.New()
	d, _ := entrega(cuerpoReporte(t, eventID, nil, payloadDeReporte("SPAM")), 0)
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
func TestAlertReportedSinActorConPayloadInvalidoVaALaDLQ(t *testing.T) {
	casos := map[string]any{
		"sin payload":           nil,
		"payload no es objeto":  "texto",
		"sin alert_id":          map[string]any{"reason": "SPAM"},
		"sin reason":            map[string]any{"alert_id": uuid.NewString()},
		"reason fuera del enum": payloadDeReporte("OTRO"),
	}

	for nombre, payload := range casos {
		t.Run(nombre, func(t *testing.T) {
			aplicador, dlq := &reportadorFalso{}, &dlqFalsa{}
			c := consumidorDeReportes(t, aplicador, dlq)

			d, a := entrega(cuerpoReporte(t, uuid.New(), nil, payload), 0)
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

func TestAlertReportedInvalidoVaDirectoALaDLQ(t *testing.T) {
	casos := map[string]struct {
		actor   any
		payload any
	}{
		"actor vacío":           {"", payloadDeReporte("SPAM")},
		"actor que no es uuid":  {"no-es-uuid", payloadDeReporte("SPAM")},
		"actor uuid nulo":       {uuid.Nil.String(), payloadDeReporte("SPAM")},
		"sin payload":           {uuid.NewString(), nil},
		"payload no es objeto":  {uuid.NewString(), "texto"},
		"sin alert_id":          {uuid.NewString(), map[string]any{"reason": "SPAM"}},
		"alert_id no es uuid":   {uuid.NewString(), map[string]any{"alert_id": "x", "reason": "SPAM"}},
		"sin reason":            {uuid.NewString(), map[string]any{"alert_id": uuid.NewString()}},
		"reason fuera del enum": {uuid.NewString(), payloadDeReporte("OTRO")},
		"reason en minúsculas":  {uuid.NewString(), payloadDeReporte("spam")},
	}

	for nombre, caso := range casos {
		t.Run(nombre, func(t *testing.T) {
			aplicador, dlq := &reportadorFalso{}, &dlqFalsa{}
			c := consumidorDeReportes(t, aplicador, dlq)

			d, a := entrega(cuerpoReporte(t, uuid.New(), caso.actor, caso.payload), 0)
			c.process(t.Context(), d)

			if len(aplicador.recibidos) != 0 {
				t.Errorf("un mensaje inválido no debe llegar al caso de uso")
			}
			if acks, nacks, _ := a.contadores(); acks != 1 || nacks != 0 {
				t.Errorf("acks=%d nacks=%d, se esperaba ack tras derivar a la dlq", acks, nacks)
			}
			if dlq.derivados() != 1 || dlq.colas[0] != colaDeReportes {
				t.Errorf("se esperaba una derivación a %q, hubo %v", colaDeReportes, dlq.colas)
			}
		})
	}
}

// Un error de base es transitorio: nack sin requeue; agotados los reintentos,
// DLQ con la cola de trabajo como routing key.
func TestAlertReportedConErrorDeBaseHaceNackYAlAgotarVaALaDLQ(t *testing.T) {
	aplicador, dlq := &reportadorFalso{err: domain.ErrDatabaseUnavailable}, &dlqFalsa{}
	c := consumidorDeReportes(t, aplicador, dlq)
	body := cuerpoReporte(t, uuid.New(), uuid.NewString(), payloadDeReporte("SPAM"))

	d, a := entregaDeCola(colaDeReportes, body, 0)
	c.process(t.Context(), d)
	if acks, nacks, requeues := a.contadores(); acks != 0 || nacks != 1 || requeues != 0 {
		t.Errorf("acks=%d nacks=%d requeues=%d, se esperaba un nack sin requeue", acks, nacks, requeues)
	}

	d, a = entregaDeCola(colaDeReportes, body, maxReintentosDePrueba)
	c.process(t.Context(), d)
	if acks, nacks, _ := a.contadores(); acks != 1 || nacks != 0 {
		t.Errorf("agotados los reintentos: acks=%d nacks=%d", acks, nacks)
	}
	if dlq.derivados() != 1 || dlq.colas[0] != colaDeReportes {
		t.Errorf("se esperaba una derivación a %q, hubo %v", colaDeReportes, dlq.colas)
	}
}

// El ack llega después del commit; con la base caída solo hay nack.
func TestAlertReportedConfirmaDespuesDelCommit(t *testing.T) {
	casos := map[string]struct {
		err  error
		want []string
	}{
		"éxito":         {nil, []string{"commit", "ack"}},
		"error de base": {errors.New("deadlock"), []string{"nack"}},
	}
	for nombre, caso := range casos {
		t.Run(nombre, func(t *testing.T) {
			reg := &registro{}
			aplicador := &reportadorFalso{registro: reg, err: caso.err}
			c := consumidorDeReportes(t, aplicador, &dlqFalsa{})

			d, _ := entrega(cuerpoReporte(t, uuid.New(), uuid.NewString(), payloadDeReporte("SPAM")), 0)
			d.Acknowledger = &ackerOrdenado{registro: reg}
			c.process(t.Context(), d)

			if got := reg.copia(); !slices.Equal(got, caso.want) {
				t.Errorf("orden = %v, se esperaba %v", got, caso.want)
			}
		})
	}
}

func TestNewAlertReportedHandlerExigeElCasoDeUso(t *testing.T) {
	if _, err := NewAlertReportedHandler(nil, loggerMudo()); err == nil {
		t.Error("se esperaba un error sin caso de uso")
	}
}
