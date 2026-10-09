package consumer

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

const maxReintentosDePrueba = 5

func nuevoConsumidor(t *testing.T, h Handler, dlq deadLetterPublisher) *Consumer {
	t.Helper()

	c, err := NewConsumer(nuevoCanalFalso(), dlq, Spec{
		Queue:      colaDePrueba,
		EventType:  tipoDePrueba,
		MaxRetries: maxReintentosDePrueba,
		Handler:    h,
	}, loggerMudo())
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	return c
}

func TestProcesadoConExitoSeConfirma(t *testing.T) {
	h, dlq := &handlerFalso{}, &dlqFalsa{}
	c := nuevoConsumidor(t, h, dlq)

	eventID := uuid.New()
	d, a := entrega(cuerpoValido(t, eventID, tipoDePrueba), 0)
	c.process(t.Context(), d)

	acks, nacks, _ := a.contadores()
	if acks != 1 || nacks != 0 {
		t.Errorf("acks=%d nacks=%d, se esperaba un único ack", acks, nacks)
	}
	if dlq.derivados() != 0 {
		t.Errorf("un mensaje procesado no debería ir a la dlq")
	}
	if h.cantidad() != 1 || h.vistos[0].EventID != eventID {
		t.Errorf("el handler debería recibir el sobre del evento %s: %+v", eventID, h.vistos)
	}
}

// El handler solo ve el sobre ya validado, con el payload sin interpretar.
func TestElHandlerRecibeElPayloadSinInterpretar(t *testing.T) {
	h := &handlerFalso{}
	c := nuevoConsumidor(t, h, &dlqFalsa{})

	d, _ := entrega(cuerpoValido(t, uuid.New(), tipoDePrueba), 0)
	c.process(t.Context(), d)

	if got := string(h.vistos[0].Payload); !strings.Contains(got, "alert_id") {
		t.Errorf("payload = %q, se esperaba el JSON original", got)
	}
	if h.vistos[0].Actor == nil {
		t.Errorf("el actor del sobre debería llegar al handler")
	}
}

// Un error transitorio (por ejemplo, la base caída) rechaza sin reencolar en
// caliente: la cola de trabajo lo manda a su cola de reintento.
func TestFalloTransitorioRechazaSinReencolar(t *testing.T) {
	h, dlq := &handlerFalso{err: errBase}, &dlqFalsa{}
	c := nuevoConsumidor(t, h, dlq)

	d, a := entrega(cuerpoValido(t, uuid.New(), tipoDePrueba), 0)
	c.process(t.Context(), d)

	acks, nacks, requeues := a.contadores()
	if acks != 0 || nacks != 1 {
		t.Errorf("acks=%d nacks=%d, se esperaba un único nack", acks, nacks)
	}
	if requeues != 0 {
		t.Errorf("el nack no debe pedir requeue: reentregaría en caliente y sin límite")
	}
	if dlq.derivados() != 0 {
		t.Errorf("un fallo transitorio con reintentos disponibles no va a la dlq")
	}
}

func TestReintentosAgotadosVanALaDLQConLaColaDeTrabajoComoRoutingKey(t *testing.T) {
	h, dlq := &handlerFalso{err: errBase}, &dlqFalsa{}
	c := nuevoConsumidor(t, h, dlq)

	body := cuerpoValido(t, uuid.New(), tipoDePrueba)
	d, a := entrega(body, maxReintentosDePrueba)
	c.process(t.Context(), d)

	acks, nacks, _ := a.contadores()
	if acks != 1 || nacks != 0 {
		t.Errorf("acks=%d nacks=%d, se esperaba ack tras derivar a la dlq", acks, nacks)
	}
	if dlq.derivados() != 1 {
		t.Fatalf("derivados = %d, se esperaba 1", dlq.derivados())
	}
	if dlq.colas[0] != colaDePrueba {
		t.Errorf("la dlq se rutea por la cola de trabajo %q, no por la routing key del evento; se usó %q", colaDePrueba, dlq.colas[0])
	}
	if string(dlq.cuerpos[0]) != string(body) {
		t.Errorf("la dlq debe recibir el cuerpo original, sin modificar")
	}
	if !strings.Contains(dlq.motivos[0], errBase.Error()) {
		t.Errorf("el motivo del descarte debería nombrar la causa: %q", dlq.motivos[0])
	}
}

// Un reintento menos que el tope todavía reintenta.
func TestUnReintentoAntesDelTopeSigueReintentando(t *testing.T) {
	h, dlq := &handlerFalso{err: errBase}, &dlqFalsa{}
	c := nuevoConsumidor(t, h, dlq)

	d, a := entrega(cuerpoValido(t, uuid.New(), tipoDePrueba), maxReintentosDePrueba-1)
	c.process(t.Context(), d)

	if _, nacks, _ := a.contadores(); nacks != 1 || dlq.derivados() != 0 {
		t.Errorf("nacks=%d derivados=%d, se esperaba un nack y ninguna derivación", nacks, dlq.derivados())
	}
}

// Si la DLQ no confirma, el original no se pierde: se rechaza y vuelve por la
// cola de reintento.
func TestSiLaDLQFallaElOriginalNoSeConfirma(t *testing.T) {
	h, dlq := &handlerFalso{err: Permanent(errors.New("regla violada"))}, &dlqFalsa{err: errDLQNotConfirmed}
	c := nuevoConsumidor(t, h, dlq)

	d, a := entrega(cuerpoValido(t, uuid.New(), tipoDePrueba), 0)
	c.process(t.Context(), d)

	acks, nacks, requeues := a.contadores()
	if acks != 0 || nacks != 1 || requeues != 0 {
		t.Errorf("acks=%d nacks=%d requeues=%d, se esperaba un nack sin requeue", acks, nacks, requeues)
	}
}

func TestFalloPermanenteDelHandlerVaDirectoALaDLQSinReintentar(t *testing.T) {
	h, dlq := &handlerFalso{err: Permanent(errors.New("actor ausente"))}, &dlqFalsa{}
	c := nuevoConsumidor(t, h, dlq)

	d, a := entrega(cuerpoValido(t, uuid.New(), tipoDePrueba), 0)
	c.process(t.Context(), d)

	acks, nacks, _ := a.contadores()
	if acks != 1 || nacks != 0 {
		t.Errorf("acks=%d nacks=%d, se esperaba ack tras derivar a la dlq", acks, nacks)
	}
	if dlq.derivados() != 1 || dlq.colas[0] != colaDePrueba {
		t.Errorf("se esperaba una derivación a %q, hubo %v", colaDePrueba, dlq.colas)
	}
}

// Un permanente envuelto por el handler con contexto sigue siéndolo.
func TestFalloPermanenteEnvueltoSigueSiendoPermanente(t *testing.T) {
	envuelto := fmt.Errorf("procesando: %w", Permanent(errors.New("payload sin alert_id")))
	h, dlq := &handlerFalso{err: envuelto}, &dlqFalsa{}
	c := nuevoConsumidor(t, h, dlq)

	d, _ := entrega(cuerpoValido(t, uuid.New(), tipoDePrueba), 0)
	c.process(t.Context(), d)

	if dlq.derivados() != 1 {
		t.Errorf("derivados = %d, se esperaba 1", dlq.derivados())
	}
}

func TestMensajesInvalidosVanDirectoALaDLQSinLlamarAlHandler(t *testing.T) {
	casos := map[string][]byte{
		"json ilegible":     []byte(`{no es json`),
		"cuerpo vacío":      nil,
		"sin eventId":       []byte(`{"eventType":"alert.rejected","payload":{}}`),
		"eventId no uuid":   []byte(`{"eventId":"123","eventType":"alert.rejected","payload":{}}`),
		"eventId nulo":      []byte(`{"eventId":"00000000-0000-0000-0000-000000000000","eventType":"alert.rejected"}`),
		"sin eventType":     []byte(`{"eventId":"` + uuid.NewString() + `","payload":{}}`),
		"eventType ajeno":   []byte(`{"eventId":"` + uuid.NewString() + `","eventType":"alert.reported","payload":{}}`),
		"tipos equivocados": []byte(`{"eventId":42,"eventType":[]}`),
	}

	for nombre, body := range casos {
		t.Run(nombre, func(t *testing.T) {
			h, dlq := &handlerFalso{}, &dlqFalsa{}
			c := nuevoConsumidor(t, h, dlq)

			d, a := entrega(body, 0)
			c.process(t.Context(), d)

			if h.cantidad() != 0 {
				t.Errorf("el handler no debería ver un mensaje inválido")
			}
			acks, nacks, _ := a.contadores()
			if acks != 1 || nacks != 0 {
				t.Errorf("acks=%d nacks=%d, se esperaba ack tras derivar a la dlq", acks, nacks)
			}
			if dlq.derivados() != 1 || dlq.colas[0] != colaDePrueba {
				t.Errorf("se esperaba una derivación a %q, hubo %v", colaDePrueba, dlq.colas)
			}
		})
	}
}

// Un panic no tumba al consumidor: se deriva a la DLQ y el siguiente mensaje
// se procesa normalmente.
func TestPanicDelHandlerVaALaDLQYElConsumidorSigueVivo(t *testing.T) {
	h, dlq := &handlerFalso{panico: "boom"}, &dlqFalsa{}
	c := nuevoConsumidor(t, h, dlq)

	d, a := entrega(cuerpoValido(t, uuid.New(), tipoDePrueba), 0)
	c.process(t.Context(), d)

	acks, nacks, _ := a.contadores()
	if acks != 1 || nacks != 0 {
		t.Errorf("acks=%d nacks=%d, se esperaba ack tras derivar a la dlq", acks, nacks)
	}
	if dlq.derivados() != 1 {
		t.Fatalf("derivados = %d, se esperaba 1", dlq.derivados())
	}
	if !strings.Contains(dlq.motivos[0], "panic") {
		t.Errorf("el motivo debería indicar el panic: %q", dlq.motivos[0])
	}

	h.panico = nil
	d2, a2 := entrega(cuerpoValido(t, uuid.New(), tipoDePrueba), 0)
	c.process(t.Context(), d2)
	if acks, _, _ := a2.contadores(); acks != 1 {
		t.Errorf("el consumidor debería seguir procesando tras un panic")
	}
}

// La entrega es at-least-once: el mismo mensaje puede llegar de nuevo. La
// idempotencia es del handler; el consumidor entrega cada copia sin
// deduplicar por su cuenta.
func TestElConsumidorEntregaCadaCopiaAlHandler(t *testing.T) {
	h := &handlerFalso{}
	c := nuevoConsumidor(t, h, &dlqFalsa{})

	body := cuerpoValido(t, uuid.New(), tipoDePrueba)
	for range 2 {
		d, a := entrega(body, 0)
		c.process(t.Context(), d)
		if acks, _, _ := a.contadores(); acks != 1 {
			t.Errorf("cada copia entregada se confirma")
		}
	}
	if h.cantidad() != 2 {
		t.Errorf("llamadas = %d, se esperaba 2", h.cantidad())
	}
}

func TestUnAckFallidoNoPanica(t *testing.T) {
	c := nuevoConsumidor(t, &handlerFalso{}, &dlqFalsa{})

	d, a := entrega(cuerpoValido(t, uuid.New(), tipoDePrueba), 0)
	a.ackErr = errors.New("canal cerrado")
	c.process(t.Context(), d)

	if acks, _, _ := a.contadores(); acks != 1 {
		t.Errorf("se esperaba el intento de ack")
	}
}

func TestRunConsumeConAckManualYTerminaAlCancelarse(t *testing.T) {
	canal := nuevoCanalFalso()
	h := &handlerFalso{}
	c, err := NewConsumer(canal, &dlqFalsa{}, Spec{Queue: colaDePrueba, EventType: tipoDePrueba, MaxRetries: 1, Handler: h}, loggerMudo())
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	d, a := entrega(cuerpoValido(t, uuid.New(), tipoDePrueba), 0)
	canal.entregas <- d

	ctx, cancel := context.WithCancel(t.Context())
	hecho := make(chan error, 1)
	go func() { hecho <- c.Run(ctx) }()

	esperar(t, func() bool { acks, _, _ := a.contadores(); return acks == 1 })
	cancel()

	select {
	case err := <-hecho:
		if err != nil {
			t.Errorf("un apagado pedido no es un error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run no terminó tras cancelar el contexto")
	}

	if len(canal.consumidas) != 1 || canal.consumidas[0] != colaDePrueba {
		t.Errorf("colas consumidas = %v, se esperaba [%s]", canal.consumidas, colaDePrueba)
	}
	if canal.autoAck[0] {
		t.Errorf("auto-ack está prohibido: el ack es manual")
	}
}

func TestRunDevuelveConnectionLostSiElCanalSeCierraSolo(t *testing.T) {
	canal := nuevoCanalFalso()
	c, _ := NewConsumer(canal, &dlqFalsa{}, Spec{Queue: colaDePrueba, EventType: tipoDePrueba, Handler: &handlerFalso{}}, loggerMudo())

	close(canal.entregas)

	if err := c.Run(t.Context()); !errors.Is(err, ErrConnectionLost) {
		t.Errorf("err = %v, se esperaba ErrConnectionLost", err)
	}
}

func TestRunDevuelveElErrorSiNoPuedeConsumir(t *testing.T) {
	canal := nuevoCanalFalso()
	canal.consumeErr = errors.New("NOT_FOUND - no queue")
	c, _ := NewConsumer(canal, &dlqFalsa{}, Spec{Queue: colaDePrueba, EventType: tipoDePrueba, Handler: &handlerFalso{}}, loggerMudo())

	err := c.Run(t.Context())
	if err == nil || !strings.Contains(err.Error(), colaDePrueba) {
		t.Errorf("err = %v, se esperaba un error que nombre la cola", err)
	}
}

func TestNewConsumerRechazaConfiguracionInvalida(t *testing.T) {
	canal, dlq, h := nuevoCanalFalso(), &dlqFalsa{}, &handlerFalso{}
	valido := Spec{Queue: colaDePrueba, EventType: tipoDePrueba, MaxRetries: 1, Handler: h}

	casos := map[string]func() error{
		"sin canal":            func() error { _, err := NewConsumer(nil, dlq, valido, nil); return err },
		"sin dlq":              func() error { _, err := NewConsumer(canal, nil, valido, nil); return err },
		"sin cola":             func() error { s := valido; s.Queue = ""; _, err := NewConsumer(canal, dlq, s, nil); return err },
		"sin eventType":        func() error { s := valido; s.EventType = ""; _, err := NewConsumer(canal, dlq, s, nil); return err },
		"sin handler":          func() error { s := valido; s.Handler = nil; _, err := NewConsumer(canal, dlq, s, nil); return err },
		"reintentos negativos": func() error { s := valido; s.MaxRetries = -1; _, err := NewConsumer(canal, dlq, s, nil); return err },
	}
	for nombre, caso := range casos {
		t.Run(nombre, func(t *testing.T) {
			if err := caso(); err == nil {
				t.Errorf("se esperaba un error")
			}
		})
	}
}

// esperar sondea hasta que cond se cumpla o venza un plazo generoso.
func esperar(t *testing.T, cond func() bool) {
	t.Helper()

	limite := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(limite) {
			t.Fatal("la condición no se cumplió a tiempo")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
