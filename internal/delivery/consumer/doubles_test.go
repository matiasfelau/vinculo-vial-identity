package consumer

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

const (
	colaDePrueba = "identity.alert-rejected.q"
	tipoDePrueba = "alert.rejected"
)

// loggerMudo descarta los logs de las pruebas que no los inspeccionan.
func loggerMudo() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// acker registra qué le dijo el consumidor al broker sobre un delivery.
type acker struct {
	mu       sync.Mutex
	acks     int
	nacks    int
	requeues int
	ackErr   error
}

func (a *acker) Ack(uint64, bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.acks++
	return a.ackErr
}

func (a *acker) Nack(_ uint64, _, requeue bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.nacks++
	if requeue {
		a.requeues++
	}
	return nil
}

func (a *acker) Reject(uint64, bool) error { return nil }

func (a *acker) contadores() (acks, nacks, requeues int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.acks, a.nacks, a.requeues
}

// cuerpoValido arma el cuerpo de un evento bien formado.
func cuerpoValido(t *testing.T, eventID uuid.UUID, eventType string) []byte {
	t.Helper()

	actor := uuid.NewString()
	body, err := json.Marshal(map[string]any{
		"eventId":   eventID.String(),
		"eventType": eventType,
		"actor":     actor,
		"payload":   map[string]any{"alert_id": uuid.NewString()},
	})
	if err != nil {
		t.Fatalf("no se pudo armar el cuerpo: %v", err)
	}
	return body
}

// entrega arma un delivery con su acker de prueba y, si retries > 0, el header
// x-death que RabbitMQ agregaría tras esa cantidad de rechazos en la cola.
func entrega(body []byte, retries int64) (amqp.Delivery, *acker) {
	return entregaDeCola(colaDePrueba, body, retries)
}

// entregaDeCola es entrega para una cola de trabajo específica: el x-death
// cuenta los rechazos de esa cola, que es la única que mira el consumidor.
func entregaDeCola(cola string, body []byte, retries int64) (amqp.Delivery, *acker) {
	a := &acker{}
	headers := amqp.Table{}
	if retries > 0 {
		headers["x-death"] = []any{
			amqp.Table{"queue": cola, "reason": "rejected", "count": retries},
		}
	}
	return amqp.Delivery{Acknowledger: a, DeliveryTag: 1, Headers: headers, Body: body}, a
}

// handlerFalso devuelve el resultado programado y cuenta las invocaciones.
type handlerFalso struct {
	mu       sync.Mutex
	llamadas int
	vistos   []Envelope
	err      error
	panico   any
}

func (h *handlerFalso) Handle(_ context.Context, envelope Envelope) error {
	h.mu.Lock()
	h.llamadas++
	h.vistos = append(h.vistos, envelope)
	h.mu.Unlock()

	if h.panico != nil {
		panic(h.panico)
	}
	return h.err
}

func (h *handlerFalso) cantidad() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.llamadas
}

// dlqFalsa registra lo que se derivó a la DLQ.
type dlqFalsa struct {
	mu       sync.Mutex
	colas    []string
	cuerpos  [][]byte
	motivos  []string
	err      error
	llamadas int
}

func (d *dlqFalsa) PublishToDLQ(_ context.Context, queue string, body []byte, reason string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.llamadas++
	if d.err != nil {
		return d.err
	}
	d.colas = append(d.colas, queue)
	d.cuerpos = append(d.cuerpos, body)
	d.motivos = append(d.motivos, reason)
	return nil
}

func (d *dlqFalsa) derivados() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.colas)
}

// confirmacionFalsa resuelve WaitContext con un resultado programado, o espera
// a que venza el contexto si bloquea es true.
type confirmacionFalsa struct {
	acked   bool
	err     error
	bloquea bool
}

func (c confirmacionFalsa) WaitContext(ctx context.Context) (bool, error) {
	if c.bloquea {
		<-ctx.Done()
		return false, ctx.Err()
	}
	return c.acked, c.err
}

// publicacion es lo que recibió PublishWithDeferredConfirmWithContext.
type publicacion struct {
	exchange  string
	key       string
	mandatory bool
	msg       amqp.Publishing
}

// canalFalso implementa Channel sin broker.
type canalFalso struct {
	mu sync.Mutex

	entregas     chan amqp.Delivery
	consumeErr   error
	consumidas   []string
	autoAck      []bool
	publicadas   []publicacion
	confirmacion deferredConfirmation
	publishErr   error

	qosErr      error
	qosPrefetch int
	qosLlamado  bool
	confirmErr  error
	confirmado  bool
	retornos    chan amqp.Return
	cerrado     bool
}

func nuevoCanalFalso() *canalFalso {
	return &canalFalso{
		entregas:     make(chan amqp.Delivery, 16),
		confirmacion: confirmacionFalsa{acked: true},
	}
}

func (c *canalFalso) Consume(queue, _ string, autoAck, _, _, _ bool, _ amqp.Table) (<-chan amqp.Delivery, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.consumidas = append(c.consumidas, queue)
	c.autoAck = append(c.autoAck, autoAck)
	if c.consumeErr != nil {
		return nil, c.consumeErr
	}
	return c.entregas, nil
}

func (c *canalFalso) PublishWithDeferredConfirmWithContext(_ context.Context, exchange, key string, mandatory, _ bool, msg amqp.Publishing) (deferredConfirmation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.publishErr != nil {
		return nil, c.publishErr
	}
	c.publicadas = append(c.publicadas, publicacion{exchange: exchange, key: key, mandatory: mandatory, msg: msg})
	return c.confirmacion, nil
}

func (c *canalFalso) Qos(prefetch, _ int, _ bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.qosLlamado = true
	c.qosPrefetch = prefetch
	return c.qosErr
}

func (c *canalFalso) Confirm(bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.confirmado = c.confirmErr == nil
	return c.confirmErr
}

func (c *canalFalso) NotifyReturn(ch chan amqp.Return) chan amqp.Return {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.retornos = ch
	return ch
}

func (c *canalFalso) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cerrado = true
	return nil
}

var errBase = errors.New("la base no responde")
