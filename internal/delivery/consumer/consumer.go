package consumer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"

	amqp "github.com/rabbitmq/amqp091-go"
)

// ErrConnectionLost indica que el canal de deliveries se cerró sin que el
// contexto estuviera cancelado: el broker o la conexión cayeron. Quien
// orquesta el ciclo de vida (Run) distingue así una caída, que reconecta, de un
// apagado pedido.
var ErrConnectionLost = errors.New("consumer: se perdió la conexión con rabbitmq")

// Handler procesa un evento cuyo sobre ya pasó la validación mínima.
//
// El resultado decide el destino del mensaje: nil lo confirma (ack); un error
// que cumple errors.Is(err, ErrPermanent) lo deriva directo a la DLQ; cualquier
// otro error es transitorio y lo manda a la cola de reintento hasta agotar
// MaxRetries.
//
// La entrega es at-least-once: un mismo mensaje puede llegar más de una vez, y
// el handler tiene que ser idempotente.
type Handler interface {
	Handle(ctx context.Context, envelope Envelope) error
}

// Spec describe qué consume un Consumer.
type Spec struct {
	// Queue es el nombre de la cola de trabajo. También es la routing key con
	// que se publica en su DLQ y la cola cuyo x-death cuenta los reintentos.
	Queue string
	// EventType es el único eventType admitido en la cola: un sobre con otro
	// tipo es un mensaje inválido.
	EventType string
	// MaxRetries es la cantidad máxima de reintentos de un fallo transitorio.
	// Agotada, el mensaje se deriva a la DLQ.
	MaxRetries int
	Handler    Handler
}

// Consumer consume una cola y aplica la decisión del handler sobre cada
// delivery. El ack es siempre manual: la cola se consume con autoAck en false.
type Consumer struct {
	channel Channel
	dlq     deadLetterPublisher
	spec    Spec
	logger  *slog.Logger
}

func (s Spec) validate() error {
	switch {
	case s.Queue == "":
		return errors.New("consumer: falta el nombre de la cola")
	case s.EventType == "":
		return errors.New("consumer: falta el eventType esperado")
	case s.MaxRetries < 0:
		return errors.New("consumer: MaxRetries no puede ser negativo")
	case s.Handler == nil:
		return errors.New("consumer: falta el handler")
	}
	return nil
}

// NewConsumer construye un Consumer sobre un canal ya configurado.
func NewConsumer(channel Channel, dlq deadLetterPublisher, spec Spec, logger *slog.Logger) (*Consumer, error) {
	if channel == nil {
		return nil, errors.New("consumer: falta el canal")
	}
	if dlq == nil {
		return nil, errors.New("consumer: falta el publisher de la dlq")
	}
	if err := spec.validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &Consumer{
		channel: channel,
		dlq:     dlq,
		spec:    spec,
		logger:  logger.With(slog.String("queue", spec.Queue)),
	}, nil
}

// Run consume la cola hasta que el contexto se cancela o el canal se cierra.
// Procesa de a un mensaje: cuando ctx se cancela, termina el mensaje en curso
// antes de volver, y los que el broker había adelantado por el prefetch y no se
// procesaron vuelven a la cola al cerrarse el canal. Devuelve ErrConnectionLost
// si el canal cayó sin que se pidiera el apagado.
func (c *Consumer) Run(ctx context.Context) error {
	deliveries, err := c.channel.Consume(c.spec.Queue, "", false, false, false, false, nil)
	if err != nil {
		return fmt.Errorf("consumer: no se pudo consumir %s: %w", c.spec.Queue, err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case delivery, ok := <-deliveries:
			if !ok {
				if ctx.Err() != nil {
					return nil
				}
				return ErrConnectionLost
			}
			c.process(ctx, delivery)
		}
	}
}

// outcome es lo que se le dice al broker sobre un delivery.
type outcome int

const (
	// outcomeAck confirma el mensaje: se procesó, o ya quedó en la DLQ.
	outcomeAck outcome = iota
	// outcomeNack lo rechaza sin reencolarlo en caliente: la cola de trabajo lo
	// manda a su cola de reintento, que lo devuelve tras el TTL.
	outcomeNack
)

func (c *Consumer) process(ctx context.Context, delivery amqp.Delivery) {
	switch c.decide(ctx, delivery) {
	case outcomeAck:
		if err := delivery.Ack(false); err != nil {
			// El mensaje se va a reentregar: el handler es idempotente.
			c.logger.ErrorContext(ctx, "no se pudo confirmar el mensaje", slog.String("error", err.Error()))
		}
	case outcomeNack:
		if err := delivery.Nack(false, false); err != nil {
			c.logger.ErrorContext(ctx, "no se pudo rechazar el mensaje", slog.String("error", err.Error()))
		}
	}
}

// decide clasifica el resultado del procesamiento. Nunca loguea el cuerpo del
// mensaje: solo los identificadores del sobre.
func (c *Consumer) decide(ctx context.Context, delivery amqp.Delivery) outcome {
	envelope, err := ParseEnvelope(delivery.Body)
	if err == nil && envelope.EventType != c.spec.EventType {
		err = Permanent(fmt.Errorf("eventType inesperado para la cola: %q", envelope.EventType))
	}
	if err != nil {
		return c.deadLetter(ctx, delivery.Body, "", err)
	}

	eventID := envelope.EventID.String()

	err = c.handle(ctx, envelope)
	switch {
	case err == nil:
		return outcomeAck
	case errors.Is(err, ErrPermanent):
		return c.deadLetter(ctx, delivery.Body, eventID, err)
	}

	retries := deathCount(delivery.Headers, c.spec.Queue)
	if retries >= int64(c.spec.MaxRetries) {
		return c.deadLetter(ctx, delivery.Body, eventID, fmt.Errorf("se agotaron los %d reintentos: %w", c.spec.MaxRetries, err))
	}

	c.logger.WarnContext(ctx, "fallo transitorio: el mensaje va a la cola de reintento",
		slog.String("event_id", eventID),
		slog.Int64("retries", retries),
		slog.Int("max_retries", c.spec.MaxRetries),
		slog.String("error", err.Error()),
	)
	return outcomeNack
}

// handle invoca al handler y convierte un panic en un fallo permanente: un
// handler que entra en pánico con un mensaje lo hará siempre con ese mensaje,
// y no puede tumbar el proceso consumidor.
func (c *Consumer) handle(ctx context.Context, envelope Envelope) (err error) {
	defer func() {
		if r := recover(); r != nil {
			c.logger.ErrorContext(ctx, "panic en el handler",
				slog.String("event_id", envelope.EventID.String()),
				slog.Any("panic", r),
				slog.String("stack", string(debug.Stack())),
			)
			err = Permanent(fmt.Errorf("panic en el handler: %v", r))
		}
	}()
	return c.spec.Handler.Handle(ctx, envelope)
}

// deadLetter publica el mensaje en la DLQ y solo confirma el original si el
// broker confirmó la publicación. Si la DLQ falla, el original se rechaza y
// vuelve por la cola de reintento: nunca se pierde un mensaje por no poder
// derivarlo.
func (c *Consumer) deadLetter(ctx context.Context, body []byte, eventID string, cause error) outcome {
	c.logger.ErrorContext(ctx, "mensaje derivado a la dlq",
		slog.String("event_id", eventID),
		slog.String("error", cause.Error()),
	)

	if err := c.dlq.PublishToDLQ(ctx, c.spec.Queue, body, cause.Error()); err != nil {
		c.logger.ErrorContext(ctx, "no se pudo publicar en la dlq: el mensaje se reintenta",
			slog.String("event_id", eventID),
			slog.String("error", err.Error()),
		)
		return outcomeNack
	}
	return outcomeAck
}
