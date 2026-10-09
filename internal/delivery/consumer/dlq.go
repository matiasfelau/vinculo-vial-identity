package consumer

import (
	"context"
	"errors"
	"fmt"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// DLQExchange es el exchange de dead letter de la plataforma. Es un nombre fijo
// de la topología, igual que los nombres de cola: no varía entre entornos y no
// se declara desde acá (lo hace vinculo-vial-core).
const DLQExchange = "vvi.dlq.exchange"

// dlqReasonHeader lleva el motivo del descarte en el mensaje de la DLQ.
const dlqReasonHeader = "x-discard-reason"

var (
	// errDLQNotConfirmed se devuelve cuando el broker no confirmó la
	// publicación a la DLQ (nack del publisher confirm) o el canal no está en
	// modo confirm. En ambos casos no hay garantía de que el mensaje haya
	// quedado persistido: el llamador no debe hacer ack del original.
	errDLQNotConfirmed = errors.New("la dlq no confirmó la publicación")

	// errDLQQueueRequired se devuelve cuando no se informa la cola de origen.
	// La DLQ está bindeada por el nombre de la cola de trabajo: publicar con
	// otra routing key, o vacía, dejaría el mensaje sin ruta.
	errDLQQueueRequired = errors.New("la cola de origen es obligatoria para publicar en la dlq")
)

// deadLetterPublisher deriva un mensaje a la DLQ de la cola de trabajo.
type deadLetterPublisher interface {
	PublishToDLQ(ctx context.Context, queue string, body []byte, reason string) error
}

// DeadLetterPublisher publica directo al exchange de dead letter, salteando el
// ciclo de reintentos. No declara exchanges, colas ni bindings: solo publica
// sobre topología preexistente.
type DeadLetterPublisher struct {
	channel Channel
	timeout time.Duration
}

var _ deadLetterPublisher = (*DeadLetterPublisher)(nil)

// NewDeadLetterPublisher construye el publisher. timeout acota la publicación
// completa, incluida la espera de la confirmación del broker. El canal debe
// estar en modo confirm (ver configureChannel).
func NewDeadLetterPublisher(channel Channel, timeout time.Duration) (*DeadLetterPublisher, error) {
	if channel == nil {
		return nil, errors.New("consumer: falta el canal de la dlq")
	}
	if timeout <= 0 {
		return nil, errors.New("consumer: el timeout de la dlq debe ser positivo")
	}
	return &DeadLetterPublisher{channel: channel, timeout: timeout}, nil
}

// PublishToDLQ publica el mensaje en vvi.dlq.exchange con la routing key igual
// al nombre de la cola de trabajo de la que proviene (queue), que es por lo que
// está bindeada su DLQ. Lo publica persistente y con mandatory=true, y espera la
// confirmación del broker antes de devolver éxito: sin ella el llamador no
// puede hacer ack del original.
//
// Un mensaje mandatory que el broker no puede rutear, por ejemplo con una DLQ
// sin cola bindeada, igual recibe el ack del confirm: el confirm certifica que
// el broker procesó la publicación, no que la ruteó. Esa situación se reporta
// aparte por NotifyReturn (ver logUnroutable), no como error de esta llamada.
func (p *DeadLetterPublisher) PublishToDLQ(ctx context.Context, queue string, body []byte, reason string) error {
	if queue == "" {
		return errDLQQueueRequired
	}

	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	confirmation, err := p.channel.PublishWithDeferredConfirmWithContext(ctx, DLQExchange, queue, true, false, amqp.Publishing{
		ContentType:  "application/json",
		DeliveryMode: amqp.Persistent,
		Body:         body,
		Headers:      amqp.Table{dlqReasonHeader: reason},
	})
	if err != nil {
		return fmt.Errorf("no se pudo publicar en la dlq: %w", err)
	}
	if confirmation == nil {
		return errDLQNotConfirmed
	}

	acked, err := confirmation.WaitContext(ctx)
	if err != nil {
		return fmt.Errorf("no se recibió la confirmación de la dlq: %w", err)
	}
	if !acked {
		return errDLQNotConfirmed
	}
	return nil
}
