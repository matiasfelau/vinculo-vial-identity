package consumer

import (
	"context"

	amqp "github.com/rabbitmq/amqp091-go"
)

// deferredConfirmation es el subconjunto de *amqp.DeferredConfirmation que usa
// este paquete. amqp091-go no expone un constructor público para ese tipo, así
// que sin esta interfaz no habría forma de armar un doble de prueba que
// resuelva WaitContext sin un broker real.
type deferredConfirmation interface {
	WaitContext(ctx context.Context) (bool, error)
}

var _ deferredConfirmation = (*amqp.DeferredConfirmation)(nil)

// Channel es el subconjunto de *amqp.Channel que consume este paquete: lo que
// configureChannel aplica al abrir la conexión (Qos, Confirm, NotifyReturn) más
// lo que necesitan el consumidor y el publisher de la DLQ.
type Channel interface {
	Consume(queue, consumer string, autoAck, exclusive, noLocal, noWait bool, args amqp.Table) (<-chan amqp.Delivery, error)
	PublishWithDeferredConfirmWithContext(ctx context.Context, exchange, key string, mandatory, immediate bool, msg amqp.Publishing) (deferredConfirmation, error)
	Qos(prefetchCount, prefetchSize int, global bool) error
	Confirm(noWait bool) error
	NotifyReturn(c chan amqp.Return) chan amqp.Return
	Close() error
}

// realChannel adapta *amqp.Channel a Channel. El método real de publicación
// devuelve el tipo concreto *amqp.DeferredConfirmation, y Go no deja que un
// tipo satisfaga una interfaz cuyo método devuelve otro tipo, aunque este lo
// implemente. El resto de los métodos se promueven sin cambios.
type realChannel struct {
	*amqp.Channel
}

func (c realChannel) PublishWithDeferredConfirmWithContext(ctx context.Context, exchange, key string, mandatory, immediate bool, msg amqp.Publishing) (deferredConfirmation, error) {
	confirmation, err := c.Channel.PublishWithDeferredConfirmWithContext(ctx, exchange, key, mandatory, immediate, msg)
	// Un *amqp.DeferredConfirmation nil asignado directo a la interfaz sería un
	// valor no nil que envuelve un puntero nil, y el publisher de la DLQ dejaría
	// de poder detectar con == nil el caso que documenta el SDK: el canal no
	// está en modo confirm.
	if confirmation == nil {
		return nil, err
	}
	return confirmation, err
}

var _ Channel = realChannel{}
