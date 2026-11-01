// Package consumer consume eventos de RabbitMQ con ack manual, reintentos
// acotados y derivación a la DLQ.
//
// Este servicio solo consume sobre topología existente: las colas de trabajo,
// su cola de reintento y su DLQ las declara vinculo-vial-core, y nada acá las
// declara. El reintento y la DLQ se rutean por el nombre de la cola de trabajo,
// nunca por la routing key del evento, para que un reintento no se reentregue a
// los demás consumidores del mismo evento.
package consumer

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// ErrPermanent clasifica un fallo que reintentar no arregla: un mensaje que no
// se puede deserializar o validar, una regla de negocio violada o un panic del
// handler. Un mensaje que falla con ErrPermanent va directo a la DLQ, sin
// pasar por la cola de reintento. Cualquier otro error se trata como
// transitorio.
var ErrPermanent = errors.New("fallo permanente")

// Permanent marca cause como permanente: errors.Is(err, ErrPermanent) es true
// y cause sigue siendo alcanzable con errors.Is y errors.As.
func Permanent(cause error) error {
	return fmt.Errorf("%w: %w", ErrPermanent, cause)
}

// Envelope es el sobre estándar de eventos de la plataforma, tal como lo
// recibe un consumidor. Solo declara los campos que se usan: el resto
// (timestamp, producer) se ignora.
type Envelope struct {
	EventID   uuid.UUID `json:"eventId"`
	EventType string    `json:"eventType"`
	// Actor es nulo para los hechos del sistema. Qué significa un actor nulo
	// lo decide cada handler.
	Actor *string `json:"actor"`
	// Payload queda sin interpretar: cada handler lo valida contra el esquema
	// de su evento.
	Payload json.RawMessage `json:"payload"`
}

// ParseEnvelope decodifica el sobre y valida el mínimo indispensable para
// procesarlo. Todo error es permanente: reintentar no cambia el resultado.
func ParseEnvelope(body []byte) (Envelope, error) {
	var envelope Envelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return Envelope{}, Permanent(fmt.Errorf("sobre ilegible: %w", err))
	}
	if envelope.EventID == uuid.Nil {
		return Envelope{}, Permanent(errors.New("sobre sin eventId"))
	}
	if envelope.EventType == "" {
		return Envelope{}, Permanent(errors.New("sobre sin eventType"))
	}
	return envelope, nil
}
