package consumer

import (
	"context"
	"errors"
	"testing"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

func nuevoPublisherDLQ(t *testing.T, canal Channel, timeout time.Duration) *DeadLetterPublisher {
	t.Helper()

	p, err := NewDeadLetterPublisher(canal, timeout)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	return p
}

func TestPublishToDLQUsaLaColaDeTrabajoComoRoutingKey(t *testing.T) {
	canal := nuevoCanalFalso()
	p := nuevoPublisherDLQ(t, canal, time.Second)

	body := []byte(`{"eventId":"x"}`)
	if err := p.PublishToDLQ(t.Context(), colaDePrueba, body, "motivo"); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if len(canal.publicadas) != 1 {
		t.Fatalf("publicaciones = %d, se esperaba 1", len(canal.publicadas))
	}
	pub := canal.publicadas[0]
	if pub.exchange != "vvi.dlq.exchange" {
		t.Errorf("exchange = %q, se esperaba vvi.dlq.exchange", pub.exchange)
	}
	if pub.key != colaDePrueba {
		t.Errorf("routing key = %q, se esperaba el nombre de la cola de trabajo %q", pub.key, colaDePrueba)
	}
	if !pub.mandatory {
		t.Errorf("la publicación en la dlq debe ser mandatory")
	}
	if pub.msg.DeliveryMode != amqp.Persistent {
		t.Errorf("la publicación en la dlq debe ser persistente")
	}
	if string(pub.msg.Body) != string(body) {
		t.Errorf("la dlq debe recibir el cuerpo original")
	}
	if pub.msg.Headers[dlqReasonHeader] != "motivo" {
		t.Errorf("header %s = %v, se esperaba el motivo", dlqReasonHeader, pub.msg.Headers[dlqReasonHeader])
	}
}

func TestPublishToDLQExigeLaColaDeOrigen(t *testing.T) {
	canal := nuevoCanalFalso()
	p := nuevoPublisherDLQ(t, canal, time.Second)

	if err := p.PublishToDLQ(t.Context(), "", []byte("x"), "m"); !errors.Is(err, errDLQQueueRequired) {
		t.Errorf("err = %v, se esperaba errDLQQueueRequired", err)
	}
	if len(canal.publicadas) != 0 {
		t.Errorf("sin cola de origen no debe publicarse nada: quedaría sin ruta")
	}
}

func TestPublishToDLQFallaSiElBrokerNoConfirma(t *testing.T) {
	canal := nuevoCanalFalso()
	canal.confirmacion = confirmacionFalsa{acked: false}
	p := nuevoPublisherDLQ(t, canal, time.Second)

	if err := p.PublishToDLQ(t.Context(), colaDePrueba, []byte("x"), "m"); !errors.Is(err, errDLQNotConfirmed) {
		t.Errorf("err = %v, se esperaba errDLQNotConfirmed", err)
	}
}

// Un canal sin modo confirm devuelve una confirmación nula: no hay garantía de
// que la DLQ lo haya recibido, y el original no debe confirmarse.
func TestPublishToDLQFallaSiElCanalNoEstaEnModoConfirm(t *testing.T) {
	canal := nuevoCanalFalso()
	canal.confirmacion = nil
	p := nuevoPublisherDLQ(t, canal, time.Second)

	if err := p.PublishToDLQ(t.Context(), colaDePrueba, []byte("x"), "m"); !errors.Is(err, errDLQNotConfirmed) {
		t.Errorf("err = %v, se esperaba errDLQNotConfirmed", err)
	}
}

func TestPublishToDLQPropagaLosErroresDelCanal(t *testing.T) {
	causa := errors.New("canal cerrado")

	t.Run("al publicar", func(t *testing.T) {
		canal := nuevoCanalFalso()
		canal.publishErr = causa
		p := nuevoPublisherDLQ(t, canal, time.Second)

		if err := p.PublishToDLQ(t.Context(), colaDePrueba, []byte("x"), "m"); !errors.Is(err, causa) {
			t.Errorf("err = %v, se esperaba la causa envuelta", err)
		}
	})

	t.Run("al esperar la confirmación", func(t *testing.T) {
		canal := nuevoCanalFalso()
		canal.confirmacion = confirmacionFalsa{err: causa}
		p := nuevoPublisherDLQ(t, canal, time.Second)

		if err := p.PublishToDLQ(t.Context(), colaDePrueba, []byte("x"), "m"); !errors.Is(err, causa) {
			t.Errorf("err = %v, se esperaba la causa envuelta", err)
		}
	})
}

// Un broker que nunca confirma no puede colgar al consumidor: el timeout
// explícito corta la espera.
func TestPublishToDLQVenceElTimeoutSiElBrokerNoConfirma(t *testing.T) {
	canal := nuevoCanalFalso()
	canal.confirmacion = confirmacionFalsa{bloquea: true}
	p := nuevoPublisherDLQ(t, canal, 30*time.Millisecond)

	inicio := time.Now()
	err := p.PublishToDLQ(t.Context(), colaDePrueba, []byte("x"), "m")

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, se esperaba context.DeadlineExceeded", err)
	}
	if demora := time.Since(inicio); demora > time.Second {
		t.Errorf("la espera duró %s: el timeout no cortó", demora)
	}
}

func TestNewDeadLetterPublisherValidaSusArgumentos(t *testing.T) {
	if _, err := NewDeadLetterPublisher(nil, time.Second); err == nil {
		t.Errorf("se esperaba un error sin canal")
	}
	if _, err := NewDeadLetterPublisher(nuevoCanalFalso(), 0); err == nil {
		t.Errorf("se esperaba un error con timeout cero: toda llamada saliente lleva timeout explícito")
	}
}
