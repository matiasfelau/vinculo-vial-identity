// Package events publica los eventos de dominio hacia el broker de la
// plataforma.
//
// RabbitMQ es un recurso global y externo a este servicio: no se levanta en su
// docker-compose. Por eso conviven dos implementaciones del puerto
// domain.EventPublisher, la real y NoopPublisher.
package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// Valores por defecto de la configuración del publisher.
const (
	DefaultExchange       = "vinculo-vial.events"
	DefaultProducer       = "vinculo-vial-identity"
	DefaultPublishTimeout = 5 * time.Second
	DefaultDialTimeout    = 10 * time.Second
	DefaultHeartbeat      = 10 * time.Second
)

// Config son los parámetros de conexión y publicación.
type Config struct {
	// URL es la cadena amqp:// o amqps:// del broker.
	URL string
	// Exchange es el topic exchange de la plataforma.
	Exchange string
	// Producer identifica a este servicio dentro del sobre del evento.
	Producer string
	// PublishTimeout acota la espera de la confirmación del broker. Vencido el
	// plazo, la publicación se da por fallida y el caso de uso sigue adelante.
	PublishTimeout time.Duration
	// DialTimeout acota el establecimiento de la conexión.
	DialTimeout time.Duration
	// Heartbeat es el latido de la conexión AMQP; permite detectar un broker
	// caído sin esperar al timeout de TCP.
	Heartbeat time.Duration
}

func (c *Config) applyDefaults() {
	if c.Exchange == "" {
		c.Exchange = DefaultExchange
	}
	if c.Producer == "" {
		c.Producer = DefaultProducer
	}
	if c.PublishTimeout <= 0 {
		c.PublishTimeout = DefaultPublishTimeout
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = DefaultDialTimeout
	}
	if c.Heartbeat <= 0 {
		c.Heartbeat = DefaultHeartbeat
	}
}

// Publisher implementa domain.EventPublisher sobre RabbitMQ.
//
// Es seguro para uso concurrente: un canal AMQP no lo es, así que las
// publicaciones se serializan con un mutex. Para el volumen de altas de US-01 es
// más que suficiente; si el throughput lo exigiera, el paso siguiente es un pool
// de canales, no compartir uno sin protección.
type Publisher struct {
	cfg    Config
	logger *slog.Logger
	now    func() time.Time

	mu   sync.Mutex
	conn *amqp.Connection
	ch   *amqp.Channel
}

// NewPublisher conecta con el broker y declara el exchange.
//
// Se conecta en el arranque y no de forma perezosa: una URL mal configurada
// tiene que hacer fallar el despliegue, no descubrirse recién cuando se
// registre el primer vecino.
func NewPublisher(cfg Config, logger *slog.Logger) (*Publisher, error) {
	if cfg.URL == "" {
		return nil, errors.New("events: falta la URL del broker")
	}
	cfg.applyDefaults()

	if logger == nil {
		logger = slog.Default()
	}

	p := &Publisher{cfg: cfg, logger: logger, now: time.Now}

	if err := p.connect(); err != nil {
		return nil, err
	}
	return p, nil
}

// PublishUserRegistered emite el evento con confirmación del broker.
//
// La entrega es persistente y se espera el ack: sin confirmación, un publish
// exitoso solo prueba que el mensaje salió del proceso, no que el broker lo
// haya aceptado, y un reinicio del broker lo perdería en silencio.
func (p *Publisher) PublishUserRegistered(ctx context.Context, evt domain.UserRegistered) error {
	envelope := newEnvelope(evt, p.cfg.Producer, p.now())

	body, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("events: no se pudo serializar el evento: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, p.cfg.PublishTimeout)
	defer cancel()

	msg := amqp.Publishing{
		ContentType: "application/json",
		// Persistente: el mensaje sobrevive a un reinicio del broker.
		DeliveryMode: amqp.Persistent,
		MessageId:    envelope.EventID,
		Type:         envelope.EventType,
		AppId:        envelope.Producer,
		Timestamp:    p.now().UTC(),
		Body:         body,
	}

	if err := p.publish(ctx, msg); err != nil {
		// Un solo reintento tras reconectar: el fallo más común es una conexión
		// que el broker cerró mientras el servicio estaba ocioso, y en ese caso
		// el segundo intento sobre una conexión nueva funciona.
		p.logger.WarnContext(ctx, "reintentando la publicación sobre una conexión nueva",
			slog.String("error", err.Error()),
		)

		if reconnectErr := p.reconnect(); reconnectErr != nil {
			return fmt.Errorf("events: no se pudo reconectar con el broker: %w", reconnectErr)
		}
		if err := p.publish(ctx, msg); err != nil {
			return fmt.Errorf("events: no se pudo publicar %s: %w", envelope.EventType, err)
		}
	}

	return nil
}

func (p *Publisher) publish(ctx context.Context, msg amqp.Publishing) error {
	confirm, err := p.send(ctx, msg)
	if err != nil {
		return err
	}

	// La espera de la confirmación queda fuera del mutex: el ack del broker
	// tarda un ida y vuelta de red y retener el canal durante ese tiempo
	// serializaría innecesariamente las altas concurrentes.
	acked, err := confirm.WaitContext(ctx)
	if err != nil {
		return err
	}
	if !acked {
		return errors.New("el broker rechazó el mensaje (nack)")
	}
	return nil
}

// send escribe en el canal AMQP, que no es seguro para uso concurrente.
func (p *Publisher) send(ctx context.Context, msg amqp.Publishing) (*amqp.DeferredConfirmation, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.ch == nil || p.ch.IsClosed() {
		return nil, errors.New("canal cerrado")
	}

	return p.ch.PublishWithDeferredConfirmWithContext(
		ctx,
		p.cfg.Exchange,
		EventTypeUserRegistered,
		// mandatory=false: que hoy no haya cola atada al routing key es una
		// decisión de los consumidores, no un fallo del alta.
		false,
		false,
		msg,
	)
}

// scrubURL evita que la URL del broker —que lleva usuario y contraseña— llegue
// al log a través del error del driver.
func scrubURL(err error, url string) error {
	if err == nil || url == "" {
		return err
	}

	msg := err.Error()
	if !strings.Contains(msg, url) {
		return err
	}
	return errors.New(strings.ReplaceAll(msg, url, "[url omitida]"))
}

func (p *Publisher) connect() error {
	conn, err := amqp.DialConfig(p.cfg.URL, amqp.Config{
		Heartbeat: p.cfg.Heartbeat,
		Dial:      amqp.DefaultDial(p.cfg.DialTimeout),
	})
	if err != nil {
		// La URL lleva las credenciales del broker; nunca se incluye en el error.
		return fmt.Errorf("events: no se pudo conectar con el broker: %w", scrubURL(err, p.cfg.URL))
	}

	ch, err := conn.Channel()
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("events: no se pudo abrir el canal: %w", err)
	}

	if err := ch.ExchangeDeclare(
		p.cfg.Exchange,
		amqp.ExchangeTopic,
		true,  // durable: sobrevive al reinicio del broker
		false, // no se autoelimina cuando no hay colas atadas
		false, // no es interno
		false, // se espera la confirmación de la declaración
		nil,
	); err != nil {
		_ = ch.Close()
		_ = conn.Close()
		return fmt.Errorf("events: no se pudo declarar el exchange %q: %w", p.cfg.Exchange, err)
	}

	if err := ch.Confirm(false); err != nil {
		_ = ch.Close()
		_ = conn.Close()
		return fmt.Errorf("events: el broker no aceptó el modo de confirmación: %w", err)
	}

	p.mu.Lock()
	p.conn, p.ch = conn, ch
	p.mu.Unlock()

	return nil
}

func (p *Publisher) reconnect() error {
	p.mu.Lock()
	if p.ch != nil {
		_ = p.ch.Close()
	}
	if p.conn != nil {
		_ = p.conn.Close()
	}
	p.ch, p.conn = nil, nil
	p.mu.Unlock()

	return p.connect()
}

// Close libera el canal y la conexión.
func (p *Publisher) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var errs []error
	if p.ch != nil {
		if err := p.ch.Close(); err != nil {
			errs = append(errs, err)
		}
		p.ch = nil
	}
	if p.conn != nil {
		if err := p.conn.Close(); err != nil {
			errs = append(errs, err)
		}
		p.conn = nil
	}
	return errors.Join(errs...)
}
