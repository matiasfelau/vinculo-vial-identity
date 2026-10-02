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
	"net"
	"strings"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// Valores por defecto de la configuración del publisher.
const (
	// DefaultExchange es el topic exchange del contrato de la plataforma. Debe
	// coincidir exactamente con el que declara vinculo-vial-core: ver la nota
	// de declaración pasiva en connect().
	DefaultExchange = "vvi.topic.exchange"
	DefaultProducer = "vinculo-vial-identity"
	// DefaultPublishTimeout acota el intento completo de publish (attempt,
	// reconexión y reintento — ver publishEnvelope y dialWithDeadline). Lo
	// consume el worker del outbox, fuera del camino de cualquier request,
	// así que no suma a la latencia de ningún endpoint.
	DefaultPublishTimeout = 1500 * time.Millisecond
	// DefaultDialTimeout solo rige la conexión inicial en el arranque
	// (NewPublisher): no es parte del presupuesto por petición, así que no
	// comparte el recorte de DefaultPublishTimeout.
	DefaultDialTimeout = 10 * time.Second
	DefaultHeartbeat   = 10 * time.Second
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

// NewPublisher conecta con el broker y verifica que el exchange exista.
//
// Se conecta en el arranque y no de forma perezosa: una URL mal configurada, o
// un exchange que todavía no declaró vinculo-vial-core, tienen que hacer
// fallar el despliegue, no descubrirse recién cuando se registre el primer
// vecino.
func NewPublisher(cfg Config, logger *slog.Logger) (*Publisher, error) {
	if cfg.URL == "" {
		return nil, errors.New("events: falta la URL del broker")
	}
	cfg.applyDefaults()

	if logger == nil {
		logger = slog.Default()
	}

	p := &Publisher{cfg: cfg, logger: logger, now: time.Now}

	// En el arranque no hay un presupuesto de publish del que derivar el
	// deadline del dial (ver dialWithDeadline): DialTimeout es, acá sí, una
	// ventana propia.
	ctx, cancel := context.WithTimeout(context.Background(), cfg.DialTimeout)
	defer cancel()

	if err := p.connect(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

// PublishSessionsRevoked emite el evento con confirmación del broker.
//
// La entrega es persistente y se espera el ack: sin confirmación, un publish
// exitoso solo prueba que el mensaje salió del proceso, no que el broker lo
// haya aceptado, y un reinicio del broker lo perdería en silencio. Toda
// publicación va además con mandatory=true (ver send), como fija el contrato.
func (p *Publisher) PublishSessionsRevoked(ctx context.Context, evt domain.SessionsRevoked) error {
	return p.publishEnvelope(ctx, newSessionsRevokedEnvelope(evt, p.cfg.Producer, p.now()))
}

// publishEnvelope serializa el sobre y lo entrega con confirmación del
// broker. Es el cuerpo común a todo Publish*: el routing key de cada evento
// es su propio EventType, tal como documenta cada constante EventType*.
func (p *Publisher) publishEnvelope(ctx context.Context, envelope Envelope) error {
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

	if err := p.publish(ctx, envelope.EventType, msg); err != nil {
		// Un solo reintento tras reconectar: el fallo más común es una conexión
		// que el broker cerró mientras el servicio estaba ocioso, y en ese caso
		// el segundo intento sobre una conexión nueva funciona.
		p.logger.WarnContext(ctx, "reintentando la publicación sobre una conexión nueva",
			slog.String("error", err.Error()),
		)

		if reconnectErr := p.reconnect(ctx); reconnectErr != nil {
			return fmt.Errorf("events: no se pudo reconectar con el broker: %w", reconnectErr)
		}
		if err := p.publish(ctx, envelope.EventType, msg); err != nil {
			return fmt.Errorf("events: no se pudo publicar %s: %w", envelope.EventType, err)
		}
	}

	return nil
}

func (p *Publisher) publish(ctx context.Context, routingKey string, msg amqp.Publishing) error {
	confirm, err := p.send(ctx, routingKey, msg)
	if err != nil {
		return err
	}

	// La espera de la confirmación queda fuera del mutex: el ack del broker
	// tarda un ida y vuelta de red y retener el canal durante ese tiempo
	// serializaría innecesariamente las publicaciones concurrentes.
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
func (p *Publisher) send(ctx context.Context, routingKey string, msg amqp.Publishing) (*amqp.DeferredConfirmation, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.ch == nil || p.ch.IsClosed() {
		return nil, errors.New("canal cerrado")
	}

	return p.ch.PublishWithDeferredConfirmWithContext(
		ctx,
		p.cfg.Exchange,
		routingKey,
		// mandatory=true, sin excepciones: si ningún binding enruta el mensaje
		// a una cola, el broker lo devuelve (ver watchReturns) en lugar de
		// descartarlo sin dejar rastro. No cambia lo que confirma el
		// publisher confirm: ese ack sigue significando "el broker aceptó el
		// mensaje", nunca "una cola lo recibió"; mandatory es lo que expone
		// esa segunda garantía.
		true,
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

// dialWithDeadline adapta amqp.DefaultDial para que el dial respete el
// presupuesto que quede en ctx, en vez de abrir su propia ventana de tiempo
// independiente de DialTimeout. Sin esto, una reconexión disparada a mitad de
// publishEnvelope podía tardar hasta DialTimeout completo sin importar cuánto
// del PublishTimeout total ya se había consumido, multiplicando la latencia
// de un broker caído muy por encima del presupuesto configurado (contrato de
// resiliencia: el publish completo, reconexión incluida, no debe superar
// PublishTimeout).
// remainingOrFallback calcula la ventana de tiempo disponible para el dial:
// lo que le quede de deadline a ctx, acotado por fallback. El menor de los
// dos manda. Separado de dialWithDeadline para poder probar el cálculo sin
// abrir una conexión de verdad —la conversación de red queda fuera de los
// tests unitarios de este paquete, igual que el resto del protocolo AMQP.
func remainingOrFallback(ctx context.Context, fallback time.Duration) time.Duration {
	timeout := fallback
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}
	return timeout
}

func dialWithDeadline(ctx context.Context, fallback time.Duration) func(network, addr string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		timeout := remainingOrFallback(ctx, fallback)
		if timeout <= 0 {
			return nil, context.DeadlineExceeded
		}

		conn, err := net.DialTimeout(network, addr, timeout)
		if err != nil {
			return nil, err
		}

		// Igual que amqp.DefaultDial: el latido todavía no arrancó, así que se
		// fija un deadline propio para el handshake AMQP/TLS. La librería lo
		// limpia una vez establecida la conexión (openComplete).
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			_ = conn.Close()
			return nil, err
		}

		return conn, nil
	}
}

func (p *Publisher) connect(ctx context.Context) error {
	conn, err := amqp.DialConfig(p.cfg.URL, amqp.Config{
		Heartbeat: p.cfg.Heartbeat,
		Dial:      dialWithDeadline(ctx, p.cfg.DialTimeout),
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

	// Declaración pasiva: este servicio solo publica, nunca declara topología
	// (exchanges, colas, bindings) — eso es responsabilidad exclusiva de
	// vinculo-vial-core. Antes se declaraba el exchange en modo activo, que
	// crea silenciosamente uno propio si el nombre configurado no coincide con
	// el que usa el resto de la plataforma: exactamente el desvío que dejaba
	// perderse user.sessions.revoked sin que ningún log lo delatara. Con
	// declaración pasiva, si el exchange todavía no existe, el arranque falla
	// en lugar de crear uno nuevo.
	if err := ch.ExchangeDeclarePassive(
		p.cfg.Exchange,
		amqp.ExchangeTopic,
		true,  // durable
		false, // no se autoelimina
		false, // no es interno
		false, // se espera la confirmación de la declaración
		nil,
	); err != nil {
		_ = ch.Close()
		_ = conn.Close()
		return fmt.Errorf("events: el exchange %q no existe: la topología la declara vinculo-vial-core, no este servicio: %w", p.cfg.Exchange, err)
	}

	if err := ch.Confirm(false); err != nil {
		_ = ch.Close()
		_ = conn.Close()
		return fmt.Errorf("events: el broker no aceptó el modo de confirmación: %w", err)
	}

	// Con mandatory=true (ver send) el broker devuelve acá cualquier mensaje
	// que no pudo enrutar a ninguna cola, en vez de descartarlo en silencio.
	// Se registra antes de publicar nada y se vuelve a registrar en cada
	// reconexión, porque el canal AMQP anterior cierra este canal de retorno
	// junto con él.
	returns := make(chan amqp.Return, 8)
	ch.NotifyReturn(returns)
	go p.watchReturns(returns)

	p.mu.Lock()
	p.conn, p.ch = conn, ch
	p.mu.Unlock()

	return nil
}

// watchReturns deja constancia en WARN de cada evento que el broker no pudo
// enrutar a ninguna cola. No es un error para el llamador de publishEnvelope
// —el publisher confirm ya se recibió, el broker aceptó el mensaje— pero sí es
// una alerta operativa: significa que Core declaró el exchange sin ningún
// binding para ese routing key, o que el consumidor esperado todavía no
// levantó su cola. Nunca loguea el cuerpo del mensaje, solo los identificadores
// del sobre.
func (p *Publisher) watchReturns(returns <-chan amqp.Return) {
	for ret := range returns {
		p.logger.Warn("el broker no pudo enrutar el evento: ninguna cola lo consume",
			slog.String("event_id", ret.MessageId),
			slog.String("event_type", ret.Type),
			slog.String("routing_key", ret.RoutingKey),
			slog.String("exchange", ret.Exchange),
			slog.Int("reply_code", int(ret.ReplyCode)),
			slog.String("reply_text", ret.ReplyText),
		)
	}
}

func (p *Publisher) reconnect(ctx context.Context) error {
	p.mu.Lock()
	if p.ch != nil {
		_ = p.ch.Close()
	}
	if p.conn != nil {
		_ = p.conn.Close()
	}
	p.ch, p.conn = nil, nil
	p.mu.Unlock()

	return p.connect(ctx)
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
