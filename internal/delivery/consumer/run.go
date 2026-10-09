package consumer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// Backoff de la reconexión. Acota la espera entre intentos tras una caída del
// broker; no es parte del presupuesto de ningún request.
const (
	minReconnectBackoff = time.Second
	maxReconnectBackoff = 30 * time.Second
)

// returnsBuffer es el tamaño del canal donde el broker devuelve los mensajes
// mandatory que no pudo rutear. Solo los publica la DLQ, de a uno por vez.
const returnsBuffer = 8

// Settings son los parámetros de conexión comunes a todos los consumidores.
type Settings struct {
	// URL es la cadena amqp:// o amqps:// del broker. Lleva credenciales: nunca
	// se loguea.
	URL string
	// Prefetch acota, vía basic.qos, cuántos mensajes sin ack puede tener en
	// vuelo el canal. Sin tope el broker empuja toda la cola al proceso.
	Prefetch int
	// DialTimeout acota el establecimiento de la conexión.
	DialTimeout time.Duration
	// Heartbeat es el latido de la conexión AMQP; permite detectar un broker
	// caído sin esperar al timeout de TCP.
	Heartbeat time.Duration
	// PublishTimeout acota la publicación en la DLQ, confirmación incluida.
	PublishTimeout time.Duration
}

func (s Settings) validate() error {
	switch {
	case s.URL == "":
		return errors.New("consumer: falta la URL del broker")
	case s.Prefetch < 1 || s.Prefetch > 65535:
		return fmt.Errorf("consumer: el prefetch debe estar entre 1 y 65535, se recibió %d", s.Prefetch)
	case s.DialTimeout <= 0:
		return errors.New("consumer: el timeout de conexión debe ser positivo")
	case s.Heartbeat <= 0:
		return errors.New("consumer: el heartbeat debe ser positivo")
	case s.PublishTimeout <= 0:
		return errors.New("consumer: el timeout de la dlq debe ser positivo")
	}
	return nil
}

// dialFunc abre una conexión y un canal ya configurados. closer libera la
// conexión. Se inyecta para poder probar la reconexión sin un broker.
type dialFunc func() (closer io.Closer, channel Channel, err error)

// Run mantiene vivo un consumidor ante caídas del broker, con una conexión
// dedicada: al perderse el canal espera un backoff exponencial acotado y
// reabre, sin declarar topología. Bloquea hasta que ctx se cancela, y para
// entonces ya terminó de procesar el mensaje en curso.
func Run(ctx context.Context, settings Settings, spec Spec, logger *slog.Logger) error {
	if err := settings.validate(); err != nil {
		return err
	}
	if err := spec.validate(); err != nil {
		return err
	}
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With(slog.String("queue", spec.Queue))

	dial := func() (io.Closer, Channel, error) { return dialAMQP(settings, logger) }
	return runWithReconnect(ctx, dial, settings.PublishTimeout, spec, logger, minReconnectBackoff, maxReconnectBackoff)
}

func runWithReconnect(ctx context.Context, dial dialFunc, publishTimeout time.Duration, spec Spec, logger *slog.Logger, minBackoff, maxBackoff time.Duration) error {
	backoff := minBackoff

	for ctx.Err() == nil {
		conn, channel, err := dial()
		if err != nil {
			logger.ErrorContext(ctx, "no se pudo conectar con rabbitmq", slog.String("error", err.Error()))
		} else {
			backoff = minBackoff

			runErr := runOnce(ctx, channel, publishTimeout, spec, logger)

			if err := channel.Close(); err != nil {
				logger.DebugContext(ctx, "no se pudo cerrar el canal", slog.String("error", err.Error()))
			}
			if err := conn.Close(); err != nil {
				logger.DebugContext(ctx, "no se pudo cerrar la conexión", slog.String("error", err.Error()))
			}

			if runErr != nil {
				logger.ErrorContext(ctx, "el consumidor se interrumpió, se reconecta", slog.String("error", runErr.Error()))
			}
		}

		if !sleepOrDone(ctx, backoff) {
			return nil
		}
		backoff = min(backoff*2, maxBackoff)
	}
	return nil
}

// runOnce arma el consumidor sobre un canal recién abierto y lo corre hasta que
// el canal cae o ctx se cancela.
func runOnce(ctx context.Context, channel Channel, publishTimeout time.Duration, spec Spec, logger *slog.Logger) error {
	dlq, err := NewDeadLetterPublisher(channel, publishTimeout)
	if err != nil {
		return err
	}
	consumer, err := NewConsumer(channel, dlq, spec, logger)
	if err != nil {
		return err
	}
	return consumer.Run(ctx)
}

func dialAMQP(settings Settings, logger *slog.Logger) (io.Closer, Channel, error) {
	conn, err := amqp.DialConfig(settings.URL, amqp.Config{
		Heartbeat: settings.Heartbeat,
		Dial:      amqp.DefaultDial(settings.DialTimeout),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("no se pudo abrir la conexión: %w", scrubURL(err, settings.URL))
	}

	raw, err := conn.Channel()
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("no se pudo abrir el canal: %w", err)
	}

	channel := realChannel{Channel: raw}
	if err := configureChannel(channel, settings.Prefetch, logger); err != nil {
		_ = channel.Close()
		_ = conn.Close()
		return nil, nil, err
	}
	return conn, channel, nil
}

// configureChannel aplica sobre el canal lo que todo consumidor necesita:
// prefetch acotado, modo confirm (que exige la publicación en la DLQ) y el
// listener de devoluciones. Separado de dialAMQP para probarlo con un doble.
func configureChannel(channel Channel, prefetch int, logger *slog.Logger) error {
	if err := channel.Qos(prefetch, 0, false); err != nil {
		return fmt.Errorf("no se pudo fijar el prefetch: %w", err)
	}
	if err := channel.Confirm(false); err != nil {
		return fmt.Errorf("el broker no aceptó el modo de confirmación: %w", err)
	}

	go logUnroutable(channel.NotifyReturn(make(chan amqp.Return, returnsBuffer)), logger)
	return nil
}

// logUnroutable deja constancia de cada mensaje mandatory que el broker no pudo
// rutear, por ejemplo una DLQ sin cola bindeada: un problema de topología que
// este servicio no declara y no puede resolver. Nunca loguea el cuerpo. Termina
// sola cuando el canal se cierra.
func logUnroutable(returns <-chan amqp.Return, logger *slog.Logger) {
	for ret := range returns {
		logger.Warn("el broker devolvió un mensaje que no pudo rutear",
			slog.String("exchange", ret.Exchange),
			slog.String("routing_key", ret.RoutingKey),
			slog.Int("reply_code", int(ret.ReplyCode)),
			slog.String("reply_text", ret.ReplyText),
		)
	}
}

// sleepOrDone espera d o hasta que ctx se cancele. Devuelve false si terminó
// por cancelación.
func sleepOrDone(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// scrubURL evita que la URL del broker, que lleva usuario y contraseña, llegue
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
