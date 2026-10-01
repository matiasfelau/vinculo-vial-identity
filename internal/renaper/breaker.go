package renaper

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// Valores por defecto del circuit breaker hacia RENAPER.
const (
	DefaultBreakerFailureThreshold = 5
	DefaultBreakerWindow           = time.Minute
	DefaultBreakerOpenDuration     = 30 * time.Second
)

// BreakerConfig son los parámetros del circuit breaker: cuántas fallas dentro
// de qué ventana abren el circuito, y cuánto permanece abierto antes de
// admitir una única llamada de prueba.
type BreakerConfig struct {
	FailureThreshold int
	Window           time.Duration
	OpenDuration     time.Duration
}

func (c *BreakerConfig) applyDefaults() {
	if c.FailureThreshold <= 0 {
		c.FailureThreshold = DefaultBreakerFailureThreshold
	}
	if c.Window <= 0 {
		c.Window = DefaultBreakerWindow
	}
	if c.OpenDuration <= 0 {
		c.OpenDuration = DefaultBreakerOpenDuration
	}
}

type breakerState int

const (
	breakerClosed breakerState = iota
	breakerOpen
	breakerHalfOpen
)

// withBreaker decora un domain.RenaperService con un circuit breaker.
//
// Solo cuentan como falla domain.ErrUpstreamUnavailable y
// domain.ErrUpstreamInvalidResponse —timeout, conexión rechazada, 5xx del
// upstream—, tal como fija el contrato de resiliencia de la plataforma. Un
// rechazo legítimo de RENAPER, (false, nil), es un resultado válido de la
// dependencia —el equivalente a un 4xx: la propia solicitud no calificó—, no
// una falla suya, y nunca abre el circuito.
//
// Mientras el circuito está abierto, ValidateIdentity devuelve de inmediato
// sin tocar la red: "circuito abierto → 503 sin tocar la red" del contrato.
type withBreaker struct {
	next   domain.RenaperService
	cfg    BreakerConfig
	logger *slog.Logger
	now    func() time.Time

	mu       sync.Mutex
	state    breakerState
	failures []time.Time
	openedAt time.Time
}

// WithCircuitBreaker decora next. logger puede ser nil (usa slog.Default()).
func WithCircuitBreaker(next domain.RenaperService, cfg BreakerConfig, logger *slog.Logger) domain.RenaperService {
	cfg.applyDefaults()
	if logger == nil {
		logger = slog.Default()
	}
	return &withBreaker{next: next, cfg: cfg, logger: logger, now: time.Now}
}

func (w *withBreaker) ValidateIdentity(ctx context.Context, dni, tramite, sexo, selfie []byte) (bool, error) {
	if !w.allow() {
		return false, fmt.Errorf("renaper: circuito abierto, no se intenta la consulta: %w", domain.ErrUpstreamUnavailable)
	}

	ok, err := w.next.ValidateIdentity(ctx, dni, tramite, sexo, selfie)
	w.record(err)
	return ok, err
}

// allow decide si la llamada puede intentarse.
//
// Con el circuito cerrado, siempre. Con el circuito abierto, solo cuando ya
// venció OpenDuration —y en ese caso transiciona a medio abierto y deja pasar
// esta única llamada como prueba—. Con el circuito medio abierto, nunca: ya
// hay una prueba en curso y una segunda llamada concurrente no debe sumarse
// a ella.
func (w *withBreaker) allow() bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	switch w.state {
	case breakerOpen:
		if w.now().Sub(w.openedAt) < w.cfg.OpenDuration {
			return false
		}
		w.state = breakerHalfOpen
		return true
	case breakerHalfOpen:
		return false
	default: // breakerClosed
		return true
	}
}

// record contabiliza el resultado de una llamada que allow() ya autorizó.
func (w *withBreaker) record(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	fails := errors.Is(err, domain.ErrUpstreamUnavailable) || errors.Is(err, domain.ErrUpstreamInvalidResponse)
	now := w.now()

	if w.state == breakerHalfOpen {
		if fails {
			w.state = breakerOpen
			w.openedAt = now
			w.failures = nil
			w.logger.Warn("circuito hacia RENAPER sigue abierto: la prueba falló")
			return
		}
		w.state = breakerClosed
		w.failures = nil
		w.logger.Info("circuito hacia RENAPER cerrado: la prueba fue exitosa")
		return
	}

	if !fails {
		return
	}

	w.failures = append(w.failures, now)

	// Poda las fallas que ya salieron de la ventana: solo importa la tasa
	// reciente, no el historial completo desde que arrancó el proceso.
	cutoff := now.Add(-w.cfg.Window)
	i := 0
	for i < len(w.failures) && w.failures[i].Before(cutoff) {
		i++
	}
	w.failures = w.failures[i:]

	if len(w.failures) >= w.cfg.FailureThreshold {
		w.state = breakerOpen
		w.openedAt = now
		w.failures = nil
		w.logger.Warn("circuito hacia RENAPER abierto",
			slog.Int("umbral_de_fallas", w.cfg.FailureThreshold),
			slog.Duration("ventana", w.cfg.Window),
		)
	}
}
