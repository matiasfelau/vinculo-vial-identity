// Package legalhold implementa el barrido que destruye los holds de baja de
// cuenta (US-11) al vencer su plazo de retención (art. 4 inc. 7 de la Ley
// 25.326: los datos se destruyen cuando dejan de ser necesarios). Depende
// únicamente de los puertos de domain, para ejercitarse entero con dobles.
package legalhold

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// Sweeper destruye periódicamente los holds con destroy_at <= now.
type Sweeper struct {
	repo      domain.LegalHoldRepository
	interval  time.Duration
	batchSize int
	logger    *slog.Logger
	now       func() time.Time
}

// NewSweeper valida los parámetros y construye el Sweeper. interval es cada
// cuánto corre un barrido y batchSize acota cuántos holds se borran por
// sentencia. logger puede ser nil (usa slog.Default).
func NewSweeper(repo domain.LegalHoldRepository, interval time.Duration, batchSize int, logger *slog.Logger) (*Sweeper, error) {
	switch {
	case repo == nil:
		return nil, errors.New("legalhold: falta el repositorio de holds")
	case interval <= 0:
		return nil, errors.New("legalhold: el intervalo del barrido debe ser positivo")
	case batchSize < 1:
		return nil, errors.New("legalhold: el tamaño del lote debe ser al menos 1")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Sweeper{repo: repo, interval: interval, batchSize: batchSize, logger: logger, now: time.Now}, nil
}

// SweepOnce destruye todos los holds vencidos, de a lotes, y devuelve cuántos
// destruyó. Corta apenas el contexto se cancela: lo que no alcanzó a borrar lo
// toma el próximo barrido. Es seguro con varias réplicas a la vez.
//
// Ante un error devuelve igual lo destruido hasta ese momento.
func (s *Sweeper) SweepOnce(ctx context.Context) (int64, error) {
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}

		destroyed, err := s.repo.DestroyExpired(ctx, s.now(), s.batchSize)
		total += destroyed
		if err != nil {
			return total, fmt.Errorf("legalhold: no se pudo destruir un lote de holds: %w", err)
		}
		if destroyed < int64(s.batchSize) {
			return total, nil
		}
	}
}

// Run barre una vez al arrancar —un servicio que estuvo caído más que el
// intervalo no espera un ciclo entero con holds vencidos— y después cada
// interval, hasta que ctx se cancele. Es bloqueante: el llamador lo lanza en su
// propia goroutine y espera a que vuelva para cerrar la base, que es lo que
// garantiza el apagado ordenado.
func (s *Sweeper) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		s.cycle(ctx)

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// cycle ejecuta un barrido y deja constancia. Un fallo no detiene el proceso:
// el próximo ciclo reintenta. Un apagado a mitad de barrido no es un error.
func (s *Sweeper) cycle(ctx context.Context) {
	destroyed, err := s.SweepOnce(ctx)
	switch {
	case err != nil && ctx.Err() != nil:
		s.logger.InfoContext(ctx, "barrido de holds interrumpido por el apagado",
			slog.Int64("destroyed", destroyed))
	case err != nil:
		s.logger.ErrorContext(ctx, "barrido de holds fallido: se reintentará en el próximo ciclo",
			slog.Int64("destroyed", destroyed),
			slog.String("error", err.Error()))
	case destroyed > 0:
		s.logger.InfoContext(ctx, "holds vencidos destruidos", slog.Int64("destroyed", destroyed))
	}
}
