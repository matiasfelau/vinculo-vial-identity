package emailchallenge

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// Sweeper borra periódicamente los desafíos por email que ya no sirven: aquellos
// cuyo código, grant y ventana de envíos de 24 h ya vencieron todos. Mismo
// esquema que el barrido de sanciones (internal/service/sanction): un ciclo al
// arrancar y después uno por intervalo, de a lotes, seguro con varias réplicas.
type Sweeper struct {
	repo      domain.EmailChallengeRepository
	interval  time.Duration
	batchSize int
	logger    *slog.Logger
	now       func() time.Time
}

// NewSweeper valida los parámetros y construye el Sweeper. logger puede ser nil
// (usa slog.Default).
func NewSweeper(repo domain.EmailChallengeRepository, interval time.Duration, batchSize int, logger *slog.Logger) (*Sweeper, error) {
	switch {
	case repo == nil:
		return nil, errors.New("emailchallenge: falta el repositorio de desafíos")
	case interval <= 0:
		return nil, errors.New("emailchallenge: el intervalo del barrido debe ser positivo")
	case batchSize < 1:
		return nil, errors.New("emailchallenge: el tamaño del lote debe ser al menos 1")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Sweeper{repo: repo, interval: interval, batchSize: batchSize, logger: logger, now: time.Now}, nil
}

// SweepOnce borra todos los desafíos vencidos, de a lotes, y devuelve cuántos
// borró. Corta apenas el contexto se cancela: lo que no alcanzó a borrar lo toma
// el próximo barrido. Ante un error devuelve igual lo borrado hasta ese momento.
func (s *Sweeper) SweepOnce(ctx context.Context) (int64, error) {
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}

		deleted, err := s.repo.DeleteExpired(ctx, s.now(), s.batchSize)
		total += deleted
		if err != nil {
			return total, fmt.Errorf("emailchallenge: no se pudo borrar un lote de desafíos: %w", err)
		}
		if deleted < int64(s.batchSize) {
			return total, nil
		}
	}
}

// Run barre una vez al arrancar y después cada interval, hasta que ctx se
// cancele. Es bloqueante: el llamador lo lanza en su propia goroutine y espera a
// que vuelva para cerrar la base, que es lo que garantiza el apagado ordenado.
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

// cycle ejecuta un barrido y deja constancia. Un fallo no detiene el proceso: el
// próximo ciclo reintenta. Un apagado a mitad de barrido no es un error.
func (s *Sweeper) cycle(ctx context.Context) {
	deleted, err := s.SweepOnce(ctx)
	switch {
	case err != nil && ctx.Err() != nil:
		s.logger.InfoContext(ctx, "barrido de desafíos de email interrumpido por el apagado",
			slog.Int64("deleted", deleted))
	case err != nil:
		s.logger.ErrorContext(ctx, "barrido de desafíos de email fallido: se reintentará en el próximo ciclo",
			slog.Int64("deleted", deleted),
			slog.String("error", err.Error()))
	case deleted > 0:
		s.logger.InfoContext(ctx, "desafíos de email vencidos borrados", slog.Int64("deleted", deleted))
	}
}
