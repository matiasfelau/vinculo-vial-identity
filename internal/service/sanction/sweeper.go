// Package sanction implementa el barrido que borra las sanciones heredables de
// las cuentas dadas de baja (US-11) al vencer su plazo: pasado
// SANCTION_CARRYOVER_DAYS, registrarse otra vez con el mismo DNI ya no hereda
// nada, y el dato deja de ser necesario (art. 4 inc. 7 de la Ley 25.326).
// Depende únicamente de los puertos de domain, para ejercitarse entero con
// dobles.
package sanction

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// Sweeper borra periódicamente las sanciones con expires_at <= now.
type Sweeper struct {
	repo      domain.SanctionCarryoverRepository
	interval  time.Duration
	batchSize int
	logger    *slog.Logger
	now       func() time.Time
}

// NewSweeper valida los parámetros y construye el Sweeper. interval es cada
// cuánto corre un barrido y batchSize acota cuántas filas se borran por
// sentencia. logger puede ser nil (usa slog.Default).
func NewSweeper(repo domain.SanctionCarryoverRepository, interval time.Duration, batchSize int, logger *slog.Logger) (*Sweeper, error) {
	switch {
	case repo == nil:
		return nil, errors.New("sanction: falta el repositorio de sanciones")
	case interval <= 0:
		return nil, errors.New("sanction: el intervalo del barrido debe ser positivo")
	case batchSize < 1:
		return nil, errors.New("sanction: el tamaño del lote debe ser al menos 1")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Sweeper{repo: repo, interval: interval, batchSize: batchSize, logger: logger, now: time.Now}, nil
}

// SweepOnce borra todas las sanciones vencidas, de a lotes, y devuelve cuántas
// borró. Corta apenas el contexto se cancela: lo que no alcanzó a borrar lo toma
// el próximo barrido. Es seguro con varias réplicas a la vez.
//
// Ante un error devuelve igual lo borrado hasta ese momento.
func (s *Sweeper) SweepOnce(ctx context.Context) (int64, error) {
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}

		deleted, err := s.repo.DeleteExpired(ctx, s.now(), s.batchSize)
		total += deleted
		if err != nil {
			return total, fmt.Errorf("sanction: no se pudo borrar un lote de sanciones: %w", err)
		}
		if deleted < int64(s.batchSize) {
			return total, nil
		}
	}
}

// Run barre una vez al arrancar —un servicio que estuvo caído más que el
// intervalo no espera un ciclo entero con filas vencidas— y después cada
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

// cycle ejecuta un barrido y deja constancia. Un fallo no detiene el proceso: el
// próximo ciclo reintenta. Un apagado a mitad de barrido no es un error.
func (s *Sweeper) cycle(ctx context.Context) {
	deleted, err := s.SweepOnce(ctx)
	switch {
	case err != nil && ctx.Err() != nil:
		s.logger.InfoContext(ctx, "barrido de sanciones interrumpido por el apagado",
			slog.Int64("deleted", deleted))
	case err != nil:
		s.logger.ErrorContext(ctx, "barrido de sanciones fallido: se reintentará en el próximo ciclo",
			slog.Int64("deleted", deleted),
			slog.String("error", err.Error()))
	case deleted > 0:
		s.logger.InfoContext(ctx, "sanciones vencidas borradas", slog.Int64("deleted", deleted))
	}
}
