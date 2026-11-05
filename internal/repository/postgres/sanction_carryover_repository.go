package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// SanctionCarryoverRepository implementa domain.SanctionCarryoverRepository.
type SanctionCarryoverRepository struct {
	db *gorm.DB
}

var _ domain.SanctionCarryoverRepository = (*SanctionCarryoverRepository)(nil)

// NewSanctionCarryoverRepository construye el repositorio y migra
// sanction_carryovers.
func NewSanctionCarryoverRepository(ctx context.Context, db *gorm.DB) (*SanctionCarryoverRepository, error) {
	if db == nil {
		return nil, errors.New("postgres: se requiere una conexión GORM")
	}
	if err := ensureSanctionCarryovers(ctx, db); err != nil {
		return nil, err
	}
	return &SanctionCarryoverRepository{db: db}, nil
}

// deleteExpiredSanctions borra un lote de sanciones vencidas. Las filas se eligen
// en un CTE MATERIALIZED con FOR UPDATE SKIP LOCKED: dos réplicas barriendo a la
// vez reparten el trabajo en lugar de esperarse o de intentar borrar lo mismo.
//
// El CTE es MATERIALIZED a propósito. Con un `IN (SELECT ... LIMIT n FOR
// UPDATE)` en el WHERE, el planner puede reevaluar la subconsulta por cada fila
// y el DELETE termina borrando más de n; materializarla fija el lote, y
// DeleteExpired nunca borra más que limit.
const deleteExpiredSanctions = `
WITH doomed AS MATERIALIZED (
	SELECT dni_hmac FROM sanction_carryovers
	WHERE expires_at <= ?
	ORDER BY expires_at
	LIMIT ?
	FOR UPDATE SKIP LOCKED
)
DELETE FROM sanction_carryovers AS c
USING doomed
WHERE c.dni_hmac = doomed.dni_hmac`

// DeleteExpired borra hasta limit sanciones con expires_at <= now: pasado el
// plazo la sanción de una cuenta dada de baja deja de heredarse, y los datos se
// destruyen cuando dejan de ser necesarios (art. 4 inc. 7 de la Ley 25.326).
func (r *SanctionCarryoverRepository) DeleteExpired(ctx context.Context, now time.Time, limit int) (int64, error) {
	if limit < 1 {
		return 0, errors.New("postgres: el límite del lote debe ser al menos 1")
	}

	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	res := r.db.WithContext(ctx).Exec(deleteExpiredSanctions, now.UTC(), limit)
	if res.Error != nil {
		return 0, fmt.Errorf("postgres: no se pudieron borrar las sanciones vencidas: %w", classifyDBError(res.Error))
	}
	return res.RowsAffected, nil
}
