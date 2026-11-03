package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// LegalHoldRepository implementa domain.LegalHoldRepository.
type LegalHoldRepository struct {
	db *gorm.DB
}

var _ domain.LegalHoldRepository = (*LegalHoldRepository)(nil)

// NewLegalHoldRepository construye el repositorio y migra legal_hold.
func NewLegalHoldRepository(ctx context.Context, db *gorm.DB) (*LegalHoldRepository, error) {
	if db == nil {
		return nil, errors.New("postgres: se requiere una conexión GORM")
	}
	if err := ensureLegalHoldSchema(ctx, db); err != nil {
		return nil, err
	}
	return &LegalHoldRepository{db: db}, nil
}

// destroyExpiredHolds borra un lote de holds vencidos. Las filas se eligen en un
// CTE MATERIALIZED con FOR UPDATE SKIP LOCKED: dos réplicas barriendo a la vez
// reparten el trabajo en lugar de esperarse o de intentar borrar lo mismo.
//
// El CTE es MATERIALIZED a propósito. Con un `IN (SELECT ... LIMIT n FOR
// UPDATE)` en el WHERE, el planner puede reevaluar la subconsulta por cada fila
// y el DELETE termina borrando más de n; materializarla fija el lote, y
// DestroyExpired nunca destruye más que limit.
const destroyExpiredHolds = `
WITH doomed AS MATERIALIZED (
	SELECT user_id FROM legal_hold.user_holds
	WHERE destroy_at <= ?
	ORDER BY destroy_at
	LIMIT ?
	FOR UPDATE SKIP LOCKED
)
DELETE FROM legal_hold.user_holds AS h
USING doomed
WHERE h.user_id = doomed.user_id`

// DestroyExpired borra hasta limit holds con destroy_at <= now (art. 4 inc. 7
// de la Ley 25.326: los datos se destruyen cuando dejan de ser necesarios).
func (r *LegalHoldRepository) DestroyExpired(ctx context.Context, now time.Time, limit int) (int64, error) {
	if limit < 1 {
		return 0, errors.New("postgres: el límite del lote debe ser al menos 1")
	}

	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	res := r.db.WithContext(ctx).Exec(destroyExpiredHolds, now.UTC(), limit)
	if res.Error != nil {
		return 0, fmt.Errorf("postgres: no se pudieron destruir los holds vencidos: %w", classifyDBError(res.Error))
	}
	return res.RowsAffected, nil
}
