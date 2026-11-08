package postgres

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// AccountDeletionRepository implementa domain.AccountDeletionRepository.
type AccountDeletionRepository struct {
	db *gorm.DB
}

var _ domain.AccountDeletionRepository = (*AccountDeletionRepository)(nil)

// NewAccountDeletionRepository construye el repositorio y migra
// sanction_carryovers. Requiere que users, sessions y outbox_events ya existan:
// los tres repositorios que las migran tienen que haber corrido antes en el
// arranque.
func NewAccountDeletionRepository(ctx context.Context, db *gorm.DB) (*AccountDeletionRepository, error) {
	if db == nil {
		return nil, errors.New("postgres: se requiere una conexión GORM")
	}
	if err := ensureSanctionCarryovers(ctx, db); err != nil {
		return nil, err
	}
	return &AccountDeletionRepository{db: db}, nil
}

// DeleteAccount ejecuta la baja en una única transacción. Ver
// domain.AccountDeletionRepository.
//
// La fila del usuario se bloquea (SELECT ... FOR UPDATE) antes de leer la
// sanción: un reporte o una penalización que llega a la vez espera a que la baja
// termine, y la sanción que se deja nunca es más vieja que la de la fila que se
// borra. Un evento de reputación que llegue después encuentra al usuario
// inexistente y se confirma sin efecto.
//
// La sanción se guarda con un upsert por dni_hmac: una fila vencida que el
// barrido todavía no borró, de una cuenta anterior con el mismo DNI, se pisa con
// la sanción nueva.
//
// Las sesiones se borran explícitamente y no se confía solo en el ON DELETE
// CASCADE de la clave foránea: marcarlas revocadas antes de borrarlas no tendría
// ningún efecto observable dentro de la misma transacción, y la revocación hacia
// los demás servicios la lleva user.sessions.revoked, que va en deletion.Events.
func (r *AccountDeletionRepository) DeleteAccount(ctx context.Context, deletion domain.AccountDeletion) error {
	if err := deletion.Validate(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var user userModel
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ?", deletion.UserID).
			Take(&user).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return domain.ErrUserNotFound
			}
			return fmt.Errorf("no se pudo bloquear al usuario: %w", err)
		}

		if carryover := deletion.CarryoverFor(user.toDomain()); carryover != nil {
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "dni_hmac"}},
				UpdateAll: true,
			}).Create(toSanctionCarryoverModel(*carryover)).Error; err != nil {
				return fmt.Errorf("no se pudo guardar la sanción para heredar: %w", err)
			}
		}

		if err := tx.Where("user_id = ?", deletion.UserID).Delete(&sessionModel{}).Error; err != nil {
			return fmt.Errorf("no se pudieron borrar las sesiones: %w", err)
		}

		if err := tx.Where("id = ?", deletion.UserID).Delete(&userModel{}).Error; err != nil {
			return fmt.Errorf("no se pudo borrar al usuario: %w", err)
		}

		for i := range deletion.Events {
			if err := tx.Create(toOutboxModel(&deletion.Events[i])).Error; err != nil {
				return fmt.Errorf("no se pudo encolar el evento de outbox: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return err
		}
		return fmt.Errorf("postgres: no se pudo dar de baja la cuenta: %w", classifyDBError(err))
	}
	return nil
}
