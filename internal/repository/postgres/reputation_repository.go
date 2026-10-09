package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// ReputationRepository implementa domain.ReputationRepository sobre
// GORM/PostgreSQL.
type ReputationRepository struct {
	db *gorm.DB
}

var _ domain.ReputationRepository = (*ReputationRepository)(nil)

// NewReputationRepository construye el repositorio y migra processed_events.
//
// La tabla users la migra NewUserRepository, que tiene que haber corrido antes
// en el arranque: este repositorio actualiza sus columnas de reputación. Como
// el resto del servicio, migra con AutoMigrate: es una excepción conocida a la
// regla de migraciones versionadas, tratada como deuda técnica de todo el
// proyecto (ver README).
func NewReputationRepository(ctx context.Context, db *gorm.DB) (*ReputationRepository, error) {
	if db == nil {
		return nil, errors.New("postgres: se requiere una conexión GORM")
	}

	if err := db.WithContext(ctx).AutoMigrate(&processedEventModel{}); err != nil {
		return nil, fmt.Errorf("postgres: falló la migración del esquema de processed_events: %w", err)
	}

	return &ReputationRepository{db: db}, nil
}

// ApplyRejection registra el evento y resta la penalización en una única
// transacción.
//
// El INSERT ... ON CONFLICT DO NOTHING va primero: si no inserta ninguna fila,
// el evento ya se procesó y la transacción termina sin tocar al usuario. Si
// otra entrega concurrente del mismo evento está insertando la misma clave, el
// segundo INSERT espera a que la primera transacción termine y recién entonces
// resuelve el conflicto, así que la penalización nunca se aplica dos veces.
//
// La resta se hace en SQL (reputation_score - $1), no leyendo y escribiendo el
// valor, para que dos rechazos distintos del mismo usuario no se pisen.
func (r *ReputationRepository) ApplyRejection(ctx context.Context, event domain.ProcessedEvent, userID uuid.UUID, penalty int) (domain.RejectionResult, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	result := domain.RejectionApplied

	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		inserted := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(toProcessedEventModel(event))
		if inserted.Error != nil {
			return fmt.Errorf("no se pudo registrar el evento procesado: %w", inserted.Error)
		}
		if inserted.RowsAffected == 0 {
			result = domain.RejectionDuplicate
			return nil
		}

		if penalty <= 0 {
			return nil
		}

		updated := tx.Model(&userModel{}).
			Where("id = ?", userID).
			Updates(map[string]any{
				"reputation_score": gorm.Expr("reputation_score - ?", penalty),
				"updated_at":       event.ProcessedAt.UTC(),
			})
		if updated.Error != nil {
			return fmt.Errorf("no se pudo restar la reputación: %w", updated.Error)
		}
		if updated.RowsAffected == 0 {
			result = domain.RejectionUserNotFound
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("postgres: no se pudo aplicar el rechazo: %w", classifyDBError(err))
	}
	return result, nil
}
