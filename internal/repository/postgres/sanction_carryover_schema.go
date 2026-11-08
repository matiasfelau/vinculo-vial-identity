package postgres

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// sanctionCarryoverMigrationLockKey es la clave del advisory lock que serializa
// la migración de sanction_carryovers cuando varias réplicas arrancan a la vez:
// sin él, dos CREATE TABLE concurrentes pueden chocar en el catálogo, y dos
// copias del esquema anterior duplicarían el trabajo de la migración.
const sanctionCarryoverMigrationLockKey int64 = 0x6c68_0002

// sanctionCarryoverModel es la proyección de persistencia de
// domain.SanctionCarryover. Es una tabla operativa de Identity, en el esquema por
// defecto, como users: no hay un registro aparte ni un rol propio.
//
// La fila no lleva user_id: se vincula con el DNI y nada más (dni_hmac es el mismo
// Blind Index que users.dni_hashed). expires_at está indexada para el barrido.
type sanctionCarryoverModel struct {
	DNIHMAC         string    `gorm:"column:dni_hmac;type:varchar(64);primaryKey"`
	AccountStatus   string    `gorm:"column:account_status;type:varchar(32);not null"`
	ReputationScore int       `gorm:"column:reputation_score;type:integer;not null"`
	ReportCount     int       `gorm:"column:report_count;type:integer;not null"`
	CreatedAt       time.Time `gorm:"column:created_at;type:timestamptz;not null"`
	ExpiresAt       time.Time `gorm:"column:expires_at;type:timestamptz;not null;index:idx_sanction_carryovers_expires_at"`
}

// TableName fija el nombre de la tabla en lugar de depender de la pluralización
// automática de GORM.
func (sanctionCarryoverModel) TableName() string { return "sanction_carryovers" }

func toSanctionCarryoverModel(c domain.SanctionCarryover) *sanctionCarryoverModel {
	return &sanctionCarryoverModel{
		DNIHMAC:         c.DNIHMAC,
		AccountStatus:   string(c.AccountStatus),
		ReputationScore: c.ReputationScore,
		ReportCount:     c.ReportCount,
		CreatedAt:       c.CreatedAt,
		ExpiresAt:       c.ExpiresAt,
	}
}

func (m *sanctionCarryoverModel) toDomain() domain.SanctionCarryover {
	return domain.SanctionCarryover{
		DNIHMAC:         m.DNIHMAC,
		AccountStatus:   domain.AccountStatus(m.AccountStatus),
		ReputationScore: m.ReputationScore,
		ReportCount:     m.ReportCount,
		CreatedAt:       m.CreatedAt,
		ExpiresAt:       m.ExpiresAt,
	}
}

// ensureSanctionCarryovers crea sanction_carryovers si falta y, si la base viene
// del esquema de retención anterior de US-11, lo migra (ver
// migrateLegacyHoldSchema). Es idempotente y la llaman todos los repositorios que
// tocan la tabla, así ninguno depende del orden de arranque.
//
// Todo corre en una transacción bajo un advisory lock: con varias réplicas
// arrancando a la vez, una migra y las demás encuentran el trabajo hecho.
func ensureSanctionCarryovers(ctx context.Context, db *gorm.DB) error {
	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", sanctionCarryoverMigrationLockKey).Error; err != nil {
			return fmt.Errorf("no se pudo tomar el lock de la migración: %w", err)
		}
		if err := tx.AutoMigrate(&sanctionCarryoverModel{}); err != nil {
			return fmt.Errorf("no se pudo migrar sanction_carryovers: %w", err)
		}
		return migrateLegacyHoldSchema(tx, time.Now())
	})
	if err != nil {
		return fmt.Errorf("postgres: falló la migración de sanction_carryovers: %w", err)
	}
	return nil
}
