package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// legalHoldMigrationLockKey es la clave del advisory lock que serializa la
// migración de legal_hold cuando varias réplicas arrancan a la vez: sin él, dos
// CREATE SCHEMA IF NOT EXISTS concurrentes pueden chocar en el catálogo.
const legalHoldMigrationLockKey int64 = 0x6c68_0001

// migrateLegalHold es la migración explícita de US-11: el esquema legal_hold y
// su tabla user_holds, aislados del resto de las tablas del servicio. No pasa
// por AutoMigrate porque este crea tablas en el esquema por defecto, y el
// aislamiento del esquema es parte del contrato: en producción se accede a
// legal_hold con un rol de base de datos propio (ver el README).
//
// dni_hmac e idx_user_holds_dni_hmac solo cubren los holds con sanción: el
// signup busca por ahí y el índice parcial deja afuera al resto.
const migrateLegalHold = `
CREATE SCHEMA IF NOT EXISTS legal_hold;

CREATE TABLE IF NOT EXISTS legal_hold.user_holds (
	user_id          uuid PRIMARY KEY,
	dni_sealed       text        NOT NULL,
	deleted_at       timestamptz NOT NULL,
	destroy_at       timestamptz NOT NULL,
	dni_hmac         varchar(64),
	account_status   varchar(32),
	reputation_score integer,
	report_count     integer
);

CREATE INDEX IF NOT EXISTS idx_user_holds_destroy_at ON legal_hold.user_holds (destroy_at);
CREATE INDEX IF NOT EXISTS idx_user_holds_dni_hmac ON legal_hold.user_holds (dni_hmac) WHERE dni_hmac IS NOT NULL;
`

// ensureLegalHoldSchema aplica migrateLegalHold si la tabla todavía no existe.
// Lo llaman todos los repositorios que tocan legal_hold, así ninguno depende del
// orden de arranque, y es idempotente.
//
// Con la tabla ya creada no ejecuta nada, ni siquiera los IF NOT EXISTS:
// Postgres exige el permiso de creación antes de mirar si el objeto existe, así
// que correrlos obligaría a darle al rol del servicio permisos de DDL sobre un
// esquema que, en producción, es de otro rol. Con esta guarda el DBA crea el
// esquema con su rol y le da al servicio solo permisos de DML.
func ensureLegalHoldSchema(ctx context.Context, db *gorm.DB) error {
	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", legalHoldMigrationLockKey).Error; err != nil {
			return fmt.Errorf("no se pudo tomar el lock de la migración: %w", err)
		}

		var exists bool
		if err := tx.Raw("SELECT to_regclass('legal_hold.user_holds') IS NOT NULL").Scan(&exists).Error; err != nil {
			return fmt.Errorf("no se pudo comprobar si legal_hold.user_holds existe: %w", err)
		}
		if exists {
			return nil
		}
		return tx.Exec(migrateLegalHold).Error
	})
	if err != nil {
		return fmt.Errorf("postgres: falló la migración del esquema legal_hold: %w", err)
	}
	return nil
}

// userHoldModel es la proyección de persistencia de domain.UserHold. Los
// campos de sanción son punteros: en la base son NULL cuando la cuenta no
// estaba penalizada y después de que un nuevo registro los heredó.
type userHoldModel struct {
	UserID          uuid.UUID `gorm:"column:user_id;type:uuid;primaryKey"`
	DNISealed       string    `gorm:"column:dni_sealed;type:text;not null"`
	DeletedAt       time.Time `gorm:"column:deleted_at;type:timestamptz;not null"`
	DestroyAt       time.Time `gorm:"column:destroy_at;type:timestamptz;not null"`
	DNIHMAC         *string   `gorm:"column:dni_hmac;type:varchar(64)"`
	AccountStatus   *string   `gorm:"column:account_status;type:varchar(32)"`
	ReputationScore *int      `gorm:"column:reputation_score;type:integer"`
	ReportCount     *int      `gorm:"column:report_count;type:integer"`
}

// TableName califica la tabla con su esquema.
func (userHoldModel) TableName() string { return "legal_hold.user_holds" }

func toUserHoldModel(h domain.UserHold) *userHoldModel {
	m := &userHoldModel{
		UserID:    h.UserID,
		DNISealed: h.DNISealed,
		DeletedAt: h.DeletedAt,
		DestroyAt: h.DestroyAt,
	}
	if s := h.Sanction; s != nil {
		hmac, status, score, count := s.DNIHMAC, string(s.AccountStatus), s.ReputationScore, s.ReportCount
		m.DNIHMAC, m.AccountStatus, m.ReputationScore, m.ReportCount = &hmac, &status, &score, &count
	}
	return m
}
