package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// emailChallengesMigrationLockKey es la clave del advisory lock que serializa la
// migración de email_challenges cuando varias réplicas arrancan a la vez.
const emailChallengesMigrationLockKey int64 = 0x6c68_0004

// emailChallengeModel es la proyección de persistencia de domain.EmailChallenge.
//
// Hay a lo sumo una fila por (purpose, subject_hmac). grant_hash es único: es la
// clave con que se busca el token que presenta el cliente. Ninguna columna guarda
// el email ni el código en claro.
type emailChallengeModel struct {
	ID          uuid.UUID  `gorm:"column:id;type:uuid;primaryKey"`
	Purpose     string     `gorm:"column:purpose;type:varchar(32);not null;uniqueIndex:uix_email_challenges_purpose_subject,priority:1"`
	SubjectHMAC string     `gorm:"column:subject_hmac;type:varchar(64);not null;uniqueIndex:uix_email_challenges_purpose_subject,priority:2"`
	UserID      *uuid.UUID `gorm:"column:user_id;type:uuid"`

	CodeHMAC      *string    `gorm:"column:code_hmac;type:varchar(64)"`
	CodeExpiresAt *time.Time `gorm:"column:code_expires_at;type:timestamptz"`
	CodeAttempts  int        `gorm:"column:code_attempts;type:integer;not null;default:0"`

	GrantHash      *string    `gorm:"column:grant_hash;type:varchar(64);uniqueIndex:uix_email_challenges_grant_hash"`
	GrantExpiresAt *time.Time `gorm:"column:grant_expires_at;type:timestamptz"`
	GrantAttempts  int        `gorm:"column:grant_attempts;type:integer;not null;default:0"`

	SendsCount           int        `gorm:"column:sends_count;type:integer;not null;default:0"`
	SendsWindowStartedAt *time.Time `gorm:"column:sends_window_started_at;type:timestamptz"`
	LastSentAt           *time.Time `gorm:"column:last_sent_at;type:timestamptz"`

	ConsumedAt *time.Time `gorm:"column:consumed_at;type:timestamptz"`
	CreatedAt  time.Time  `gorm:"column:created_at;type:timestamptz;not null"`
}

// TableName fija el nombre de la tabla en lugar de depender de la pluralización
// automática de GORM.
func (emailChallengeModel) TableName() string { return "email_challenges" }

// addEmailChallengesForeignKey agrega, de forma idempotente, la clave foránea de
// email_challenges.user_id hacia users.id con ON DELETE CASCADE: la baja de una
// cuenta se lleva sus desafíos de recuperación (Ley 25.326, minimización). Va en
// SQL crudo por el mismo motivo que la de sessions.
const addEmailChallengesForeignKey = `
DO $$
BEGIN
	IF NOT EXISTS (
		SELECT 1 FROM pg_constraint WHERE conname = 'fk_email_challenges_user_id'
	) THEN
		ALTER TABLE email_challenges
			ADD CONSTRAINT fk_email_challenges_user_id
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
	END IF;
END $$;
`

// ensureEmailChallenges crea email_challenges si falta y le agrega la clave
// foránea hacia users. Es idempotente y requiere que users ya exista. Corre en
// una transacción bajo un advisory lock: con varias réplicas arrancando a la
// vez, una migra y las demás encuentran el trabajo hecho. La llaman los dos
// repositorios que tocan la tabla, así ninguno depende del orden de arranque.
func ensureEmailChallenges(ctx context.Context, db *gorm.DB) error {
	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", emailChallengesMigrationLockKey).Error; err != nil {
			return fmt.Errorf("no se pudo tomar el lock de la migración: %w", err)
		}
		if err := tx.AutoMigrate(&emailChallengeModel{}); err != nil {
			return fmt.Errorf("no se pudo migrar email_challenges: %w", err)
		}
		if err := tx.Exec(addEmailChallengesForeignKey).Error; err != nil {
			return fmt.Errorf("no se pudo crear la clave foránea de email_challenges: %w", err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("postgres: falló la migración de email_challenges: %w", err)
	}
	return nil
}

func toEmailChallengeModel(c *domain.EmailChallenge) *emailChallengeModel {
	m := &emailChallengeModel{
		ID:                   c.ID,
		Purpose:              string(c.Purpose),
		SubjectHMAC:          c.SubjectHMAC,
		UserID:               c.UserID,
		CodeExpiresAt:        utcPtr(c.CodeExpiresAt),
		CodeAttempts:         c.CodeAttempts,
		GrantExpiresAt:       utcPtr(c.GrantExpiresAt),
		GrantAttempts:        c.GrantAttempts,
		SendsCount:           c.SendsCount,
		SendsWindowStartedAt: utcPtr(c.SendsWindowStartedAt),
		LastSentAt:           utcPtr(c.LastSentAt),
		ConsumedAt:           utcPtr(c.ConsumedAt),
		CreatedAt:            c.CreatedAt.UTC(),
	}
	if c.CodeHMAC != "" {
		code := c.CodeHMAC
		m.CodeHMAC = &code
	}
	if c.GrantHash != "" {
		grant := c.GrantHash
		m.GrantHash = &grant
	}
	return m
}

func (m *emailChallengeModel) toDomain() *domain.EmailChallenge {
	c := &domain.EmailChallenge{
		ID:                   m.ID,
		Purpose:              domain.EmailChallengePurpose(m.Purpose),
		SubjectHMAC:          m.SubjectHMAC,
		UserID:               m.UserID,
		CodeExpiresAt:        m.CodeExpiresAt,
		CodeAttempts:         m.CodeAttempts,
		GrantExpiresAt:       m.GrantExpiresAt,
		GrantAttempts:        m.GrantAttempts,
		SendsCount:           m.SendsCount,
		SendsWindowStartedAt: m.SendsWindowStartedAt,
		LastSentAt:           m.LastSentAt,
		ConsumedAt:           m.ConsumedAt,
		CreatedAt:            m.CreatedAt,
	}
	if m.CodeHMAC != nil {
		c.CodeHMAC = *m.CodeHMAC
	}
	if m.GrantHash != nil {
		c.GrantHash = *m.GrantHash
	}
	return c
}

// utcPtr normaliza a UTC un instante opcional, sin compartir el puntero.
func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
