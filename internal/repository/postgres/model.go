package postgres

import (
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// userModel es la proyección de persistencia de domain.User.
//
// Se mantiene separada de la entidad a propósito: las etiquetas de GORM, los
// tipos de columna y los nombres heredados del esquema son detalles de la base
// que no deben filtrarse al dominio. El campo `password` guarda el hash Argon2id
// y conserva ese nombre por compatibilidad con el esquema acordado.
type userModel struct {
	ID            uuid.UUID `gorm:"column:id;type:uuid;primaryKey"`
	Email         string    `gorm:"column:email;type:varchar(254);not null;uniqueIndex:uix_users_email"`
	Password      string    `gorm:"column:password;type:varchar(255);not null"`
	DNIHashed     string    `gorm:"column:dni_hashed;type:varchar(64);not null;uniqueIndex:uix_users_dni_hashed"`
	DNIEncrypted  string    `gorm:"column:dni_encrypted;type:text;not null"`
	AccountStatus string    `gorm:"column:account_status;type:varchar(32);not null;default:ACTIVE"`
	// ReputationScore y ReportCount (US-08) se agregaron a una tabla con
	// usuarios: el default explícito es lo que hace que AutoMigrate pueda
	// declararlas NOT NULL y que las filas existentes queden en 0, sin backfill.
	ReputationScore int `gorm:"column:reputation_score;type:integer;not null;default:0"`
	ReportCount     int `gorm:"column:report_count;type:integer;not null;default:0"`
	// EmailVerifiedAt (US-13) es nulable: las cuentas anteriores a la
	// verificación de email quedan en NULL, sin backfill, y no pueden recuperar su
	// contraseña.
	EmailVerifiedAt *time.Time `gorm:"column:email_verified_at;type:timestamptz"`
	// TermsVersion y TermsAcceptedAt (US-19) son nulables: las cuentas anteriores
	// quedan en NULL, sin backfill, porque no hay consentimiento que registrar.
	TermsVersion    *string    `gorm:"column:terms_version;type:varchar(16)"`
	TermsAcceptedAt *time.Time `gorm:"column:terms_accepted_at;type:timestamptz"`
	CreatedAt       time.Time  `gorm:"column:created_at;type:timestamptz;not null"`
	UpdatedAt       time.Time  `gorm:"column:updated_at;type:timestamptz;not null"`
}

// TableName fija el nombre de la tabla en lugar de depender de la pluralización
// automática de GORM.
func (userModel) TableName() string { return "users" }

func toModel(u *domain.User) *userModel {
	var termsVersion *string
	if u.TermsVersion != "" {
		termsVersion = &u.TermsVersion
	}
	return &userModel{
		TermsVersion:    termsVersion,
		TermsAcceptedAt: utcPtr(u.TermsAcceptedAt),
		ID:              u.ID,
		Email:           u.Email,
		Password:        u.PasswordHash,
		DNIHashed:       u.DNIHashed,
		DNIEncrypted:    u.DNIEncrypted,
		AccountStatus:   string(u.AccountStatus),
		ReputationScore: u.ReputationScore,
		ReportCount:     u.ReportCount,
		EmailVerifiedAt: utcPtr(u.EmailVerifiedAt),
		CreatedAt:       u.CreatedAt,
		UpdatedAt:       u.UpdatedAt,
	}
}

func (m *userModel) toDomain() *domain.User {
	termsVersion := ""
	if m.TermsVersion != nil {
		termsVersion = *m.TermsVersion
	}
	return &domain.User{
		TermsVersion:    termsVersion,
		TermsAcceptedAt: m.TermsAcceptedAt,
		ID:              m.ID,
		Email:           m.Email,
		PasswordHash:    m.Password,
		DNIHashed:       m.DNIHashed,
		DNIEncrypted:    m.DNIEncrypted,
		AccountStatus:   domain.AccountStatus(m.AccountStatus),
		ReputationScore: m.ReputationScore,
		ReportCount:     m.ReportCount,
		EmailVerifiedAt: m.EmailVerifiedAt,
		CreatedAt:       m.CreatedAt,
		UpdatedAt:       m.UpdatedAt,
	}
}
