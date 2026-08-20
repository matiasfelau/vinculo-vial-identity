package postgres

import (
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// sessionModel es la proyección de persistencia de domain.Session. Se
// mantiene separada de la entidad por el mismo motivo que userModel: las
// etiquetas de GORM y los tipos de columna son detalles de la base que no
// deben filtrarse al dominio.
type sessionModel struct {
	ID               uuid.UUID `gorm:"column:id;type:uuid;primaryKey"`
	UserID           uuid.UUID `gorm:"column:user_id;type:uuid;not null;index"`
	RefreshTokenHash string    `gorm:"column:refresh_token_hash;type:varchar(64);not null;uniqueIndex:uix_sessions_refresh_token_hash"`
	IsRevoked        bool      `gorm:"column:is_revoked;type:boolean;not null;default:false"`
	ExpiresAt        time.Time `gorm:"column:expires_at;type:timestamptz;not null"`
	CreatedAt        time.Time `gorm:"column:created_at;type:timestamptz;not null"`
}

// TableName fija el nombre de la tabla en lugar de depender de la
// pluralización automática de GORM.
func (sessionModel) TableName() string { return "sessions" }

func toSessionModel(s *domain.Session) *sessionModel {
	return &sessionModel{
		ID:               s.ID,
		UserID:           s.UserID,
		RefreshTokenHash: s.RefreshTokenHash,
		IsRevoked:        s.IsRevoked,
		ExpiresAt:        s.ExpiresAt,
		CreatedAt:        s.CreatedAt,
	}
}

func (m *sessionModel) toDomain() *domain.Session {
	return &domain.Session{
		ID:               m.ID,
		UserID:           m.UserID,
		RefreshTokenHash: m.RefreshTokenHash,
		IsRevoked:        m.IsRevoked,
		ExpiresAt:        m.ExpiresAt,
		CreatedAt:        m.CreatedAt,
	}
}
