package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// SessionRepository implementa domain.SessionRepository.
type SessionRepository struct {
	db *gorm.DB
}

// addSessionsForeignKey agrega, de forma idempotente, la restricción de clave
// foránea de sessions.user_id hacia users.id con ON DELETE CASCADE.
//
// Va en SQL crudo y no en la migración automática de GORM porque AutoMigrate
// solo genera una constraint de este tipo a partir de una asociación Go —un
// campo `User userModel` en sessionModel—, y no hace falta cargar esa relación
// completa solo para declararla. El bloque DO hace que ejecutar esto en cada
// arranque no falle si la constraint ya existe.
const addSessionsForeignKey = `
DO $$
BEGIN
	IF NOT EXISTS (
		SELECT 1 FROM pg_constraint WHERE conname = 'fk_sessions_user_id'
	) THEN
		ALTER TABLE sessions
			ADD CONSTRAINT fk_sessions_user_id
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
	END IF;
END $$;
`

// NewSessionRepository construye el repositorio, ejecuta AutoMigrate y agrega
// la restricción de clave foránea hacia users.
//
// Requiere que la tabla users ya exista: se asume que el repositorio de
// usuarios se inicializa primero, tal como lo hace cmd/api/main.go.
func NewSessionRepository(ctx context.Context, db *gorm.DB) (*SessionRepository, error) {
	if db == nil {
		return nil, errors.New("postgres: se requiere una conexión GORM")
	}

	if err := db.WithContext(ctx).AutoMigrate(&sessionModel{}); err != nil {
		return nil, fmt.Errorf("postgres: falló la migración del esquema de sessions: %w", err)
	}

	if err := db.WithContext(ctx).Exec(addSessionsForeignKey).Error; err != nil {
		return nil, fmt.Errorf("postgres: no se pudo crear la restricción de clave foránea de sessions: %w", err)
	}

	return &SessionRepository{db: db}, nil
}

// Create inserta la sesión nueva.
func (r *SessionRepository) Create(ctx context.Context, s *domain.Session) error {
	if s == nil {
		return errors.New("postgres: se requiere una sesión")
	}

	if err := r.db.WithContext(ctx).Create(toSessionModel(s)).Error; err != nil {
		return fmt.Errorf("postgres: no se pudo crear la sesión: %w", err)
	}
	return nil
}

// FindByHash busca una sesión por el SHA-256 de su Refresh Token.
func (r *SessionRepository) FindByHash(ctx context.Context, refreshTokenHash string) (*domain.Session, error) {
	var m sessionModel
	if err := r.db.WithContext(ctx).Where("refresh_token_hash = ?", refreshTokenHash).Take(&m).Error; err != nil {
		return nil, mapSessionFindError(err)
	}
	return m.toDomain(), nil
}

// RevokeByID marca como revocada una única sesión.
func (r *SessionRepository) RevokeByID(ctx context.Context, id uuid.UUID) error {
	if err := r.db.WithContext(ctx).
		Model(&sessionModel{}).
		Where("id = ?", id).
		Update("is_revoked", true).Error; err != nil {
		return fmt.Errorf("postgres: no se pudo revocar la sesión: %w", err)
	}
	return nil
}

// RevokeByHash marca como revocada la sesión cuyo hash de Refresh Token
// coincide. Ver la nota de domain.SessionRepository.RevokeByHash: que no
// coincida ninguna fila no es un error.
func (r *SessionRepository) RevokeByHash(ctx context.Context, refreshTokenHash string) error {
	if err := r.db.WithContext(ctx).
		Model(&sessionModel{}).
		Where("refresh_token_hash = ?", refreshTokenHash).
		Update("is_revoked", true).Error; err != nil {
		return fmt.Errorf("postgres: no se pudo revocar la sesión: %w", err)
	}
	return nil
}

// RevokeAllByUserID marca como revocadas todas las sesiones de un usuario.
//
// No distingue si había alguna sesión vigente para ese user_id: revocar cero
// filas no es un error, es simplemente que no había nada que revocar.
func (r *SessionRepository) RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error {
	if err := r.db.WithContext(ctx).
		Model(&sessionModel{}).
		Where("user_id = ?", userID).
		Update("is_revoked", true).Error; err != nil {
		return fmt.Errorf("postgres: no se pudo revocar las sesiones del usuario: %w", err)
	}
	return nil
}

// RotateSession revoca la sesión vieja e inserta la sesión rotada dentro de
// una única transacción de GORM: si la inserción falla, la revocación se
// deshace. Ver la nota de domain.SessionRepository.RotateSession — no es una
// optimización, es requisito de corrección.
func (r *SessionRepository) RotateSession(ctx context.Context, oldSessionID uuid.UUID, newSession *domain.Session) error {
	if newSession == nil {
		return errors.New("postgres: se requiere la sesión rotada")
	}

	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&sessionModel{}).
			Where("id = ?", oldSessionID).
			Update("is_revoked", true).Error; err != nil {
			return fmt.Errorf("no se pudo revocar la sesión anterior: %w", err)
		}

		if err := tx.Create(toSessionModel(newSession)).Error; err != nil {
			return fmt.Errorf("no se pudo crear la sesión rotada: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("postgres: no se pudo rotar la sesión: %w", err)
	}
	return nil
}

func mapSessionFindError(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return domain.ErrSessionNotFound
	}
	return fmt.Errorf("postgres: no se pudo buscar la sesión: %w", err)
}
