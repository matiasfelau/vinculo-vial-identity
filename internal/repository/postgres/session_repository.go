package postgres

import (
	"context"
	"errors"
	"fmt"

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
