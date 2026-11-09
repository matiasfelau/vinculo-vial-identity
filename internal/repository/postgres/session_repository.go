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

// sessionsMigrationLockKey es la clave del advisory lock que serializa la
// migración de sessions.started_at cuando varias réplicas arrancan a la vez.
const sessionsMigrationLockKey int64 = 0x6c68_0003

// backfillSessionsStartedAt agrega started_at a una tabla sessions que ya
// existe sin la columna (US-12) y la rellena con created_at. AutoMigrate no
// sirve para esto: agregaría la columna NOT NULL sobre filas existentes y
// Postgres lo rechaza. Es idempotente y no ejecuta DDL si la tabla no existe
// (AutoMigrate la crea después con la columna ya declarada) o si started_at ya
// es NOT NULL: así, con la migración aplicada a mano por un DBA, el rol del
// servicio no necesita ser dueño de la tabla para arrancar.
const backfillSessionsStartedAt = `
DO $$
BEGIN
	IF to_regclass('sessions') IS NOT NULL AND NOT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'sessions'
			AND column_name = 'started_at' AND is_nullable = 'NO'
	) THEN
		ALTER TABLE sessions ADD COLUMN IF NOT EXISTS started_at timestamptz;
		UPDATE sessions SET started_at = created_at WHERE started_at IS NULL;
		ALTER TABLE sessions ALTER COLUMN started_at SET NOT NULL;
	END IF;
END $$;
`

// migrateSessions deja sessions en el esquema vigente: backfill de started_at
// y AutoMigrate, en una transacción bajo advisory lock para que las réplicas
// que arrancan juntas no choquen en el catálogo.
func migrateSessions(ctx context.Context, db *gorm.DB) error {
	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", sessionsMigrationLockKey).Error; err != nil {
			return fmt.Errorf("no se pudo tomar el lock de la migración: %w", err)
		}
		if err := tx.Exec(backfillSessionsStartedAt).Error; err != nil {
			return fmt.Errorf("no se pudo rellenar started_at: %w", err)
		}
		if err := tx.AutoMigrate(&sessionModel{}); err != nil {
			return fmt.Errorf("no se pudo migrar el esquema: %w", err)
		}
		return nil
	})
}

// NewSessionRepository construye el repositorio, ejecuta AutoMigrate y agrega
// la restricción de clave foránea hacia users.
//
// Requiere que la tabla users ya exista: se asume que el repositorio de
// usuarios se inicializa primero, tal como lo hace cmd/api/main.go.
func NewSessionRepository(ctx context.Context, db *gorm.DB) (*SessionRepository, error) {
	if db == nil {
		return nil, errors.New("postgres: se requiere una conexión GORM")
	}

	if err := migrateSessions(ctx, db); err != nil {
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

	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	if err := r.db.WithContext(ctx).Create(toSessionModel(s)).Error; err != nil {
		return fmt.Errorf("postgres: no se pudo crear la sesión: %w", classifyDBError(err))
	}
	return nil
}

// FindByHash busca una sesión por el SHA-256 de su Refresh Token.
func (r *SessionRepository) FindByHash(ctx context.Context, refreshTokenHash string) (*domain.Session, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	var m sessionModel
	if err := r.db.WithContext(ctx).Where("refresh_token_hash = ?", refreshTokenHash).Take(&m).Error; err != nil {
		return nil, mapSessionFindError(err)
	}
	return m.toDomain(), nil
}

// RevokeByID marca como revocada una única sesión.
func (r *SessionRepository) RevokeByID(ctx context.Context, id uuid.UUID) error {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	if err := r.db.WithContext(ctx).
		Model(&sessionModel{}).
		Where("id = ?", id).
		Update("is_revoked", true).Error; err != nil {
		return fmt.Errorf("postgres: no se pudo revocar la sesión: %w", classifyDBError(err))
	}
	return nil
}

// RevokeByHash marca como revocada la sesión cuyo hash de Refresh Token
// coincide. Ver la nota de domain.SessionRepository.RevokeByHash: que no
// coincida ninguna fila no es un error.
func (r *SessionRepository) RevokeByHash(ctx context.Context, refreshTokenHash string) error {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	if err := r.db.WithContext(ctx).
		Model(&sessionModel{}).
		Where("refresh_token_hash = ?", refreshTokenHash).
		Update("is_revoked", true).Error; err != nil {
		return fmt.Errorf("postgres: no se pudo revocar la sesión: %w", classifyDBError(err))
	}
	return nil
}

// RevokeAllByUserID marca como revocadas todas las sesiones de un usuario y,
// si outboxEvent no es nil, lo persiste en la misma transacción (patrón
// Transactional Outbox): si falla cualquiera de los dos INSERT/UPDATE, el
// otro se deshace. Ninguna consulta por fuera de esta transacción puede ver
// la revocación sin ver también el evento pendiente, ni viceversa — resuelve
// la doble escritura no atómica que antes dejaba este método.
//
// No distingue si había alguna sesión vigente para ese user_id: revocar cero
// filas no es un error, es simplemente que no había nada que revocar.
func (r *SessionRepository) RevokeAllByUserID(ctx context.Context, userID uuid.UUID, outboxEvent *domain.OutboxEvent) error {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&sessionModel{}).
			Where("user_id = ?", userID).
			Update("is_revoked", true).Error; err != nil {
			return fmt.Errorf("no se pudo revocar las sesiones del usuario: %w", err)
		}

		if outboxEvent != nil {
			if err := tx.Create(toOutboxModel(outboxEvent)).Error; err != nil {
				return fmt.Errorf("no se pudo encolar el evento de outbox: %w", err)
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("postgres: no se pudo ejecutar la defensa activa: %w", classifyDBError(err))
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

	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

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
		return fmt.Errorf("postgres: no se pudo rotar la sesión: %w", classifyDBError(err))
	}
	return nil
}

func mapSessionFindError(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return domain.ErrSessionNotFound
	}
	if classified := classifyDBError(err); errors.Is(classified, domain.ErrDatabaseUnavailable) {
		return classified
	}
	return fmt.Errorf("postgres: no se pudo buscar la sesión: %w", err)
}
