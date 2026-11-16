// Package postgres implementa la persistencia sobre PostgreSQL con GORM.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// pgUniqueViolation es el SQLSTATE que devuelve PostgreSQL al violar un índice
// único (23505).
const pgUniqueViolation = "23505"

// UserRepository implementa domain.UserRepository.
type UserRepository struct {
	db *gorm.DB
}

// NewUserRepository construye el repositorio y ejecuta AutoMigrate.
//
// Migrar en la inicialización es la decisión de MVP acordada: evita sumar una
// herramienta de migraciones al alcance de US-01. La contrapartida es que
// AutoMigrate solo agrega columnas e índices —nunca los borra ni los altera de
// forma destructiva—, así que en cuanto haga falta un cambio de tipo o un
// backfill hay que migrar a una herramienta con versionado (golang-migrate,
// atlas) antes de tener datos reales en producción.
func NewUserRepository(ctx context.Context, db *gorm.DB) (*UserRepository, error) {
	if db == nil {
		return nil, errors.New("postgres: se requiere una conexión GORM")
	}

	if err := db.WithContext(ctx).AutoMigrate(&userModel{}); err != nil {
		return nil, fmt.Errorf("postgres: falló la migración del esquema: %w", err)
	}

	// Create consulta sanction_carryovers para la herencia de sanciones (US-11),
	// así que la tabla tiene que existir antes del primer alta.
	if err := ensureSanctionCarryovers(ctx, db); err != nil {
		return nil, err
	}

	// Create consume el grant de verificación de email (US-13) en la transacción
	// del alta, así que email_challenges tiene que existir antes del primer alta.
	if err := ensureEmailChallenges(ctx, db); err != nil {
		return nil, err
	}

	return &UserRepository{db: db}, nil
}

// consumeEmailVerificationGrant marca como usado el grant de verificación de
// email del alta. El UPDATE es la guarda: solo afecta una fila si el grant es de
// ese email, no se usó y no venció, y todo eso se decide en la base, en la misma
// transacción que crea el usuario, así dos altas con el mismo token no pasan las
// dos.
func consumeEmailVerificationGrant(tx *gorm.DB, g *domain.GrantConsumption) error {
	res := tx.Model(&emailChallengeModel{}).
		Where("purpose = ? AND subject_hmac = ? AND grant_hash = ?", string(g.Purpose), g.SubjectHMAC, g.GrantHash).
		Where("consumed_at IS NULL AND grant_expires_at > ?", g.Now.UTC()).
		Update("consumed_at", g.Now.UTC())
	if res.Error != nil {
		return fmt.Errorf("no se pudo consumir el token de verificación: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return domain.ErrEmailNotVerified
	}
	return nil
}

// claimSanctionCarryover borra, y devuelve, la sanción vigente con ese Blind
// Index de DNI. Un único DELETE ... RETURNING alcanza: dos altas concurrentes con
// el mismo DNI se serializan en el bloqueo de la fila, y la segunda, cuando la
// primera confirma, ya no la encuentra. Una fila vencida no se hereda; la borra
// el barrido.
const claimSanctionCarryover = `
DELETE FROM sanction_carryovers
WHERE dni_hmac = ? AND expires_at > ?
RETURNING dni_hmac, account_status, reputation_score, report_count, created_at, expires_at`

// claimSanction reclama la sanción vigente de dniHashed, o devuelve nil si no
// hay ninguna. Tiene que correr dentro de la transacción del alta.
func claimSanction(tx *gorm.DB, dniHashed string, now time.Time) (*domain.SanctionCarryover, error) {
	var rows []sanctionCarryoverModel
	if err := tx.Raw(claimSanctionCarryover, dniHashed, now.UTC()).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("no se pudo consultar la sanción del DNI: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	carryover := rows[0].toDomain()
	return &carryover, nil
}

// Create inserta el usuario y, en la misma transacción, le hace heredar la
// sanción vigente que dejó una cuenta anterior del mismo DNI (US-11). Ver
// domain.UserRepository.Create.
//
// La detección de duplicados se delega a los índices únicos de la base en lugar
// de hacer un SELECT previo: entre la consulta y el INSERT hay una ventana en la
// que otra petición concurrente puede insertar el mismo email o DNI, y solo la
// restricción de la base cierra esa carrera. La sanción se reclama antes del
// INSERT y dentro de la misma transacción: si el INSERT choca con un duplicado,
// el reclamo se deshace y la sanción sigue disponible.
//
// La colisión se colapsa en domain.ErrDuplicateUser sin decir qué índice se violó:
// distinguir "ese email ya existe" de "ese DNI ya existe" convertiría el endpoint
// en un oráculo para saber si una persona está registrada.
func (r *UserRepository) Create(ctx context.Context, u *domain.User, inheritedStatus domain.OutboxEvent, grant *domain.GrantConsumption) error {
	if u == nil {
		return errors.New("postgres: se requiere un usuario")
	}

	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	// Se trabaja sobre una copia: u solo cambia si el alta se confirma.
	candidate := *u

	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// El grant se consume primero: si ya no sirve, no se hace nada más. Si el
		// INSERT que sigue choca con un duplicado, la transacción entera se
		// deshace y el grant queda sin gastar.
		if grant != nil {
			if err := consumeEmailVerificationGrant(tx, grant); err != nil {
				return err
			}
		}

		sanction, err := claimSanction(tx, candidate.DNIHashed, candidate.CreatedAt)
		if err != nil {
			return err
		}
		if sanction != nil {
			candidate.InheritSanction(*sanction)
		}

		if err := tx.Create(toModel(&candidate)).Error; err != nil {
			return err
		}

		if sanction != nil && candidate.AccountStatus == domain.AccountStatusUnderReview {
			if inheritedStatus.Type != domain.EventTypeUserStatusChanged {
				return errors.New("falta el user.status.changed de la sanción heredada")
			}
			if err := tx.Create(toOutboxModel(&inheritedStatus)).Error; err != nil {
				return fmt.Errorf("no se pudo encolar el evento de outbox: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, domain.ErrEmailNotVerified) {
			return domain.ErrEmailNotVerified
		}
		return mapCreateError(err)
	}

	*u = candidate
	return nil
}

// ExistsByEmail informa si hay una cuenta con ese email. Un único SELECT sobre el
// índice único de email, sin traer ninguna fila.
func (r *UserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	var count int64
	if err := r.db.WithContext(ctx).Model(&userModel{}).Where("email = ?", email).Limit(1).Count(&count).Error; err != nil {
		if classified := classifyDBError(err); errors.Is(classified, domain.ErrDatabaseUnavailable) {
			return false, classified
		}
		return false, fmt.Errorf("postgres: no se pudo consultar el email: %w", err)
	}
	return count > 0, nil
}

// FindByID busca un usuario por su identificador.
func (r *UserRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	var m userModel
	if err := r.db.WithContext(ctx).Where("id = ?", id).Take(&m).Error; err != nil {
		return nil, mapFindError(err)
	}
	return m.toDomain(), nil
}

// FindByDNIHashed busca un usuario por el Blind Index de su DNI. Es la única
// vía de búsqueda del login (US-02): nunca se busca por DNI en claro, que no
// se persiste.
func (r *UserRepository) FindByDNIHashed(ctx context.Context, dniHashed string) (*domain.User, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	var m userModel
	if err := r.db.WithContext(ctx).Where("dni_hashed = ?", dniHashed).Take(&m).Error; err != nil {
		return nil, mapFindError(err)
	}
	return m.toDomain(), nil
}

func mapFindError(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return domain.ErrUserNotFound
	}
	if classified := classifyDBError(err); errors.Is(classified, domain.ErrDatabaseUnavailable) {
		return classified
	}
	return fmt.Errorf("postgres: no se pudo buscar el usuario: %w", err)
}

func mapCreateError(err error) error {
	// La indisponibilidad de la base se distingue primero: un SQLSTATE de
	// conexión o de recursos agotados nunca coincide con el de una violación
	// de unicidad, así que el orden entre ambos chequeos no cambia el
	// resultado, pero clasificar primero deja la intención más clara.
	if classified := classifyDBError(err); errors.Is(classified, domain.ErrDatabaseUnavailable) {
		return classified
	}

	// TranslateError de GORM cubre el caso normal; el chequeo de SQLSTATE es el
	// respaldo si esa opción se desactiva o el driver cambia.
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return domain.ErrDuplicateUser
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
		return domain.ErrDuplicateUser
	}

	// El error del driver puede arrastrar el detalle de la fila rechazada
	// (incluido dni_hashed), así que se envuelve sin exponerlo hacia afuera:
	// solo el log estructurado del servicio decide qué registrar.
	return fmt.Errorf("postgres: no se pudo crear el usuario: %w", err)
}
