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

	// Create consulta legal_hold.user_holds para la herencia de sanciones
	// (US-11), así que el esquema tiene que existir antes del primer alta.
	if err := ensureLegalHoldSchema(ctx, db); err != nil {
		return nil, err
	}

	return &UserRepository{db: db}, nil
}

// claimHeldSanction anula, y devuelve, la sanción del hold vigente con ese
// Blind Index de DNI. El UPDATE devuelve los valores nuevos (todos NULL), así
// que los viejos se leen en un CTE con FOR UPDATE: dos altas concurrentes con el
// mismo DNI se serializan en el bloqueo del hold, y la segunda ya no lo
// encuentra. Al anular también dni_hmac, el hold deja de poder vincularse con
// una cuenta nueva.
const claimHeldSanction = `
WITH held AS (
	SELECT user_id, account_status, reputation_score, report_count
	FROM legal_hold.user_holds
	WHERE dni_hmac = ? AND destroy_at > ?
	FOR UPDATE
)
UPDATE legal_hold.user_holds AS h
SET dni_hmac = NULL, account_status = NULL, reputation_score = NULL, report_count = NULL
FROM held
WHERE h.user_id = held.user_id
RETURNING held.account_status, held.reputation_score, held.report_count`

// heldSanctionRow es lo que devuelve claimHeldSanction.
type heldSanctionRow struct {
	AccountStatus   *string
	ReputationScore *int
	ReportCount     *int
}

// claimSanction reclama la sanción vigente de dniHashed, o devuelve nil si no
// hay ninguna. Tiene que correr dentro de la transacción del alta.
func claimSanction(tx *gorm.DB, dniHashed string, now time.Time) (*domain.HoldSanction, error) {
	var rows []heldSanctionRow
	if err := tx.Raw(claimHeldSanction, dniHashed, now.UTC()).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("no se pudo consultar el hold del DNI: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}

	// Un hold con dni_hmac siempre trae los tres campos (la baja los escribe
	// juntos); si alguno falta, no hay sanción que heredar.
	row := rows[0]
	if row.AccountStatus == nil || row.ReputationScore == nil || row.ReportCount == nil {
		return nil, nil
	}
	return &domain.HoldSanction{
		DNIHMAC:         dniHashed,
		AccountStatus:   domain.AccountStatus(*row.AccountStatus),
		ReputationScore: *row.ReputationScore,
		ReportCount:     *row.ReportCount,
	}, nil
}

// Create inserta el usuario y, en la misma transacción, le hace heredar la
// sanción de un hold vigente del mismo DNI (US-11). Ver
// domain.UserRepository.Create.
//
// La detección de duplicados se delega a los índices únicos de la base en lugar
// de hacer un SELECT previo: entre la consulta y el INSERT hay una ventana en la
// que otra petición concurrente puede insertar el mismo email o DNI, y solo la
// restricción de la base cierra esa carrera. La sanción se reclama antes del
// INSERT y dentro de la misma transacción: si el INSERT choca con un duplicado,
// el reclamo se deshace y el hold conserva su sanción.
//
// La colisión se colapsa en domain.ErrDuplicateUser sin decir qué índice se violó:
// distinguir "ese email ya existe" de "ese DNI ya existe" convertiría el endpoint
// en un oráculo para saber si una persona está registrada.
func (r *UserRepository) Create(ctx context.Context, u *domain.User, inheritedStatus domain.OutboxEvent) error {
	if u == nil {
		return errors.New("postgres: se requiere un usuario")
	}

	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	// Se trabaja sobre una copia: u solo cambia si el alta se confirma.
	candidate := *u

	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
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
		return mapCreateError(err)
	}

	*u = candidate
	return nil
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

// FindByOwnerAndDNIHash busca el usuario cuyo id y Blind Index de DNI
// coinciden a la vez. El predicado combina las dos condiciones con AND en
// una sola consulta a propósito: así "ese owner_id no existe" y "existe,
// pero el DNI no es el suyo" producen el mismo gorm.ErrRecordNotFound —y por
// lo tanto el mismo domain.ErrUserNotFound— sin que este repositorio tenga
// que distinguirlos.
func (r *UserRepository) FindByOwnerAndDNIHash(ctx context.Context, ownerID uuid.UUID, dniHashed string) (*domain.User, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	var m userModel
	if err := r.db.WithContext(ctx).Where("id = ? AND dni_hashed = ?", ownerID, dniHashed).Take(&m).Error; err != nil {
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
