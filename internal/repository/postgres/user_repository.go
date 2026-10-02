// Package postgres implementa la persistencia sobre PostgreSQL con GORM.
package postgres

import (
	"context"
	"errors"
	"fmt"

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

	return &UserRepository{db: db}, nil
}

// Create inserta el usuario.
//
// La detección de duplicados se delega a los índices únicos de la base en lugar
// de hacer un SELECT previo: entre la consulta y el INSERT hay una ventana en la
// que otra petición concurrente puede insertar el mismo email o DNI, y solo la
// restricción de la base cierra esa carrera.
//
// La colisión se colapsa en domain.ErrDuplicateUser sin decir qué índice se violó:
// distinguir "ese email ya existe" de "ese DNI ya existe" convertiría el endpoint
// en un oráculo para saber si una persona está registrada.
func (r *UserRepository) Create(ctx context.Context, u *domain.User) error {
	if u == nil {
		return errors.New("postgres: se requiere un usuario")
	}

	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	if err := r.db.WithContext(ctx).Create(toModel(u)).Error; err != nil {
		return mapCreateError(err)
	}
	return nil
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
