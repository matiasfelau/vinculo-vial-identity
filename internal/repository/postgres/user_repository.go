// Package postgres implementa la persistencia sobre PostgreSQL con GORM.
package postgres

import (
	"context"
	"errors"
	"fmt"

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

	if err := r.db.WithContext(ctx).Create(toModel(u)).Error; err != nil {
		return mapCreateError(err)
	}
	return nil
}

func mapCreateError(err error) error {
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
