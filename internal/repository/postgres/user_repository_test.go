// Tests internos al paquete: ejercitan el mapeo entidad↔modelo y la traducción
// de errores del driver, que es donde vive la lógica propia del repositorio.
//
// Las sentencias contra PostgreSQL quedan fuera de los tests unitarios, según lo
// acordado en CLAUDE.md; se cubren con el docker-compose local.
package postgres

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

func TestMapCreateErrorTraduceDuplicados(t *testing.T) {
	cases := map[string]error{
		"centinela de GORM":               gorm.ErrDuplicatedKey,
		"centinela de GORM envuelto":      fmt.Errorf("al insertar: %w", gorm.ErrDuplicatedKey),
		"SQLSTATE 23505 del driver":       &pgconn.PgError{Code: pgUniqueViolation, ConstraintName: "uix_users_email"},
		"SQLSTATE 23505 sobre dni_hashed": &pgconn.PgError{Code: pgUniqueViolation, ConstraintName: "uix_users_dni_hashed"},
		"SQLSTATE 23505 envuelto":         fmt.Errorf("al insertar: %w", &pgconn.PgError{Code: pgUniqueViolation}),
	}

	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			got := mapCreateError(err)
			if !errors.Is(got, domain.ErrDuplicateUser) {
				t.Errorf("error = %v, se esperaba ErrDuplicateUser", got)
			}
		})
	}
}

// Colapsar ambas colisiones en el mismo error es lo que evita que el endpoint
// sirva como oráculo para saber si una persona ya está registrada.
func TestMapCreateErrorNoDistingueQueIndiceSeViolo(t *testing.T) {
	porEmail := mapCreateError(&pgconn.PgError{Code: pgUniqueViolation, ConstraintName: "uix_users_email"})
	porDNI := mapCreateError(&pgconn.PgError{Code: pgUniqueViolation, ConstraintName: "uix_users_dni_hashed"})

	if porEmail.Error() != porDNI.Error() {
		t.Errorf("los mensajes revelan qué índice colisionó: %q vs %q", porEmail, porDNI)
	}
}

func TestMapCreateErrorNoTraduceOtrosFallos(t *testing.T) {
	cases := map[string]error{
		"violación de not null":  &pgconn.PgError{Code: "23502"},
		"violación de check":     &pgconn.PgError{Code: "23514"},
		"tabla inexistente":      &pgconn.PgError{Code: "42P01"},
		"registro no encontrado": gorm.ErrRecordNotFound,
		"error de red":           errors.New("connection reset by peer"),
	}

	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			got := mapCreateError(err)
			if errors.Is(got, domain.ErrDuplicateUser) {
				t.Errorf("%v no debería traducirse a ErrDuplicateUser", err)
			}
			if !errors.Is(got, err) {
				t.Errorf("el error original debe quedar envuelto para diagnóstico: %v", got)
			}
		})
	}
}

func TestMapeoEntidadModeloEsSimetrico(t *testing.T) {
	original := &domain.User{
		ID:            uuid.New(),
		Email:         "vecino@vinculovial.ar",
		PasswordHash:  "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA",
		DNIHashed:     "5f4dcc3b5aa765d61d8327deb882cf99",
		DNIEncrypted:  "Y2lmcmFkbw==",
		AccountStatus: domain.AccountStatusActive,
		CreatedAt:     time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC),
		UpdatedAt:     time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC),
	}

	got := toModel(original).toDomain()

	if *got != *original {
		t.Errorf("ida y vuelta = %+v, se esperaba %+v", *got, *original)
	}
}

// El hash Argon2id se persiste en la columna `password` del esquema acordado,
// aunque en el dominio el campo se llame PasswordHash.
func TestToModelMapeaElHashALaColumnaPassword(t *testing.T) {
	const hash = "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA"

	m := toModel(&domain.User{PasswordHash: hash, AccountStatus: domain.AccountStatusActive})

	if m.Password != hash {
		t.Errorf("password = %q, se esperaba %q", m.Password, hash)
	}
}

func TestTableName(t *testing.T) {
	if got := (userModel{}).TableName(); got != "users" {
		t.Errorf("tabla = %q, se esperaba %q", got, "users")
	}
}

func TestNewUserRepositoryRechazaConexionNula(t *testing.T) {
	if _, err := NewUserRepository(t.Context(), nil); err == nil {
		t.Error("se esperaba un error al construir sin conexión")
	}
}

func TestCreateRechazaUsuarioNulo(t *testing.T) {
	r := &UserRepository{}

	if err := r.Create(t.Context(), nil); err == nil {
		t.Error("se esperaba un error al crear un usuario nulo")
	}
}

// El error del driver puede arrastrar el detalle de la fila rechazada: el
// repositorio no debe propagarlo hacia afuera.
func TestMapCreateErrorNoFiltraDatosSensibles(t *testing.T) {
	const dniHashed = "5f4dcc3b5aa765d61d8327deb882cf99"

	got := mapCreateError(&pgconn.PgError{
		Code:           pgUniqueViolation,
		ConstraintName: "uix_users_dni_hashed",
		Detail:         fmt.Sprintf("Key (dni_hashed)=(%s) already exists.", dniHashed),
	})

	if errors.Is(got, domain.ErrDuplicateUser) && got.Error() != domain.ErrDuplicateUser.Error() {
		t.Errorf("el duplicado debe colapsar en el centinela, se obtuvo %q", got)
	}
}

func TestMapFindErrorTraduceRegistroNoEncontrado(t *testing.T) {
	got := mapFindError(gorm.ErrRecordNotFound)
	if !errors.Is(got, domain.ErrUserNotFound) {
		t.Errorf("error = %v, se esperaba ErrUserNotFound", got)
	}
}

func TestMapFindErrorNoTraduceOtrosFallos(t *testing.T) {
	original := errors.New("connection reset by peer")
	got := mapFindError(original)

	if errors.Is(got, domain.ErrUserNotFound) {
		t.Errorf("%v no debería traducirse a ErrUserNotFound", original)
	}
	if !errors.Is(got, original) {
		t.Errorf("el error original debe quedar envuelto para diagnóstico: %v", got)
	}
}

func TestCloseToleraConexionNula(t *testing.T) {
	if err := Close(nil); err != nil {
		t.Errorf("error inesperado: %v", err)
	}
}

func TestSanitizeDSNRedactaLaCredencial(t *testing.T) {
	const dsn = "host=db user=identity password=sup3rs3cr3t dbname=identity"

	got := sanitizeDSN(fmt.Errorf("no se pudo conectar con %s", dsn), dsn)

	if got == nil {
		t.Fatal("se esperaba un error")
	}
	if strings.Contains(got.Error(), "sup3rs3cr3t") {
		t.Errorf("el error filtra la credencial: %q", got)
	}
}

func TestSanitizeDSNPreservaErroresSinCredencial(t *testing.T) {
	original := errors.New("connection refused")

	if got := sanitizeDSN(original, "host=db password=x"); !errors.Is(got, original) {
		t.Errorf("se esperaba el error original intacto, se obtuvo %v", got)
	}
	if got := sanitizeDSN(nil, "host=db"); got != nil {
		t.Errorf("se esperaba nil, se obtuvo %v", got)
	}
}
