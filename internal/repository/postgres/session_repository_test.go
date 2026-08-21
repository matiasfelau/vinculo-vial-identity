// Tests internos al paquete: ejercitan el mapeo entidad↔modelo, igual que
// user_repository_test.go. Las sentencias contra PostgreSQL —incluida la
// restricción de clave foránea— quedan fuera de los tests unitarios; se cubren
// con el docker-compose local.
package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

func TestMapeoSesionEsSimetrico(t *testing.T) {
	original := &domain.Session{
		ID:               uuid.New(),
		UserID:           uuid.New(),
		RefreshTokenHash: "5f4dcc3b5aa765d61d8327deb882cf99" + "5f4dcc3b5aa765d61d8327deb882cf99",
		IsRevoked:        false,
		ExpiresAt:        time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC),
		CreatedAt:        time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC),
	}

	got := toSessionModel(original).toDomain()

	if *got != *original {
		t.Errorf("ida y vuelta = %+v, se esperaba %+v", *got, *original)
	}
}

func TestSessionTableName(t *testing.T) {
	if got := (sessionModel{}).TableName(); got != "sessions" {
		t.Errorf("tabla = %q, se esperaba %q", got, "sessions")
	}
}

func TestNewSessionRepositoryRechazaConexionNula(t *testing.T) {
	if _, err := NewSessionRepository(t.Context(), nil); err == nil {
		t.Error("se esperaba un error al construir sin conexión")
	}
}

func TestSessionCreateRechazaSesionNula(t *testing.T) {
	r := &SessionRepository{}

	if err := r.Create(t.Context(), nil); err == nil {
		t.Error("se esperaba un error al crear una sesión nula")
	}
}

func TestMapSessionFindErrorTraduceRegistroNoEncontrado(t *testing.T) {
	got := mapSessionFindError(gorm.ErrRecordNotFound)
	if !errors.Is(got, domain.ErrSessionNotFound) {
		t.Errorf("error = %v, se esperaba ErrSessionNotFound", got)
	}
}

func TestMapSessionFindErrorNoTraduceOtrosFallos(t *testing.T) {
	original := errors.New("connection reset by peer")
	got := mapSessionFindError(original)

	if errors.Is(got, domain.ErrSessionNotFound) {
		t.Errorf("%v no debería traducirse a ErrSessionNotFound", original)
	}
	if !errors.Is(got, original) {
		t.Errorf("el error original debe quedar envuelto para diagnóstico: %v", got)
	}
}
