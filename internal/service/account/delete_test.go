package account_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/account"
)

const (
	dniEnClaro     = "30123456"
	contrasena     = "Contraseña-Segura-1"
	diasDeHerencia = 1095
	hashGuardado   = "hash:" + contrasena
)

var ahora = time.Date(2026, 11, 2, 15, 4, 5, 123456789, time.UTC)

// Dobles escritos a mano, igual que en el resto de internal/service.

type usersFake struct {
	user *domain.User
	err  error

	calls int
	ids   []uuid.UUID
}

func (f *usersFake) FindByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	f.calls++
	f.ids = append(f.ids, id)
	if f.err != nil {
		return nil, f.err
	}
	return f.user, nil
}

type deletionsFake struct {
	err error

	calls     int
	deletions []domain.AccountDeletion
}

func (f *deletionsFake) DeleteAccount(_ context.Context, d domain.AccountDeletion) error {
	f.calls++
	f.deletions = append(f.deletions, d)
	return f.err
}

type hasherFake struct {
	verifyErr error

	calls int
}

func (f *hasherFake) Hash([]byte) (string, error) { panic("account: Hash no se usa en la baja") }

func (f *hasherFake) Verify(pwd []byte, encodedHash string) (bool, error) {
	f.calls++
	if f.verifyErr != nil {
		return false, f.verifyErr
	}
	return "hash:"+string(pwd) == encodedHash, nil
}

type harness struct {
	users     *usersFake
	deletions *deletionsFake
	hasher    *hasherFake
	logs      *bytes.Buffer
	service   *account.DeleteService
	user      *domain.User
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	user := &domain.User{
		ID:            uuid.New(),
		Email:         "vecino@example.com",
		PasswordHash:  hashGuardado,
		DNIHashed:     "blind-index-del-dni",
		DNIEncrypted:  "dni-cifrado-at-rest",
		AccountStatus: domain.AccountStatusActive,
	}
	h := &harness{
		users:     &usersFake{user: user},
		deletions: &deletionsFake{},
		hasher:    &hasherFake{},
		logs:      &bytes.Buffer{},
		user:      user,
	}

	svc, err := account.NewDeleteService(account.DeleteDeps{
		Users:                 h.users,
		Deletions:             h.deletions,
		Hasher:                h.hasher,
		SanctionCarryoverDays: diasDeHerencia,
		Logger:                slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now:                   func() time.Time { return ahora },
	})
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	h.service = svc
	return h
}

func (h *harness) borrar() error {
	return h.service.Delete(context.Background(), h.user.ID, []byte(contrasena))
}

func TestBajaCorrecta(t *testing.T) {
	h := newHarness(t)

	if err := h.borrar(); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if h.deletions.calls != 1 {
		t.Fatalf("DeleteAccount se llamó %d veces, se esperaba 1", h.deletions.calls)
	}
	got := h.deletions.deletions[0]
	if got.UserID != h.user.ID {
		t.Errorf("UserID = %v, se esperaba %v", got.UserID, h.user.ID)
	}
	if !got.DeletedAt.Equal(ahora) {
		t.Errorf("DeletedAt = %v, se esperaba %v", got.DeletedAt, ahora)
	}
	if want := ahora.AddDate(0, 0, diasDeHerencia); !got.CarryoverExpiresAt.Equal(want) {
		t.Errorf("CarryoverExpiresAt = %v, se esperaba deleted_at + %d días = %v", got.CarryoverExpiresAt, diasDeHerencia, want)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("la baja que arma el servicio no valida: %v", err)
	}
}

// Los dos eventos de la baja, en orden, con el contenido del contrato.
func TestBajaEncolaLosDosEventos(t *testing.T) {
	h := newHarness(t)

	if err := h.borrar(); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	events := h.deletions.deletions[0].Events
	if len(events) != 2 {
		t.Fatalf("eventos = %d, se esperaban 2", len(events))
	}

	revoked, deleted := events[0], events[1]
	if revoked.Type != "user.sessions.revoked" || deleted.Type != "user.deleted" {
		t.Fatalf("tipos = %q y %q, se esperaban user.sessions.revoked y user.deleted", revoked.Type, deleted.Type)
	}
	if revoked.ID == uuid.Nil || deleted.ID == uuid.Nil || revoked.ID == deleted.ID {
		t.Errorf("cada evento necesita su propio ID: %v y %v", revoked.ID, deleted.ID)
	}
	if !revoked.CreatedAt.Equal(ahora) || !deleted.CreatedAt.Equal(ahora) {
		t.Errorf("CreatedAt = %v y %v, se esperaba %v", revoked.CreatedAt, deleted.CreatedAt, ahora)
	}

	var revokedPayload map[string]string
	if err := json.Unmarshal(revoked.Payload, &revokedPayload); err != nil {
		t.Fatalf("payload de user.sessions.revoked ilegible: %v", err)
	}
	if revokedPayload["user_id"] != h.user.ID.String() || revokedPayload["reason"] != "ACCOUNT_DELETED" {
		t.Errorf("payload de user.sessions.revoked = %v", revokedPayload)
	}

	var deletedPayload map[string]string
	if err := json.Unmarshal(deleted.Payload, &deletedPayload); err != nil {
		t.Fatalf("payload de user.deleted ilegible: %v", err)
	}
	if deletedPayload["user_id"] != h.user.ID.String() {
		t.Errorf("user_id de user.deleted = %q", deletedPayload["user_id"])
	}
	at, err := time.Parse(time.RFC3339, deletedPayload["deleted_at"])
	if err != nil {
		t.Fatalf("deleted_at no es RFC3339: %v", err)
	}
	if !at.Equal(ahora) {
		t.Errorf("deleted_at = %v, se esperaba %v", at, ahora)
	}
}

// Ningún evento lleva datos personales: ni el DNI, ni el email, ni la contraseña.
func TestLosEventosDeLaBajaNoLlevanDatosPersonales(t *testing.T) {
	h := newHarness(t)

	if err := h.borrar(); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	for _, e := range h.deletions.deletions[0].Events {
		for _, prohibido := range []string{dniEnClaro, h.user.Email, h.user.DNIHashed, h.user.DNIEncrypted, contrasena} {
			if strings.Contains(string(e.Payload), prohibido) {
				t.Errorf("el payload de %s contiene %q: %s", e.Type, prohibido, e.Payload)
			}
		}
	}
}

func TestBajaConContrasenaIncorrecta(t *testing.T) {
	h := newHarness(t)

	err := h.service.Delete(context.Background(), h.user.ID, []byte("otra-contraseña"))

	if !errors.Is(err, domain.ErrInvalidPassword) {
		t.Fatalf("error = %v, se esperaba ErrInvalidPassword", err)
	}
	if h.deletions.calls != 0 {
		t.Errorf("con contraseña incorrecta no se debe borrar nada")
	}
	if !strings.Contains(h.logs.String(), "level=WARN") || !strings.Contains(h.logs.String(), h.user.ID.String()) {
		t.Errorf("el intento rechazado debe quedar en el log en WARN con el user_id: %s", h.logs.String())
	}
}

// La baja es idempotente y no revela nada: un usuario que ya no existe es un
// éxito, sin pedir contraseña.
func TestBajaDeUsuarioInexistenteEsExitosa(t *testing.T) {
	h := newHarness(t)
	h.users.err = domain.ErrUserNotFound

	if err := h.borrar(); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if h.hasher.calls != 0 || h.deletions.calls != 0 {
		t.Errorf("sin usuario no se verifica ni se borra nada")
	}
}

// Si la cuenta desaparece entre la lectura y la transacción (dos bajas a la
// vez), la segunda también es un éxito.
func TestBajaConcurrenteQuePierdeLaCarreraEsExitosa(t *testing.T) {
	h := newHarness(t)
	h.deletions.err = fmt.Errorf("postgres: %w", domain.ErrUserNotFound)

	if err := h.borrar(); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if h.deletions.calls != 1 {
		t.Errorf("DeleteAccount se llamó %d veces, se esperaba 1", h.deletions.calls)
	}
}

// Los errores de infraestructura se devuelven, con el centinela alcanzable para
// que la capa HTTP responda 503.
func TestBajaConBaseNoDisponible(t *testing.T) {
	t.Run("al leer al usuario", func(t *testing.T) {
		h := newHarness(t)
		h.users.err = fmt.Errorf("postgres: %w", domain.ErrDatabaseUnavailable)

		err := h.borrar()

		if !errors.Is(err, domain.ErrDatabaseUnavailable) {
			t.Fatalf("error = %v, se esperaba ErrDatabaseUnavailable", err)
		}
		if h.deletions.calls != 0 {
			t.Errorf("no se debe intentar borrar sin haber leído al usuario")
		}
	})

	t.Run("al ejecutar la transacción", func(t *testing.T) {
		h := newHarness(t)
		h.deletions.err = fmt.Errorf("postgres: %w", domain.ErrDatabaseUnavailable)

		err := h.borrar()

		if !errors.Is(err, domain.ErrDatabaseUnavailable) {
			t.Fatalf("error = %v, se esperaba ErrDatabaseUnavailable", err)
		}
	})
}

// Si no se puede verificar la contraseña (hash corrupto, contraseña absurda) la
// baja no avanza, y tampoco se confunde con una contraseña incorrecta.
func TestBajaFallaCerradaSiNoSePuedeVerificarLaContrasena(t *testing.T) {
	h := newHarness(t)
	h.hasher.verifyErr = errors.New("password: hash con formato inválido")

	err := h.borrar()

	if err == nil || errors.Is(err, domain.ErrInvalidPassword) {
		t.Fatalf("error = %v, se esperaba un error de infraestructura distinto de ErrInvalidPassword", err)
	}
	if h.deletions.calls != 0 {
		t.Errorf("no se debe borrar nada si la contraseña no se pudo verificar")
	}
}

// Ningún log de la baja contiene la contraseña, el DNI ni el hash.
func TestBajaNoLogueaDatosSensibles(t *testing.T) {
	casos := map[string]func(h *harness){
		"éxito":                 func(*harness) {},
		"contraseña incorrecta": func(h *harness) { h.hasher.verifyErr = nil; h.user.PasswordHash = "hash:otra" },
		"falla la baja":         func(h *harness) { h.deletions.err = errors.New("deadlock") },
		"usuario inexistente":   func(h *harness) { h.users.err = domain.ErrUserNotFound },
		"cuenta ya borrada":     func(h *harness) { h.deletions.err = domain.ErrUserNotFound },
	}

	for nombre, preparar := range casos {
		t.Run(nombre, func(t *testing.T) {
			h := newHarness(t)
			preparar(h)

			_ = h.borrar()

			log := h.logs.String()
			for _, prohibido := range []string{dniEnClaro, contrasena, hashGuardado, h.user.DNIHashed, h.user.DNIEncrypted, h.user.Email} {
				if strings.Contains(log, prohibido) {
					t.Errorf("el log contiene %q: %s", prohibido, log)
				}
			}
		})
	}
}

func TestBajaConUsuarioNuloEsUnError(t *testing.T) {
	h := newHarness(t)

	if err := h.service.Delete(context.Background(), uuid.Nil, []byte(contrasena)); err == nil {
		t.Fatal("se esperaba un error")
	}
	if h.users.calls != 0 {
		t.Errorf("no se debe consultar nada con un usuario nulo")
	}
}

func TestNewDeleteServiceValidaSusDependencias(t *testing.T) {
	validas := func() account.DeleteDeps {
		return account.DeleteDeps{
			Users:                 &usersFake{},
			Deletions:             &deletionsFake{},
			Hasher:                &hasherFake{},
			SanctionCarryoverDays: diasDeHerencia,
		}
	}

	casos := map[string]func(d *account.DeleteDeps){
		"sin repositorio de usuarios": func(d *account.DeleteDeps) { d.Users = nil },
		"sin repositorio de la baja":  func(d *account.DeleteDeps) { d.Deletions = nil },
		"sin hasher":                  func(d *account.DeleteDeps) { d.Hasher = nil },
		"herencia en cero":            func(d *account.DeleteDeps) { d.SanctionCarryoverDays = 0 },
		"herencia negativa":           func(d *account.DeleteDeps) { d.SanctionCarryoverDays = -1 },
	}

	for nombre, degradar := range casos {
		t.Run(nombre, func(t *testing.T) {
			deps := validas()
			degradar(&deps)

			if _, err := account.NewDeleteService(deps); err == nil {
				t.Error("se esperaba un error")
			}
		})
	}

	if _, err := account.NewDeleteService(validas()); err != nil {
		t.Errorf("con las dependencias completas no debería fallar: %v", err)
	}
}
