package audit_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/audit"
)

const (
	dniEnClaro   = "30123456"
	selladoDePru = "sellado-hpke-en-base64"
	idDeClave    = "2026-11"
)

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

type cipherFake struct {
	err error

	calls    int
	buffers  [][]byte
	received []string
}

func (f *cipherFake) Encrypt([]byte) (string, error) { panic("audit: Encrypt no se usa en el sellado") }

func (f *cipherFake) Decrypt(ciphertext string) ([]byte, error) {
	f.calls++
	f.received = append(f.received, ciphertext)
	if f.err != nil {
		return nil, f.err
	}
	buf := []byte(dniEnClaro)
	f.buffers = append(f.buffers, buf)
	return buf, nil
}

type sealerFake struct {
	err error

	calls  int
	alerts []uuid.UUID
	plains []string
}

func (f *sealerFake) SealDNI(alertID uuid.UUID, dni []byte) (domain.AuditDNI, error) {
	f.calls++
	f.alerts = append(f.alerts, alertID)
	f.plains = append(f.plains, string(dni))
	if f.err != nil {
		return domain.AuditDNI{}, f.err
	}
	return domain.AuditDNI{Sealed: selladoDePru, KeyID: idDeClave}, nil
}

type harness struct {
	users   *usersFake
	cipher  *cipherFake
	sealer  *sealerFake
	service *audit.DNIService
	user    *domain.User
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	user := &domain.User{ID: uuid.New(), DNIEncrypted: "dni-cifrado-at-rest"}
	h := &harness{
		users:  &usersFake{user: user},
		cipher: &cipherFake{},
		sealer: &sealerFake{},
		user:   user,
	}

	svc, err := audit.NewDNIService(audit.Deps{Users: h.users, Cipher: h.cipher, Sealer: h.sealer})
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	h.service = svc
	return h
}

// Abre el DNI guardado del usuario y lo sella atado a la alerta: el sellador
// recibe el DNI canónico y el alert_id, y el resultado se devuelve tal cual.
func TestSealDNISellaElDNIGuardadoAtadoALaAlerta(t *testing.T) {
	h := newHarness(t)
	alerta := uuid.New()

	got, err := h.service.SealDNI(context.Background(), h.user.ID, alerta)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if got.Sealed != selladoDePru || got.KeyID != idDeClave {
		t.Errorf("resultado = %+v, se esperaba lo que devolvió el sellador", got)
	}
	if len(h.users.ids) != 1 || h.users.ids[0] != h.user.ID {
		t.Errorf("se buscó a los usuarios %v, se esperaba %v", h.users.ids, h.user.ID)
	}
	if len(h.cipher.received) != 1 || h.cipher.received[0] != h.user.DNIEncrypted {
		t.Errorf("el cifrador abrió %v, se esperaba el DNI cifrado del usuario", h.cipher.received)
	}
	if len(h.sealer.alerts) != 1 || h.sealer.alerts[0] != alerta || h.sealer.plains[0] != dniEnClaro {
		t.Errorf("el sellador recibió alertas=%v dni=%v", h.sealer.alerts, h.sealer.plains)
	}
}

// Un usuario que no existe llega como ErrUserNotFound, alcanzable para que la
// capa HTTP responda 404, y no se abre ni se sella nada.
func TestSealDNIDeUnUsuarioInexistente(t *testing.T) {
	h := newHarness(t)
	h.users.err = fmt.Errorf("postgres: %w", domain.ErrUserNotFound)

	_, err := h.service.SealDNI(context.Background(), h.user.ID, uuid.New())

	if !errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("error = %v, se esperaba ErrUserNotFound", err)
	}
	if h.cipher.calls != 0 || h.sealer.calls != 0 {
		t.Errorf("sin usuario no se abre ni se sella nada (cifrador=%d sellador=%d)", h.cipher.calls, h.sealer.calls)
	}
}

// Con la base caída llega ErrDatabaseUnavailable, alcanzable para el 503.
func TestSealDNIConBaseNoDisponible(t *testing.T) {
	h := newHarness(t)
	h.users.err = fmt.Errorf("postgres: %w", domain.ErrDatabaseUnavailable)

	_, err := h.service.SealDNI(context.Background(), h.user.ID, uuid.New())

	if !errors.Is(err, domain.ErrDatabaseUnavailable) {
		t.Fatalf("error = %v, se esperaba ErrDatabaseUnavailable", err)
	}
	if errors.Is(err, domain.ErrUserNotFound) {
		t.Error("una base caída no se puede confundir con un usuario inexistente")
	}
}

// Fail-closed: si no se puede abrir el DNI guardado o sellarlo, no se devuelve
// nada, ni siquiera un criptograma parcial.
func TestSealDNIFallaCerradoSiNoSePuedeAbrirOSellar(t *testing.T) {
	t.Run("no se abre el DNI guardado", func(t *testing.T) {
		h := newHarness(t)
		h.cipher.err = errors.New("aes: autenticación fallida")

		got, err := h.service.SealDNI(context.Background(), h.user.ID, uuid.New())

		if err == nil {
			t.Fatal("se esperaba un error")
		}
		if got != (domain.AuditDNI{}) {
			t.Errorf("con un error no se devuelve nada: %+v", got)
		}
		if h.sealer.calls != 0 {
			t.Errorf("sin DNI no se debe sellar")
		}
	})

	t.Run("no se sella el DNI", func(t *testing.T) {
		h := newHarness(t)
		h.sealer.err = errors.New("hpke: clave inválida")

		got, err := h.service.SealDNI(context.Background(), h.user.ID, uuid.New())

		if err == nil {
			t.Fatal("se esperaba un error")
		}
		if got != (domain.AuditDNI{}) {
			t.Errorf("con un error no se devuelve nada: %+v", got)
		}
	})
}

// El DNI en claro solo existe mientras se sella: el buffer se limpia antes de
// volver, tanto si el sellado sale bien como si falla.
func TestSealDNILimpiaElDNIEnClaro(t *testing.T) {
	casos := map[string]func(h *harness){
		"éxito":            func(*harness) {},
		"falla el sellado": func(h *harness) { h.sealer.err = errors.New("hpke") },
	}

	for nombre, preparar := range casos {
		t.Run(nombre, func(t *testing.T) {
			h := newHarness(t)
			preparar(h)

			_, _ = h.service.SealDNI(context.Background(), h.user.ID, uuid.New())

			if len(h.cipher.buffers) != 1 {
				t.Fatalf("el cifrador entregó %d buffers, se esperaba 1", len(h.cipher.buffers))
			}
			if !bytes.Equal(h.cipher.buffers[0], make([]byte, len(dniEnClaro))) {
				t.Errorf("el buffer del DNI no se limpió: %q", h.cipher.buffers[0])
			}
		})
	}
}

func TestSealDNIConIdentificadoresNulosEsUnError(t *testing.T) {
	h := newHarness(t)

	if _, err := h.service.SealDNI(context.Background(), uuid.Nil, uuid.New()); err == nil {
		t.Error("se esperaba un error sin usuario")
	}
	if _, err := h.service.SealDNI(context.Background(), h.user.ID, uuid.Nil); err == nil {
		t.Error("se esperaba un error sin alerta")
	}
	if h.users.calls != 0 {
		t.Errorf("no se debe consultar nada con identificadores nulos")
	}
}

func TestNewDNIServiceValidaSusDependencias(t *testing.T) {
	validas := func() audit.Deps {
		return audit.Deps{Users: &usersFake{}, Cipher: &cipherFake{}, Sealer: &sealerFake{}}
	}

	casos := map[string]func(d *audit.Deps){
		"sin repositorio de usuarios": func(d *audit.Deps) { d.Users = nil },
		"sin cifrador":                func(d *audit.Deps) { d.Cipher = nil },
		"sin sellador":                func(d *audit.Deps) { d.Sealer = nil },
	}

	for nombre, degradar := range casos {
		t.Run(nombre, func(t *testing.T) {
			deps := validas()
			degradar(&deps)

			if _, err := audit.NewDNIService(deps); err == nil {
				t.Error("se esperaba un error")
			}
		})
	}

	if _, err := audit.NewDNIService(validas()); err != nil {
		t.Errorf("con las dependencias completas no debería fallar: %v", err)
	}
}
