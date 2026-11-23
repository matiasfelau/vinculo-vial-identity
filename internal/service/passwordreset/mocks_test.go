package passwordreset_test

import (
	"context"
	"sync"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// Dobles escritos a mano, como en el resto de internal/service: pocos métodos y
// el comportamiento de cada caso a la vista en el propio test.

type decryptorMock struct {
	plaintext []byte
	err       error
}

func (m *decryptorMock) Decrypt(_, _ []byte) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	// Copia: el servicio limpia el buffer que recibe.
	return append([]byte(nil), m.plaintext...), nil
}

func (m *decryptorMock) DecryptCombined([]byte) ([]byte, error) { panic("no se usa") }

// indexerMock deriva un índice reconocible: dos DNI iguales dan el mismo índice y
// dos distintos, índices distintos.
type indexerMock struct{}

func (indexerMock) Index(value []byte) string { return "idx:" + string(value) }

type hasherMock struct {
	err error

	mu        sync.Mutex
	passwords []string
}

func (m *hasherMock) Hash(pwd []byte) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.passwords = append(m.passwords, string(pwd))
	if m.err != nil {
		return "", m.err
	}
	return "$argon2id$" + string(pwd), nil
}

func (m *hasherMock) Verify([]byte, string) (bool, error) { panic("no se usa") }

type renaperMock struct {
	verified bool
	err      error

	mu      sync.Mutex
	calls   int
	dni     []string
	tramite []string
	sexo    []string
	selfie  [][]byte
}

func (m *renaperMock) ValidateIdentity(_ context.Context, dni, tramite, sexo, selfie []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls++
	m.dni = append(m.dni, string(dni))
	m.tramite = append(m.tramite, string(tramite))
	m.sexo = append(m.sexo, string(sexo))
	m.selfie = append(m.selfie, append([]byte(nil), selfie...))
	if m.err != nil {
		return false, m.err
	}
	return m.verified, nil
}

// usersMock resuelve las dos búsquedas que usa la recuperación: por Blind Index
// de DNI (pedido y confirmación) y por id (revalidación).
type usersMock struct {
	mu       sync.Mutex
	byDNI    map[string]*domain.User
	byID     map[uuid.UUID]*domain.User
	dniErr   error
	idErr    error
	dniCalls int
	idCalls  int
}

func newUsersMock() *usersMock {
	return &usersMock{byDNI: map[string]*domain.User{}, byID: map[uuid.UUID]*domain.User{}}
}

func (m *usersMock) add(u *domain.User) {
	m.byDNI[u.DNIHashed] = u
	m.byID[u.ID] = u
}

func (m *usersMock) FindByDNIHashed(_ context.Context, dniHashed string) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dniCalls++
	if m.dniErr != nil {
		return nil, m.dniErr
	}
	if u, ok := m.byDNI[dniHashed]; ok {
		copied := *u
		return &copied, nil
	}
	return nil, domain.ErrUserNotFound
}

func (m *usersMock) FindByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.idCalls++
	if m.idErr != nil {
		return nil, m.idErr
	}
	if u, ok := m.byID[id]; ok {
		copied := *u
		return &copied, nil
	}
	return nil, domain.ErrUserNotFound
}

func (m *usersMock) Create(context.Context, *domain.User, domain.OutboxEvent, *domain.GrantConsumption) error {
	panic("no se usa")
}
func (m *usersMock) ExistsByEmail(context.Context, string) (bool, error) { panic("no se usa") }
