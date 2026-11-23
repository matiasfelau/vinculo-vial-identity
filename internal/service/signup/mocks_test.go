package signup_test

import (
	"context"
	"sync"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// Dobles escritos a mano en lugar de generados: son seis interfaces de uno o dos
// métodos y así el comportamiento de cada caso queda a la vista en el propio test.

type decryptorMock struct {
	plaintext []byte
	err       error

	calls              int
	ephemeralPublicKey []byte
	ciphertext         []byte
}

func (m *decryptorMock) Decrypt(ephemeralPublicKey, ciphertext []byte) ([]byte, error) {
	m.calls++
	m.ephemeralPublicKey = ephemeralPublicKey
	m.ciphertext = ciphertext
	if m.err != nil {
		return nil, m.err
	}
	// Copia: el servicio limpia el buffer devuelto, y sin copiar se corrompería
	// el dato del propio doble entre llamadas.
	out := make([]byte, len(m.plaintext))
	copy(out, m.plaintext)
	return out, nil
}

// DecryptCombined no lo ejercita ningún test de signup: es parte de
// domain.HPKEDecryptor solo porque la interfaz lo declara (lo usan las pruebas
// del sellado hacia Audit).
func (m *decryptorMock) DecryptCombined([]byte) ([]byte, error) {
	panic("signup: DecryptCombined no se usa en el alta")
}

type indexerMock struct {
	index string

	calls  int
	values []string
}

func (m *indexerMock) Index(value []byte) string {
	m.calls++
	m.values = append(m.values, string(value))
	if m.index != "" {
		return m.index
	}
	return "blind-index-de:" + string(value)
}

type cipherMock struct {
	err error

	calls      int
	plaintexts []string
}

func (m *cipherMock) Encrypt(plaintext []byte) (string, error) {
	m.calls++
	m.plaintexts = append(m.plaintexts, string(plaintext))
	if m.err != nil {
		return "", m.err
	}
	return "cifrado:" + string(plaintext), nil
}

func (m *cipherMock) Decrypt(ciphertext string) ([]byte, error) {
	return []byte(ciphertext), nil
}

type hasherMock struct {
	err error

	calls     int
	passwords []string
}

func (m *hasherMock) Hash(pwd []byte) (string, error) {
	m.calls++
	m.passwords = append(m.passwords, string(pwd))
	if m.err != nil {
		return "", m.err
	}
	return "$argon2id$" + string(pwd), nil
}

func (m *hasherMock) Verify(pwd []byte, encodedHash string) (bool, error) {
	return "$argon2id$"+string(pwd) == encodedHash, nil
}

type renaperMock struct {
	// verified es la respuesta cuando err es nil. El harness lo inicializa en
	// true: la vía feliz asume una identidad verificada, igual que el resto de
	// los dobles asume éxito salvo que el test configure lo contrario.
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
	// Copia: el servicio limpia el buffer que pasó apenas este método vuelve.
	m.selfie = append(m.selfie, append([]byte(nil), selfie...))

	if m.err != nil {
		return false, m.err
	}
	return m.verified, nil
}

type repositoryMock struct {
	err error
	// inherit, si no es nil, simula una sanción vigente del mismo DNI: Create le
	// hace heredar la sanción al usuario, como el repositorio real.
	inherit *domain.SanctionCarryover

	mu      sync.Mutex
	calls   int
	created []domain.User
	// inheritedStatus es el user.status.changed que el servicio entregó en cada
	// Create, tal como lo recibe el repositorio.
	inheritedStatus []domain.OutboxEvent
	// grants es el grant de verificación que el servicio entregó en cada Create
	// (nil cuando el alta no lleva token).
	grants []*domain.GrantConsumption
}

func (m *repositoryMock) Create(_ context.Context, u *domain.User, inheritedStatus domain.OutboxEvent, grant *domain.GrantConsumption) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls++
	if m.err != nil {
		return m.err
	}
	if m.inherit != nil {
		u.InheritSanction(*m.inherit)
	}
	m.created = append(m.created, *u)
	m.inheritedStatus = append(m.inheritedStatus, inheritedStatus)
	m.grants = append(m.grants, grant)
	return nil
}

// ExistsByEmail no lo ejercita ningún test de signup: es parte de
// domain.UserRepository solo porque la verificación de email (US-13) lo
// necesita sobre el mismo repositorio.
func (m *repositoryMock) ExistsByEmail(context.Context, string) (bool, error) {
	panic("signup: ExistsByEmail no se usa en el alta")
}

// FindByID no lo ejercita ningún test de signup: es parte de
// domain.UserRepository solo porque la baja de cuenta (US-11) lo necesita sobre
// el mismo repositorio.
func (m *repositoryMock) FindByID(context.Context, uuid.UUID) (*domain.User, error) {
	panic("signup: FindByID no se usa en el alta")
}

// FindByDNIHashed no lo ejercita ningún test de signup: es parte de
// domain.UserRepository solo porque el login (US-02) lo necesita sobre el
// mismo repositorio. Un panic acá delata inmediatamente si algún cambio futuro
// hace que el alta empiece a depender de una búsqueda que hoy no le
// corresponde.
func (m *repositoryMock) FindByDNIHashed(context.Context, string) (*domain.User, error) {
	panic("signup: FindByDNIHashed no se usa en el alta")
}

func (m *repositoryMock) last() domain.User {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.created[len(m.created)-1]
}
