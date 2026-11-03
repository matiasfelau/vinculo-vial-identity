package ownership_test

import (
	"context"
	"sync"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// Dobles escritos a mano, igual que en internal/service/signin: son pocas
// interfaces de uno o dos métodos y así el comportamiento de cada caso queda a
// la vista en el propio test.

// decryptorMock implementa domain.HPKEDecryptor. VerifyOwnership solo llama a
// DecryptCombined: Decrypt está para satisfacer la interfaz y no debería
// invocarse desde este caso de uso.
type decryptorMock struct {
	plaintext []byte
	err       error

	calls      int
	cryptogram []byte
	// returned guarda la referencia exacta al buffer que DecryptCombined
	// entregó la última vez (no una copia): permite que el test confirme que
	// el servicio lo dejó en ceros (Zero-Retention) después de usarlo.
	returned []byte
}

func (m *decryptorMock) Decrypt(ephemeralPublicKey, ciphertext []byte) ([]byte, error) {
	panic("ownership: Decrypt no se usa en verify-ownership")
}

func (m *decryptorMock) DecryptCombined(cryptogram []byte) ([]byte, error) {
	m.calls++
	m.cryptogram = cryptogram
	if m.err != nil {
		return nil, m.err
	}
	// Copia: el servicio limpia el buffer devuelto, y sin copiar se
	// corrompería el dato del propio doble entre llamadas.
	out := make([]byte, len(m.plaintext))
	copy(out, m.plaintext)
	m.returned = out
	return out, nil
}

// indexerMock implementa domain.BlindIndexer. Por defecto, Index simula el
// HMAC-SHA256 real de forma determinística ("blind-index-de:"+valor) para
// poder afirmar qué DNI normalizado llegó a Index. El campo index permite
// fijar un valor opaco cuando un test necesita que el default no delate el
// DNI como substring.
type indexerMock struct {
	index string

	calls  int
	values []string
	// received guarda la referencia exacta al slice que recibió la última
	// llamada a Index (no una copia): permite que el test confirme que el
	// servicio lo dejó en ceros después de calcular el Blind Index.
	received []byte
}

func (m *indexerMock) Index(value []byte) string {
	m.calls++
	m.values = append(m.values, string(value))
	m.received = value
	if m.index != "" {
		return m.index
	}
	return "blind-index-de:" + string(value)
}

// usersMock implementa domain.UserRepository. VerifyOwnership solo llama a
// FindByOwnerAndDNIHash: Create y FindByDNIHashed están para satisfacer la
// interfaz y no deberían invocarse desde este caso de uso.
type usersMock struct {
	user *domain.User
	err  error

	mu        sync.Mutex
	calls     int
	ownerIDs  []uuid.UUID
	dniHashes []string
}

func (m *usersMock) Create(context.Context, *domain.User, domain.OutboxEvent) error {
	panic("ownership: Create no se usa en verify-ownership")
}

func (m *usersMock) FindByID(context.Context, uuid.UUID) (*domain.User, error) {
	panic("ownership: FindByID no se usa en verify-ownership")
}

func (m *usersMock) FindByDNIHashed(context.Context, string) (*domain.User, error) {
	panic("ownership: FindByDNIHashed no se usa en verify-ownership")
}

func (m *usersMock) FindByOwnerAndDNIHash(_ context.Context, ownerID uuid.UUID, dniHashed string) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls++
	m.ownerIDs = append(m.ownerIDs, ownerID)
	m.dniHashes = append(m.dniHashes, dniHashed)
	if m.err != nil {
		return nil, m.err
	}
	return m.user, nil
}
