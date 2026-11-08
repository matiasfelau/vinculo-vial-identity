package signin_test

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// Dobles escritos a mano, igual que en internal/service/signup: son pocas
// interfaces de uno o dos métodos y así el comportamiento de cada caso queda a
// la vista en el propio test.

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

// DecryptCombined no lo ejercita ningún test de signin: es parte de
// domain.HPKEDecryptor solo porque /internal/verify-ownership (US-04) lo
// necesita sobre el mismo descifrador.
func (m *decryptorMock) DecryptCombined([]byte) ([]byte, error) {
	panic("signin: DecryptCombined no se usa en el login")
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

// hasherMock modela Argon2id de forma determinística: Hash produce
// "$argon2id$"+contraseña y Verify compara contra eso. verifyCalls guarda cada
// invocación de Verify —contraseña y hash contra el que se comparó— para poder
// afirmar sobre la defensa de timing sin que el resultado de la comparación
// importe.
type hasherMock struct {
	hashErr   error
	verifyErr error

	mu          sync.Mutex
	hashCalls   int
	verifyCalls []verifyCall
}

type verifyCall struct {
	password    string
	encodedHash string
}

func (m *hasherMock) Hash(pwd []byte) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.hashCalls++
	if m.hashErr != nil {
		return "", m.hashErr
	}
	return "$argon2id$" + string(pwd), nil
}

func (m *hasherMock) Verify(pwd []byte, encodedHash string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.verifyCalls = append(m.verifyCalls, verifyCall{password: string(pwd), encodedHash: encodedHash})
	if m.verifyErr != nil {
		return false, m.verifyErr
	}
	return "$argon2id$"+string(pwd) == encodedHash, nil
}

func (m *hasherMock) verifyCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.verifyCalls)
}

func (m *hasherMock) lastVerify() verifyCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.verifyCalls[len(m.verifyCalls)-1]
}

// usersMock implementa domain.UserRepository, pero signin solo llama a
// FindByDNIHashed: Create está para satisfacer la interfaz y no debería
// invocarse nunca desde este caso de uso.
type usersMock struct {
	user *domain.User
	err  error

	mu           sync.Mutex
	calls        int
	dniHasheados []string
}

func (m *usersMock) Create(context.Context, *domain.User, domain.OutboxEvent) error {
	panic("signin: Create no se usa en el login")
}

func (m *usersMock) FindByID(context.Context, uuid.UUID) (*domain.User, error) {
	panic("signin: FindByID no se usa en el login")
}

func (m *usersMock) FindByDNIHashed(_ context.Context, dniHashed string) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls++
	m.dniHasheados = append(m.dniHasheados, dniHashed)
	if m.err != nil {
		return nil, m.err
	}
	return m.user, nil
}

// FindByOwnerAndDNIHash no lo ejercita ningún test de signin: es parte de
// domain.UserRepository solo porque /internal/verify-ownership (US-04) lo
// necesita sobre el mismo repositorio.
func (m *usersMock) FindByOwnerAndDNIHash(context.Context, uuid.UUID, string) (*domain.User, error) {
	panic("signin: FindByOwnerAndDNIHash no se usa en el login")
}

type sessionsMock struct {
	err error

	mu      sync.Mutex
	calls   int
	created []domain.Session
}

func (m *sessionsMock) Create(_ context.Context, s *domain.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls++
	if m.err != nil {
		return m.err
	}
	m.created = append(m.created, *s)
	return nil
}

func (m *sessionsMock) FindByHash(context.Context, string) (*domain.Session, error) {
	panic("signin: FindByHash no se usa en el login")
}

func (m *sessionsMock) RevokeByID(context.Context, uuid.UUID) error {
	panic("signin: RevokeByID no se usa en el login")
}

func (m *sessionsMock) RevokeByHash(context.Context, string) error {
	panic("signin: RevokeByHash no se usa en el login")
}

func (m *sessionsMock) RevokeAllByUserID(context.Context, uuid.UUID, *domain.OutboxEvent) error {
	panic("signin: RevokeAllByUserID no se usa en el login")
}

func (m *sessionsMock) RotateSession(context.Context, uuid.UUID, *domain.Session) error {
	panic("signin: RotateSession no se usa en el login")
}

func (m *sessionsMock) last() domain.Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.created[len(m.created)-1]
}

type tokensMock struct {
	accessToken string
	accessErr   error

	refreshToken     string
	refreshHash      string
	refreshExpiresAt time.Time
	refreshErr       error

	mu           sync.Mutex
	accessCalls  int
	refreshCalls int
	accessUserID uuid.UUID
}

func (m *tokensMock) NewAccessToken(userID uuid.UUID) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.accessCalls++
	m.accessUserID = userID
	if m.accessErr != nil {
		return "", m.accessErr
	}
	return m.accessToken, nil
}

func (m *tokensMock) NewRefreshToken() (token, hash string, expiresAt time.Time, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.refreshCalls++
	if m.refreshErr != nil {
		return "", "", time.Time{}, m.refreshErr
	}
	return m.refreshToken, m.refreshHash, m.refreshExpiresAt, nil
}

func (m *tokensMock) Hash(string) string {
	panic("signin: Hash no se usa en el login")
}
