package signup_test

import (
	"context"
	"sync"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// Dobles escritos a mano en lugar de generados: son seis interfaces de uno o dos
// métodos y así el comportamiento de cada caso queda a la vista en el propio test.

type decryptorMock struct {
	plaintext []byte
	err       error

	calls      int
	cryptogram []byte
}

func (m *decryptorMock) Decrypt(cryptogram []byte) ([]byte, error) {
	m.calls++
	m.cryptogram = cryptogram
	if m.err != nil {
		return nil, m.err
	}
	// Copia: el servicio limpia el buffer devuelto, y sin copiar se corrompería
	// el dato del propio doble entre llamadas.
	out := make([]byte, len(m.plaintext))
	copy(out, m.plaintext)
	return out, nil
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

type repositoryMock struct {
	err error

	mu      sync.Mutex
	calls   int
	created []domain.User
}

func (m *repositoryMock) Create(_ context.Context, u *domain.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls++
	if m.err != nil {
		return m.err
	}
	m.created = append(m.created, *u)
	return nil
}

func (m *repositoryMock) last() domain.User {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.created[len(m.created)-1]
}

type publisherMock struct {
	err error

	mu        sync.Mutex
	calls     int
	published []domain.UserRegistered
}

func (m *publisherMock) PublishUserRegistered(_ context.Context, evt domain.UserRegistered) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls++
	if m.err != nil {
		return m.err
	}
	m.published = append(m.published, evt)
	return nil
}
