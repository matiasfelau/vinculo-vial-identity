package session_test

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// Dobles escritos a mano, igual que en internal/service/signin: son pocas
// interfaces de uno o dos métodos y así el comportamiento de cada caso queda a
// la vista en el propio test.

// sessionsMock implementa domain.SessionRepository. RefreshService llama a
// FindByHash siempre, a RotateSession en la vía feliz y a RevokeAllByUserID
// solo ante reúso (Defensa Activa); LogoutService llama a RevokeByHash.
// Create y RevokeByID están para satisfacer la interfaz y no deberían
// invocarse desde ninguno de los dos casos de uso de este paquete.
type sessionsMock struct {
	found   *domain.Session
	findErr error

	rotateErr error

	revokeAllErr error

	revokeByHashErr error

	mu               sync.Mutex
	findCalls        int
	findHashes       []string
	rotateCalls      int
	rotatedOld       uuid.UUID
	rotatedNew       domain.Session
	revokeAllCalls   int
	revokedUserID    uuid.UUID
	revokeHashCalls  int
	revokedHashes    []string
}

func (m *sessionsMock) Create(context.Context, *domain.Session) error {
	panic("session: Create no se usa en el refresh")
}

func (m *sessionsMock) FindByHash(_ context.Context, hash string) (*domain.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.findCalls++
	m.findHashes = append(m.findHashes, hash)
	if m.findErr != nil {
		return nil, m.findErr
	}
	return m.found, nil
}

func (m *sessionsMock) RevokeByID(context.Context, uuid.UUID) error {
	panic("session: RevokeByID no se usa en este paquete")
}

func (m *sessionsMock) RevokeByHash(_ context.Context, hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.revokeHashCalls++
	m.revokedHashes = append(m.revokedHashes, hash)
	if m.revokeByHashErr != nil {
		return m.revokeByHashErr
	}
	return nil
}

func (m *sessionsMock) RevokeAllByUserID(_ context.Context, userID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.revokeAllCalls++
	m.revokedUserID = userID
	if m.revokeAllErr != nil {
		return m.revokeAllErr
	}
	return nil
}

func (m *sessionsMock) RotateSession(_ context.Context, oldSessionID uuid.UUID, newSession *domain.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.rotateCalls++
	m.rotatedOld = oldSessionID
	m.rotatedNew = *newSession
	if m.rotateErr != nil {
		return m.rotateErr
	}
	return nil
}

func (m *sessionsMock) rotateCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rotateCalls
}

func (m *sessionsMock) revokeAllCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.revokeAllCalls
}

func (m *sessionsMock) revokeHashCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.revokeHashCalls
}

// tokensMock implementa domain.TokenGenerator. hash simula el SHA-256 real de
// forma determinística ("hash-de:"+token) para poder afirmar qué hash llegó
// a FindByHash sin depender de crypto/sha256 en el test.
type tokensMock struct {
	accessToken string
	accessErr   error

	refreshToken     string
	refreshHash      string
	refreshExpiresAt time.Time
	refreshErr       error

	mu           sync.Mutex
	accessCalls  int
	accessUserID uuid.UUID
	refreshCalls int
}

func (m *tokensMock) Hash(token string) string {
	return "hash-de:" + token
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
