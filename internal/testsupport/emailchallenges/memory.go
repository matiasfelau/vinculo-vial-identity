// Package emailchallenges es un doble en memoria de domain.EmailChallengeRepository
// para los tests de los casos de uso de US-13. Reproduce las garantías que los
// servicios esperan del repositorio real —mutación atómica sobre el desafío,
// eventos de outbox junto con el cambio, un grant de un solo uso— sin Postgres.
//
// Solo lo importan archivos _test: no forma parte del binario del servicio.
package emailchallenges

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

type key struct {
	purpose domain.EmailChallengePurpose
	subject string
}

// Memory implementa domain.EmailChallengeRepository en memoria.
type Memory struct {
	mu         sync.Mutex
	challenges map[key]*domain.EmailChallenge

	// Err, si no es nil, es el error que devuelven todas las operaciones, antes de
	// tocar nada: simula una base caída.
	Err error
	// GrantAttemptErr es el error que devuelve solo AddGrantAttempt.
	GrantAttemptErr error
	// CompleteErr es el error que devuelve solo CompletePasswordReset.
	CompleteErr error

	outbox      []domain.OutboxEvent
	completions []domain.PasswordResetCompletion
	mutations   int
}

var _ domain.EmailChallengeRepository = (*Memory)(nil)

// New construye un repositorio vacío.
func New() *Memory {
	return &Memory{challenges: make(map[key]*domain.EmailChallenge)}
}

// Mutate ejecuta fn sobre el desafío del subject. Si fn falla, el desafío no
// cambia ni se encolan eventos, como en la transacción real.
func (m *Memory) Mutate(_ context.Context, purpose domain.EmailChallengePurpose, subjectHMAC string, create bool, fn domain.EmailChallengeMutation) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.Err != nil {
		return m.Err
	}
	m.mutations++

	k := key{purpose, subjectHMAC}
	current, ok := m.challenges[k]
	if !ok {
		if !create {
			return domain.ErrChallengeNotFound
		}
		current = &domain.EmailChallenge{ID: uuid.New(), Purpose: purpose, SubjectHMAC: subjectHMAC, CreatedAt: time.Now().UTC()}
	}

	working := *current
	events, err := fn(&working)
	if err != nil {
		return err
	}
	m.challenges[k] = &working
	m.outbox = append(m.outbox, events...)
	return nil
}

// FindByGrantHash busca el desafío por el hash de su grant.
func (m *Memory) FindByGrantHash(_ context.Context, grantHash string) (*domain.EmailChallenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.Err != nil {
		return nil, m.Err
	}
	for _, c := range m.challenges {
		if c.GrantHash != "" && c.GrantHash == grantHash {
			copied := *c
			return &copied, nil
		}
	}
	return nil, domain.ErrChallengeNotFound
}

// AddGrantAttempt suma un rechazo de identidad al grant, si no se consumió.
func (m *Memory) AddGrantAttempt(_ context.Context, grantHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.Err != nil {
		return m.Err
	}
	if m.GrantAttemptErr != nil {
		return m.GrantAttemptErr
	}
	for _, c := range m.challenges {
		if c.GrantHash != "" && c.GrantHash == grantHash && c.ConsumedAt == nil {
			c.GrantAttempts++
		}
	}
	return nil
}

// CompletePasswordReset consume el grant si sigue siendo utilizable y registra la
// finalización, con sus dos eventos.
func (m *Memory) CompletePasswordReset(_ context.Context, c domain.PasswordResetCompletion) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.Err != nil {
		return m.Err
	}
	if m.CompleteErr != nil {
		return m.CompleteErr
	}
	for _, ch := range m.challenges {
		if ch.GrantHash == "" || ch.GrantHash != c.GrantHash {
			continue
		}
		if ch.ConsumedAt != nil || ch.GrantExpiresAt == nil || !c.Now.Before(*ch.GrantExpiresAt) ||
			ch.GrantAttempts >= c.MaxIdentityAttempts {
			return domain.ErrInvalidResetToken
		}
		consumed := c.Now
		ch.ConsumedAt = &consumed
		m.completions = append(m.completions, c)
		m.outbox = append(m.outbox, c.SessionsRevoked, c.PasswordChanged)
		return nil
	}
	return domain.ErrInvalidResetToken
}

// DeleteExpired borra hasta limit desafíos cuyos tres plazos ya pasaron, con el
// mismo criterio que la consulta real (que se prueba contra Postgres).
func (m *Memory) DeleteExpired(_ context.Context, now time.Time, limit int) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.Err != nil {
		return 0, m.Err
	}
	passed := func(t *time.Time, extra time.Duration) bool { return t == nil || !now.Before(t.Add(extra)) }

	var deleted int64
	for k, c := range m.challenges {
		if deleted >= int64(limit) {
			break
		}
		if passed(c.CodeExpiresAt, 0) && passed(c.GrantExpiresAt, 0) &&
			passed(c.SendsWindowStartedAt, domain.EmailChallengeSendWindow) {
			delete(m.challenges, k)
			deleted++
		}
	}
	return deleted, nil
}

// Get devuelve una copia del desafío del subject, o nil si no existe.
func (m *Memory) Get(purpose domain.EmailChallengePurpose, subjectHMAC string) *domain.EmailChallenge {
	m.mu.Lock()
	defer m.mu.Unlock()

	if c, ok := m.challenges[key{purpose, subjectHMAC}]; ok {
		copied := *c
		return &copied
	}
	return nil
}

// Put reemplaza el desafío del subject, para preparar un estado de partida.
func (m *Memory) Put(c domain.EmailChallenge) {
	m.mu.Lock()
	defer m.mu.Unlock()

	copied := c
	m.challenges[key{c.Purpose, c.SubjectHMAC}] = &copied
}

// Outbox devuelve los eventos encolados hasta ahora.
func (m *Memory) Outbox() []domain.OutboxEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]domain.OutboxEvent(nil), m.outbox...)
}

// Completions devuelve las recuperaciones completadas.
func (m *Memory) Completions() []domain.PasswordResetCompletion {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]domain.PasswordResetCompletion(nil), m.completions...)
}

// Mutations cuenta cuántas veces se ejecutó Mutate con éxito en la búsqueda del
// desafío (aunque la mutación no haya cambiado nada).
func (m *Memory) Mutations() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mutations
}
