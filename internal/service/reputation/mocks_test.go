package reputation_test

import (
	"context"
	"sync"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// repoMock implementa domain.ReputationRepository. Simula la deduplicación
// del repositorio real: un mismo (EventID, Consumer) vuelve como duplicado.
type repoMock struct {
	mu sync.Mutex

	err      error
	notFound bool

	vistos    map[[2]string]bool
	llamadas  int
	eventos   []domain.ProcessedEvent
	usuarios  []uuid.UUID
	penalties []int
}

func (m *repoMock) ApplyRejection(_ context.Context, event domain.ProcessedEvent, userID uuid.UUID, penalty int) (domain.RejectionResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.llamadas++
	if m.err != nil {
		return 0, m.err
	}

	if m.vistos == nil {
		m.vistos = map[[2]string]bool{}
	}
	clave := [2]string{event.EventID.String(), event.Consumer}
	if m.vistos[clave] {
		return domain.RejectionDuplicate, nil
	}
	m.vistos[clave] = true

	m.eventos = append(m.eventos, event)
	m.usuarios = append(m.usuarios, userID)
	m.penalties = append(m.penalties, penalty)

	if m.notFound {
		return domain.RejectionUserNotFound, nil
	}
	return domain.RejectionApplied, nil
}
