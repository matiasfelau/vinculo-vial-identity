package outbox_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/outbox"
)

// El user.status.changed del desbloqueo (US-17) sale por el mismo camino que el
// de la revisión: el worker lo publica con ACTIVE y MANUAL_UNBLOCK, y con el id de
// la fila como eventId. Alert levanta la restricción por el estado e ignora el
// motivo.
func TestProcessBatchPublicaElDesbloqueoManual(t *testing.T) {
	usuario := uuid.New()
	evt, err := domain.NewUserStatusChangedOutboxEvent(usuario, domain.AccountStatusActive, domain.UserStatusReasonManualUnblock)
	if err != nil {
		t.Fatalf("no se pudo armar el evento: %v", err)
	}
	evt.CreatedAt = time.Now().UTC()
	repo := &outboxRepoMock{pending: []domain.OutboxEvent{evt}}
	pub := &publisherMock{}
	w := outbox.NewWorker(repo, pub, 20, nil)

	sent, err := w.ProcessBatch(context.Background())
	if err != nil || sent != 1 {
		t.Fatalf("sent=%d err=%v, se esperaba 1 y nil", sent, err)
	}
	if len(pub.statusPublished) != 1 {
		t.Fatalf("publicados = %d, se esperaba 1", len(pub.statusPublished))
	}

	got := pub.statusPublished[0]
	if got.EventID != evt.ID || got.UserID != usuario {
		t.Errorf("evento publicado = %+v, se esperaba el evento %v del usuario %v", got, evt.ID, usuario)
	}
	if got.AccountStatus != domain.AccountStatusActive || got.Reason != domain.UserStatusReasonManualUnblock {
		t.Errorf("estado=%q motivo=%q, se esperaba ACTIVE y MANUAL_UNBLOCK", got.AccountStatus, got.Reason)
	}
}
