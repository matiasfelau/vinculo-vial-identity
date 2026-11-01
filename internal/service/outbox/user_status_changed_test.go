package outbox_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/outbox"
)

func unCambioDeEstado(t *testing.T) (domain.OutboxEvent, uuid.UUID) {
	t.Helper()

	usuario := uuid.New()
	evt, err := domain.NewOutboxEvent(domain.EventTypeUserStatusChanged, map[string]string{
		"user_id":        usuario.String(),
		"account_status": "UNDER_REVIEW",
		"reason":         "REPORTS_THRESHOLD",
	})
	if err != nil {
		t.Fatalf("no se pudo armar el evento: %v", err)
	}
	evt.CreatedAt = time.Now().UTC()
	return evt, usuario
}

// El worker publica user.status.changed con el ID de la fila del outbox como
// eventId, para que un reintento no se cuente dos veces.
func TestProcessBatchPublicaUserStatusChanged(t *testing.T) {
	evt, usuario := unCambioDeEstado(t)
	repo := &outboxRepoMock{pending: []domain.OutboxEvent{evt}}
	pub := &publisherMock{}
	w := outbox.NewWorker(repo, pub, 20, nil)

	sent, err := w.ProcessBatch(context.Background())
	if err != nil || sent != 1 {
		t.Fatalf("sent=%d err=%v, se esperaba 1 y nil", sent, err)
	}
	if len(repo.sentIDs) != 1 || repo.sentIDs[0] != evt.ID {
		t.Errorf("sentIDs = %v, se esperaba [%v]", repo.sentIDs, evt.ID)
	}
	if len(pub.published) != 0 {
		t.Errorf("no debería publicar user.sessions.revoked")
	}
	if len(pub.statusPublished) != 1 {
		t.Fatalf("publicados = %d, se esperaba 1", len(pub.statusPublished))
	}

	got := pub.statusPublished[0]
	if got.EventID != evt.ID || got.UserID != usuario {
		t.Errorf("evento publicado = %+v, se esperaba el evento %v del usuario %v", got, evt.ID, usuario)
	}
	if got.AccountStatus != domain.AccountStatusUnderReview || got.Reason != domain.UserStatusReasonReportsThreshold {
		t.Errorf("estado=%q motivo=%q", got.AccountStatus, got.Reason)
	}
}

func TestProcessBatchSiFallaElPublishDeUserStatusChangedQuedaPendiente(t *testing.T) {
	evt, _ := unCambioDeEstado(t)
	repo := &outboxRepoMock{pending: []domain.OutboxEvent{evt}}
	pub := &publisherMock{err: context.DeadlineExceeded}
	w := outbox.NewWorker(repo, pub, 20, nil)

	sent, err := w.ProcessBatch(context.Background())
	if err != nil || sent != 0 {
		t.Fatalf("sent=%d err=%v, se esperaba 0 y nil", sent, err)
	}
	if len(repo.sentIDs) != 0 || len(repo.failedIDs) != 1 {
		t.Errorf("sent=%v failed=%v: debe quedar pendiente con el intento registrado", repo.sentIDs, repo.failedIDs)
	}
}

func TestProcessBatchNoPublicaUserStatusChangedQueNoPuedeInterpretar(t *testing.T) {
	casos := map[string]string{
		"payload ilegible":   `{no es json`,
		"user_id inválido":   `{"user_id":"x","account_status":"UNDER_REVIEW","reason":"REPORTS_THRESHOLD"}`,
		"sin user_id":        `{"account_status":"UNDER_REVIEW","reason":"REPORTS_THRESHOLD"}`,
		"sin account_status": `{"user_id":"` + uuid.NewString() + `","reason":"REPORTS_THRESHOLD"}`,
		"sin reason":         `{"user_id":"` + uuid.NewString() + `","account_status":"UNDER_REVIEW"}`,
	}
	for nombre, payload := range casos {
		t.Run(nombre, func(t *testing.T) {
			evt, _ := unCambioDeEstado(t)
			evt.Payload = []byte(payload)
			repo := &outboxRepoMock{pending: []domain.OutboxEvent{evt}}
			pub := &publisherMock{}
			w := outbox.NewWorker(repo, pub, 20, nil)

			sent, err := w.ProcessBatch(context.Background())
			if err != nil || sent != 0 {
				t.Fatalf("sent=%d err=%v", sent, err)
			}
			if len(pub.statusPublished) != 0 || len(repo.sentIDs) != 0 {
				t.Errorf("no debería publicarse ni marcarse enviado")
			}
			if len(repo.failedIDs) != 1 {
				t.Errorf("failedIDs = %v, se esperaba el evento marcado como fallido", repo.failedIDs)
			}
		})
	}
}
