package outbox_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/outbox"
)

func unaBaja(t *testing.T) (domain.OutboxEvent, uuid.UUID, time.Time) {
	t.Helper()

	usuario := uuid.New()
	bajaEn := time.Date(2026, 11, 2, 15, 4, 5, 123456789, time.UTC)
	evt, err := domain.NewOutboxEvent(domain.EventTypeUserDeleted, map[string]string{
		"user_id":    usuario.String(),
		"deleted_at": bajaEn.Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatalf("no se pudo armar el evento: %v", err)
	}
	evt.CreatedAt = bajaEn
	return evt, usuario, bajaEn
}

// El worker publica user.deleted con el ID de la fila del outbox como eventId
// y la fecha de la baja intacta, hasta los nanosegundos.
func TestProcessBatchPublicaUserDeleted(t *testing.T) {
	evt, usuario, bajaEn := unaBaja(t)
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
	if len(pub.published) != 0 || len(pub.statusPublished) != 0 {
		t.Errorf("solo debería publicar user.deleted")
	}
	if len(pub.deletedPublished) != 1 {
		t.Fatalf("publicados = %d, se esperaba 1", len(pub.deletedPublished))
	}

	got := pub.deletedPublished[0]
	if got.EventID != evt.ID || got.UserID != usuario {
		t.Errorf("evento publicado = %+v, se esperaba el evento %v del usuario %v", got, evt.ID, usuario)
	}
	if !got.DeletedAt.Equal(bajaEn) {
		t.Errorf("DeletedAt = %v, se esperaba %v", got.DeletedAt, bajaEn)
	}
}

func TestProcessBatchSiFallaElPublishDeUserDeletedQuedaPendiente(t *testing.T) {
	evt, _, _ := unaBaja(t)
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

func TestProcessBatchNoPublicaUserDeletedQueNoPuedeInterpretar(t *testing.T) {
	casos := map[string]string{
		"payload ilegible":  `{no es json`,
		"user_id inválido":  `{"user_id":"x","deleted_at":"2026-11-02T15:04:05Z"}`,
		"sin user_id":       `{"deleted_at":"2026-11-02T15:04:05Z"}`,
		"sin deleted_at":    `{"user_id":"` + uuid.NewString() + `"}`,
		"deleted_at basura": `{"user_id":"` + uuid.NewString() + `","deleted_at":"ayer"}`,
	}
	for nombre, payload := range casos {
		t.Run(nombre, func(t *testing.T) {
			evt, _, _ := unaBaja(t)
			evt.Payload = []byte(payload)
			repo := &outboxRepoMock{pending: []domain.OutboxEvent{evt}}
			pub := &publisherMock{}
			w := outbox.NewWorker(repo, pub, 20, nil)

			sent, err := w.ProcessBatch(context.Background())
			if err != nil || sent != 0 {
				t.Fatalf("sent=%d err=%v", sent, err)
			}
			if len(pub.deletedPublished) != 0 || len(repo.sentIDs) != 0 {
				t.Errorf("no debería publicarse ni marcarse enviado")
			}
			if len(repo.failedIDs) != 1 {
				t.Errorf("failedIDs = %v, se esperaba el evento marcado como fallido", repo.failedIDs)
			}
		})
	}
}

// El user.status.changed de la sanción heredada (US-11) pasa por el mismo camino
// que el de US-08 y conserva su motivo.
func TestProcessBatchPublicaUserStatusChangedHeredado(t *testing.T) {
	usuario := uuid.New()
	evt, err := domain.NewUserStatusChangedOutboxEvent(usuario, domain.AccountStatusUnderReview, domain.UserStatusReasonInheritedOnSignup)
	if err != nil {
		t.Fatalf("no se pudo armar el evento: %v", err)
	}
	evt.CreatedAt = time.Now().UTC()

	repo := &outboxRepoMock{pending: []domain.OutboxEvent{evt}}
	pub := &publisherMock{}
	w := outbox.NewWorker(repo, pub, 20, nil)

	if sent, err := w.ProcessBatch(context.Background()); err != nil || sent != 1 {
		t.Fatalf("sent=%d err=%v, se esperaba 1 y nil", sent, err)
	}
	if len(pub.statusPublished) != 1 {
		t.Fatalf("publicados = %d, se esperaba 1", len(pub.statusPublished))
	}
	got := pub.statusPublished[0]
	if got.UserID != usuario || got.AccountStatus != domain.AccountStatusUnderReview || got.Reason != domain.UserStatusReasonInheritedOnSignup {
		t.Errorf("evento publicado = %+v", got)
	}
}
