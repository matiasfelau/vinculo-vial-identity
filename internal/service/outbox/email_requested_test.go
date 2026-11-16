package outbox_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/outbox"
)

func unEmail(t *testing.T) (domain.OutboxEvent, uuid.UUID, time.Time) {
	t.Helper()

	actor := uuid.New()
	expira := time.Date(2026, 11, 2, 15, 14, 5, 0, time.UTC)
	evt, err := domain.NewEmailRequestedOutboxEvent(domain.EmailRequest{
		Template: domain.EmailTemplatePasswordReset, To: "vecino@example.com", Code: "042917",
		ExpiresAt: &expira, Actor: &actor,
	}, time.Now())
	if err != nil {
		t.Fatalf("no se pudo armar el evento: %v", err)
	}
	return evt, actor, expira
}

// El worker publica email.requested con el ID de la fila del outbox como eventId
// y todos los campos intactos.
func TestProcessBatchPublicaEmailRequested(t *testing.T) {
	evt, actor, expira := unEmail(t)
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
	if len(pub.published) != 0 || len(pub.statusPublished) != 0 || len(pub.deletedPublished) != 0 {
		t.Error("solo debería publicar email.requested")
	}
	if len(pub.emailPublished) != 1 {
		t.Fatalf("publicados = %d, se esperaba 1", len(pub.emailPublished))
	}

	got := pub.emailPublished[0]
	if got.EventID != evt.ID {
		t.Errorf("EventID = %v, se esperaba el de la fila %v", got.EventID, evt.ID)
	}
	if got.Template != domain.EmailTemplatePasswordReset || got.To != "vecino@example.com" || got.Code != "042917" {
		t.Errorf("evento = %+v", got)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(expira) {
		t.Errorf("expires_at = %v, se esperaba %v", got.ExpiresAt, expira)
	}
	if got.Actor == nil || *got.Actor != actor {
		t.Errorf("actor = %v, se esperaba %v", got.Actor, actor)
	}
}

// Si la publicación falla, el evento queda pendiente y el motivo guardado en
// last_error no incluye el destinatario ni el código.
func TestProcessBatchConFalloDeEmailRequestedNoGuardaDatosPersonales(t *testing.T) {
	evt, _, _ := unEmail(t)
	repo := &outboxRepoMock{pending: []domain.OutboxEvent{evt}}
	pub := &publisherMock{err: errors.New("el broker no responde")}
	w := outbox.NewWorker(repo, pub, 20, nil)

	sent, err := w.ProcessBatch(context.Background())
	if err != nil || sent != 0 {
		t.Fatalf("sent=%d err=%v, se esperaba 0 y nil", sent, err)
	}
	if len(repo.sentIDs) != 0 {
		t.Error("el evento se marcó como enviado pese al fallo")
	}
	if len(repo.failedIDs) != 1 || repo.failedIDs[0] != evt.ID {
		t.Fatalf("failedIDs = %v, se esperaba [%v]", repo.failedIDs, evt.ID)
	}
	for _, secreto := range []string{"vecino@example.com", "042917"} {
		if strings.Contains(repo.failedErrs[0], secreto) {
			t.Errorf("last_error contiene %q: %s", secreto, repo.failedErrs[0])
		}
	}
}

// Un payload ilegible queda pendiente con el motivo, sin filtrar su contenido.
func TestProcessBatchConEmailRequestedIlegibleQuedaPendienteSinFiltrarElPayload(t *testing.T) {
	evt := domain.OutboxEvent{
		ID: uuid.New(), Type: domain.EventTypeEmailRequested,
		Payload: json.RawMessage(`{"to":"secreto@example.com","code":"123456"`),
	}
	repo := &outboxRepoMock{pending: []domain.OutboxEvent{evt}}
	pub := &publisherMock{}
	w := outbox.NewWorker(repo, pub, 20, nil)

	if sent, _ := w.ProcessBatch(context.Background()); sent != 0 {
		t.Fatalf("sent = %d, se esperaba 0", sent)
	}
	if len(pub.emailPublished) != 0 {
		t.Error("se publicó un evento ilegible")
	}
	if len(repo.failedErrs) != 1 {
		t.Fatalf("failedErrs = %v", repo.failedErrs)
	}
	for _, secreto := range []string{"secreto@example.com", "123456"} {
		if strings.Contains(repo.failedErrs[0], secreto) {
			t.Errorf("last_error contiene %q: %s", secreto, repo.failedErrs[0])
		}
	}
}
