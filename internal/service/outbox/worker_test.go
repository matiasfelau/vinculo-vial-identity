package outbox_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/outbox"
)

// Dobles escritos a mano, igual que en el resto de internal/service: pocos
// métodos, comportamiento a la vista en el propio test.

type outboxRepoMock struct {
	pending       []domain.OutboxEvent
	fetchErr      error
	markSentErr   error
	markFailedErr error

	mu         sync.Mutex
	fetchCalls int
	fetchLimit int
	sentIDs    []uuid.UUID
	failedIDs  []uuid.UUID
	failedErrs []string
}

func (m *outboxRepoMock) FetchPending(_ context.Context, limit int) ([]domain.OutboxEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.fetchCalls++
	m.fetchLimit = limit
	if m.fetchErr != nil {
		return nil, m.fetchErr
	}
	return m.pending, nil
}

func (m *outboxRepoMock) MarkSent(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.markSentErr != nil {
		return m.markSentErr
	}
	m.sentIDs = append(m.sentIDs, id)
	return nil
}

func (m *outboxRepoMock) MarkFailed(_ context.Context, id uuid.UUID, lastErr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.markFailedErr != nil {
		return m.markFailedErr
	}
	m.failedIDs = append(m.failedIDs, id)
	m.failedErrs = append(m.failedErrs, lastErr)
	return nil
}

// publisherMock implementa domain.EventPublisher. Solo el worker la usa,
// exclusivamente vía PublishSessionsRevoked.
type publisherMock struct {
	err error

	mu        sync.Mutex
	published []domain.SessionsRevoked
}

func (m *publisherMock) PublishSessionsRevoked(_ context.Context, evt domain.SessionsRevoked) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.err != nil {
		return m.err
	}
	m.published = append(m.published, evt)
	return nil
}

func unEvento() domain.OutboxEvent {
	evt, _ := domain.NewOutboxEvent("user.sessions.revoked", domain.NewSessionsRevoked(uuid.New(), uuid.New(), domain.SessionsRevokedReasonReuseDetected))
	evt.ID = uuid.MustParse("a1b2c3d4-e5f6-4789-9abc-def012345678")
	evt.CreatedAt = time.Now().UTC()
	return evt
}

func TestProcessBatchPublicaYMarcaEnviado(t *testing.T) {
	evt := unEvento()
	repo := &outboxRepoMock{pending: []domain.OutboxEvent{evt}}
	pub := &publisherMock{}
	w := outbox.NewWorker(repo, pub, 20, nil)

	sent, err := w.ProcessBatch(context.Background())
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if sent != 1 {
		t.Errorf("sent = %d, se esperaba 1", sent)
	}
	if len(repo.sentIDs) != 1 || repo.sentIDs[0] != evt.ID {
		t.Errorf("sentIDs = %v, se esperaba [%v]", repo.sentIDs, evt.ID)
	}

	// El EventID publicado tiene que ser el mismo que el de la fila de
	// outbox, no uno generado de nuevo: es lo que permite deduplicar un
	// reintento.
	if len(pub.published) != 1 {
		t.Fatalf("published = %d, se esperaba 1", len(pub.published))
	}
	publicado := pub.published[0]
	if publicado.EventID != evt.ID {
		t.Errorf("EventID publicado = %v, se esperaba %v (reutilizado del outbox)", publicado.EventID, evt.ID)
	}
	var payload struct {
		UserID string `json:"user_id"`
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(evt.Payload, &payload)

	if publicado.UserID.String() != payload.UserID {
		t.Errorf("UserID publicado = %v, se esperaba %v", publicado.UserID, payload.UserID)
	}
	if string(publicado.Reason) != payload.Reason {
		t.Errorf("Reason publicado = %q, se esperaba %q", publicado.Reason, payload.Reason)
	}
}

func TestProcessBatchSiFallaElPublishMarcaFallidoYNoEnviado(t *testing.T) {
	evt := unEvento()
	repo := &outboxRepoMock{pending: []domain.OutboxEvent{evt}}
	pub := &publisherMock{err: errors.New("el broker no respondió")}
	w := outbox.NewWorker(repo, pub, 20, nil)

	sent, err := w.ProcessBatch(context.Background())
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if sent != 0 {
		t.Errorf("sent = %d, se esperaba 0", sent)
	}
	if len(repo.failedIDs) != 1 || repo.failedIDs[0] != evt.ID {
		t.Errorf("failedIDs = %v, se esperaba [%v]", repo.failedIDs, evt.ID)
	}
	if len(repo.failedErrs) != 1 || repo.failedErrs[0] == "" {
		t.Errorf("failedErrs = %v, se esperaba el motivo del fallo", repo.failedErrs)
	}
	if len(repo.sentIDs) != 0 {
		t.Error("no debería haberse marcado como enviado")
	}
}

// Caso documentado en ProcessBatch: el publish se confirma pero MarkSent
// falla. El evento queda pendiente —no cuenta como enviado— para que el
// próximo ciclo lo reintente; la reutilización del EventID es lo que hace
// tolerable el reintento duplicado.
func TestProcessBatchSiFallaMarkSentTrasPublicarNoLoCuentaComoEnviado(t *testing.T) {
	evt := unEvento()
	repo := &outboxRepoMock{pending: []domain.OutboxEvent{evt}, markSentErr: errors.New("la base no responde")}
	pub := &publisherMock{}
	w := outbox.NewWorker(repo, pub, 20, nil)

	sent, err := w.ProcessBatch(context.Background())
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if sent != 0 {
		t.Errorf("sent = %d, se esperaba 0: el publish se confirmó pero no se pudo marcar", sent)
	}
	if len(pub.published) != 1 {
		t.Error("se esperaba que el publish sí se hubiera intentado una vez")
	}
}

// Un tipo desconocido o un payload que no se puede interpretar no se publican
// con datos inventados: el evento queda pendiente con el motivo en last_error,
// para que alguien lo vea, en vez de salir al bus con un user_id vacío.
func TestProcessBatchNoPublicaEventosQueNoPuedeInterpretar(t *testing.T) {
	casos := map[string]func(*domain.OutboxEvent){
		"tipo desconocido":    func(e *domain.OutboxEvent) { e.Type = "user.created" },
		"payload ilegible":    func(e *domain.OutboxEvent) { e.Payload = []byte("{no es json") },
		"user_id inválido":    func(e *domain.OutboxEvent) { e.Payload = []byte(`{"user_id":"no-es-uuid","reason":"REUSE_DETECTED"}`) },
		"payload sin user_id": func(e *domain.OutboxEvent) { e.Payload = []byte(`{"reason":"REUSE_DETECTED"}`) },
	}

	for nombre, degradar := range casos {
		t.Run(nombre, func(t *testing.T) {
			evt := unEvento()
			degradar(&evt)
			repo := &outboxRepoMock{pending: []domain.OutboxEvent{evt}}
			pub := &publisherMock{}
			w := outbox.NewWorker(repo, pub, 20, nil)

			sent, err := w.ProcessBatch(context.Background())
			if err != nil {
				t.Fatalf("error inesperado: %v", err)
			}
			if sent != 0 || len(pub.published) != 0 {
				t.Errorf("sent=%d published=%d, se esperaba que no se publicara nada", sent, len(pub.published))
			}
			if len(repo.failedIDs) != 1 || repo.failedIDs[0] != evt.ID {
				t.Errorf("failedIDs = %v, se esperaba [%v]", repo.failedIDs, evt.ID)
			}
			if len(repo.sentIDs) != 0 {
				t.Error("no debería haberse marcado como enviado")
			}
		})
	}
}

func TestProcessBatchRespetaElBatchSize(t *testing.T) {
	repo := &outboxRepoMock{}
	pub := &publisherMock{}
	w := outbox.NewWorker(repo, pub, 7, nil)

	if _, err := w.ProcessBatch(context.Background()); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if repo.fetchLimit != 7 {
		t.Errorf("limit pedido a FetchPending = %d, se esperaba 7", repo.fetchLimit)
	}
}

func TestProcessBatchSiFallaFetchPendingPropagaElError(t *testing.T) {
	repo := &outboxRepoMock{fetchErr: errors.New("la base no responde")}
	pub := &publisherMock{}
	w := outbox.NewWorker(repo, pub, 20, nil)

	if _, err := w.ProcessBatch(context.Background()); err == nil {
		t.Error("se esperaba un error")
	}
}

func TestProcessBatchSinEventosPendientesNoPublicaNada(t *testing.T) {
	repo := &outboxRepoMock{}
	pub := &publisherMock{}
	w := outbox.NewWorker(repo, pub, 20, nil)

	sent, err := w.ProcessBatch(context.Background())
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if sent != 0 {
		t.Errorf("sent = %d, se esperaba 0", sent)
	}
	if len(pub.published) != 0 {
		t.Error("no debería haberse publicado nada")
	}
}

// Run tiene que dejar de programar nuevos ciclos en cuanto el contexto se
// cancela (apagado del servicio), sin bloquear indefinidamente.
func TestRunRespetaLaCancelacionDelContexto(t *testing.T) {
	repo := &outboxRepoMock{}
	pub := &publisherMock{}
	w := outbox.NewWorker(repo, pub, 20, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Run(ctx, time.Millisecond)
		close(done)
	}()

	time.Sleep(20 * time.Millisecond) // deja correr unos ciclos de verdad
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run no volvió tras cancelar el contexto")
	}
}
