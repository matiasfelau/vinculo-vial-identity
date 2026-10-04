// Tests internos (package outbox): necesitan fijar el reloj del worker, que no
// es parte de su API.
package outbox

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// repoFalible deja elegir en caliente si FetchPending falla.
type repoFalible struct{ falla atomic.Bool }

func (r *repoFalible) FetchPending(context.Context, int) ([]domain.OutboxEvent, error) {
	if r.falla.Load() {
		return nil, errors.New("la base no responde")
	}
	return nil, nil
}
func (r *repoFalible) MarkSent(context.Context, uuid.UUID) error           { return nil }
func (r *repoFalible) MarkFailed(context.Context, uuid.UUID, string) error { return nil }

type publisherInerte struct{}

func (publisherInerte) PublishSessionsRevoked(context.Context, domain.SessionsRevoked) error {
	return nil
}

func esperarEstado(t *testing.T, w *Worker, estado string) {
	t.Helper()
	limite := time.Now().Add(2 * time.Second)
	for time.Now().Before(limite) {
		if got, _ := w.Status(); got == estado {
			return
		}
		time.Sleep(time.Millisecond)
	}
	got, _ := w.Status()
	t.Fatalf("estado = %q, se esperaba %q", got, estado)
}

func TestStatusAntesDeRunEsStopped(t *testing.T) {
	w := NewWorker(&repoFalible{}, publisherInerte{}, 20, nil)

	if estado, ok := w.Status(); estado != "stopped" || ok {
		t.Errorf("Status = (%q, %v), se esperaba (stopped, false)", estado, ok)
	}
}

func TestStatusEsUpMientrasCorreYStoppedAlCancelar(t *testing.T) {
	w := NewWorker(&repoFalible{}, publisherInerte{}, 20, nil)
	ctx, cancel := context.WithCancel(context.Background())
	hecho := make(chan struct{})
	go func() { w.Run(ctx, time.Millisecond); close(hecho) }()

	esperarEstado(t, w, "up")
	if _, ok := w.Status(); !ok {
		t.Error("up debe ser sano")
	}

	cancel()
	<-hecho
	if estado, ok := w.Status(); estado != "stopped" || ok {
		t.Errorf("tras cancelar: Status = (%q, %v), se esperaba (stopped, false)", estado, ok)
	}
}

// Si el worker no puede leer el outbox (la base falla), nada se drena: down.
// Cuando la base vuelve, el siguiente ciclo lo recupera solo.
func TestStatusEsDownSiNoPuedeLeerElOutboxYSeRecupera(t *testing.T) {
	repo := &repoFalible{}
	repo.falla.Store(true)
	w := NewWorker(repo, publisherInerte{}, 20, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx, time.Millisecond)

	esperarEstado(t, w, "down")
	if _, ok := w.Status(); ok {
		t.Error("down no debe ser sano")
	}

	repo.falla.Store(false)
	esperarEstado(t, w, "up")
}

// Un worker que sigue "corriendo" pero ya no inicia ciclos está colgado. El
// plazo es max(5 × intervalo, 1 minuto): un ciclo con el broker caído puede
// durar decenas de segundos legítimamente.
func TestStatusDetectaUnLoopColgado(t *testing.T) {
	inicio := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

	casos := map[string]struct {
		intervalo time.Duration
		pasado    time.Duration
		estado    string
	}{
		"dentro del piso de 1 minuto": {2 * time.Second, 59 * time.Second, "up"},
		"pasado el piso de 1 minuto":  {2 * time.Second, 61 * time.Second, "stalled"},
		"5x intervalo largo, dentro":  {30 * time.Second, 149 * time.Second, "up"},
		"5x intervalo largo, pasado":  {30 * time.Second, 151 * time.Second, "stalled"},
	}

	for nombre, tc := range casos {
		t.Run(nombre, func(t *testing.T) {
			w := NewWorker(&repoFalible{}, publisherInerte{}, 20, nil)
			w.running = true
			w.interval = tc.intervalo
			w.startedAt = inicio
			w.now = func() time.Time { return inicio.Add(tc.pasado) }

			estado, ok := w.Status()
			if estado != tc.estado || ok != (tc.estado == "up") {
				t.Errorf("Status = (%q, %v), se esperaba (%s, %v)", estado, ok, tc.estado, tc.estado == "up")
			}
		})
	}
}

// El plazo se mide desde el inicio del último ciclo, no desde el arranque: un
// worker que lleva horas sano no queda "stalled" por su antigüedad.
func TestStatusMideDesdeElUltimoCicloNoDesdeElArranque(t *testing.T) {
	inicio := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	w := NewWorker(&repoFalible{}, publisherInerte{}, 20, nil)
	w.running = true
	w.interval = 2 * time.Second
	w.startedAt = inicio
	w.lastCycleStart = inicio.Add(3 * time.Hour)
	w.now = func() time.Time { return inicio.Add(3*time.Hour + 10*time.Second) }

	if estado, ok := w.Status(); estado != "up" || !ok {
		t.Errorf("Status = (%q, %v), se esperaba (up, true)", estado, ok)
	}
}

// Que el broker esté caído no degrada al worker: un publish fallido deja el
// evento pendiente y el worker sigue sano reintentando. Esa dependencia la
// informa el chequeo del broker.
func TestStatusNoSeDegradaPorFallosDePublish(t *testing.T) {
	w := NewWorker(&repoConEvento{}, publisherQueFalla{}, 20, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx, time.Millisecond)

	time.Sleep(30 * time.Millisecond) // varios ciclos con publish fallido
	if estado, ok := w.Status(); estado != "up" || !ok {
		t.Errorf("Status = (%q, %v), se esperaba (up, true) con el broker caído", estado, ok)
	}
}

type repoConEvento struct{ repoFalible }

func (r *repoConEvento) FetchPending(context.Context, int) ([]domain.OutboxEvent, error) {
	return []domain.OutboxEvent{{
		ID:      uuid.New(),
		Type:    eventTypeSessionsRevoked,
		Payload: []byte(`{"user_id":"` + uuid.NewString() + `","reason":"REUSE_DETECTED"}`),
	}}, nil
}

type publisherQueFalla struct{}

func (publisherQueFalla) PublishSessionsRevoked(context.Context, domain.SessionsRevoked) error {
	return errors.New("el broker no responde")
}

// publisherConKeeper cuenta cuántas veces el worker le pidió mantener viva la
// conexión.
type publisherConKeeper struct {
	publisherInerte
	llamadas atomic.Int32
	err      error
}

func (p *publisherConKeeper) EnsureConnected(context.Context) error {
	p.llamadas.Add(1)
	return p.err
}

// Sin eventos pendientes el worker aprovecha el ciclo para restablecer la
// conexión: si no, tras una caída del broker /health/deps seguiría degradado
// hasta el próximo evento, aunque el broker ya estuviera sano.
func TestWorkerOciosoMantieneVivaLaConexionDelBroker(t *testing.T) {
	pub := &publisherConKeeper{}
	w := NewWorker(&repoFalible{}, pub, 20, nil)

	if _, err := w.ProcessBatch(context.Background()); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if pub.llamadas.Load() != 1 {
		t.Errorf("EnsureConnected se llamó %d veces, se esperaba 1", pub.llamadas.Load())
	}
}

// Con eventos pendientes el camino de publicar ya reconecta por su cuenta.
func TestWorkerConEventosNoLlamaAEnsureConnected(t *testing.T) {
	pub := &publisherConKeeper{}
	w := NewWorker(&repoConEvento{}, pub, 20, nil)

	if _, err := w.ProcessBatch(context.Background()); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if pub.llamadas.Load() != 0 {
		t.Errorf("EnsureConnected se llamó %d veces con eventos pendientes, se esperaba 0", pub.llamadas.Load())
	}
}

// No poder reconectar no es un error del ciclo ni degrada al worker: lo
// informa el chequeo del broker.
func TestWorkerOciosoToleraQueNoPuedaReconectar(t *testing.T) {
	pub := &publisherConKeeper{err: errors.New("el broker sigue caído")}
	w := NewWorker(&repoFalible{}, pub, 20, nil)

	if _, err := w.ProcessBatch(context.Background()); err != nil {
		t.Errorf("el ciclo no debe fallar por no poder reconectar: %v", err)
	}
}
