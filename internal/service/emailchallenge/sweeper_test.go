package emailchallenge_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/emailchallenge"
)

// repoDeBarrido es un doble que responde por lotes y registra las llamadas.
type repoDeBarrido struct {
	domain.EmailChallengeRepository

	mu         sync.Mutex
	respuestas []int64
	errAt      int // índice (1-based) de la llamada que falla; 0 = ninguna
	calls      int
	limits     []int
	called     chan struct{}
}

func (r *repoDeBarrido) DeleteExpired(_ context.Context, _ time.Time, limit int) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.calls++
	r.limits = append(r.limits, limit)
	if r.called != nil {
		select {
		case r.called <- struct{}{}:
		default:
		}
	}
	if r.errAt == r.calls {
		return 0, errors.New("la base no responde")
	}
	if len(r.respuestas) == 0 {
		return 0, nil
	}
	n := r.respuestas[0]
	r.respuestas = r.respuestas[1:]
	return n, nil
}

func nuevoSweeper(t *testing.T, repo domain.EmailChallengeRepository, batch int, logs *bytes.Buffer) *emailchallenge.Sweeper {
	t.Helper()
	s, err := emailchallenge.NewSweeper(repo, time.Hour, batch, slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	if err != nil {
		t.Fatalf("NewSweeper: %v", err)
	}
	return s
}

// Mientras un lote salga lleno, se sigue; el primero incompleto corta.
func TestSweepOnceBorraDeALotesHastaVaciar(t *testing.T) {
	repo := &repoDeBarrido{respuestas: []int64{3, 3, 1}}
	s := nuevoSweeper(t, repo, 3, &bytes.Buffer{})

	total, err := s.SweepOnce(t.Context())

	if err != nil || total != 7 {
		t.Fatalf("SweepOnce = (%d, %v), se esperaba (7, nil)", total, err)
	}
	if repo.calls != 3 {
		t.Errorf("llamadas = %d, se esperaban 3", repo.calls)
	}
	for _, l := range repo.limits {
		if l != 3 {
			t.Errorf("límite = %d, se esperaba el tamaño del lote (3)", l)
		}
	}
}

func TestSweepOnceSinNadaQueBorrarTerminaEnUnaLlamada(t *testing.T) {
	repo := &repoDeBarrido{}
	s := nuevoSweeper(t, repo, 5, &bytes.Buffer{})

	if total, err := s.SweepOnce(t.Context()); err != nil || total != 0 || repo.calls != 1 {
		t.Fatalf("SweepOnce = (%d, %v) con %d llamadas, se esperaba (0, nil) y 1", total, err, repo.calls)
	}
}

// Ante un error devuelve igual lo borrado hasta ese momento.
func TestSweepOnceDevuelveLoBorradoAnteUnError(t *testing.T) {
	repo := &repoDeBarrido{respuestas: []int64{2, 2}, errAt: 2}
	s := nuevoSweeper(t, repo, 2, &bytes.Buffer{})

	total, err := s.SweepOnce(t.Context())

	if err == nil {
		t.Fatal("se esperaba el error del segundo lote")
	}
	if total != 2 {
		t.Errorf("total = %d, se esperaba lo borrado antes del error (2)", total)
	}
}

func TestSweepOnceCortaConElContextoCancelado(t *testing.T) {
	repo := &repoDeBarrido{respuestas: []int64{5, 5, 5}}
	s := nuevoSweeper(t, repo, 5, &bytes.Buffer{})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := s.SweepOnce(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, se esperaba context.Canceled", err)
	}
	if repo.calls != 0 {
		t.Errorf("se borró con el contexto cancelado (%d llamadas)", repo.calls)
	}
}

func TestNewSweeperValidaLosParametros(t *testing.T) {
	repo := &repoDeBarrido{}
	if _, err := emailchallenge.NewSweeper(nil, time.Hour, 1, nil); err == nil {
		t.Error("repositorio nil aceptado")
	}
	if _, err := emailchallenge.NewSweeper(repo, 0, 1, nil); err == nil {
		t.Error("intervalo en cero aceptado")
	}
	if _, err := emailchallenge.NewSweeper(repo, time.Hour, 0, nil); err == nil {
		t.Error("lote en cero aceptado")
	}
	if _, err := emailchallenge.NewSweeper(repo, time.Hour, 1, nil); err != nil {
		t.Errorf("configuración válida rechazada: %v", err)
	}
}

// Run barre al arrancar, sin esperar un intervalo entero, y termina con el
// contexto.
func TestRunBarreAlArrancarYTerminaConElContexto(t *testing.T) {
	repo := &repoDeBarrido{respuestas: []int64{2}, called: make(chan struct{}, 1)}
	logs := &bytes.Buffer{}
	s := nuevoSweeper(t, repo, 5, logs)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()

	select {
	case <-repo.called:
	case <-time.After(2 * time.Second):
		t.Fatal("Run no barrió al arrancar")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run no terminó con el contexto")
	}
}

// Un fallo del barrido se registra como error y no detiene el ciclo; un
// apagado a mitad de barrido no es un error.
func TestRunRegistraLosFallosYLosBorrados(t *testing.T) {
	casos := []struct {
		name string
		repo *repoDeBarrido
		want string
		not  string
	}{
		{"borrados", &repoDeBarrido{respuestas: []int64{2}}, "desafíos de email vencidos borrados", "level=ERROR"},
		{"fallo", &repoDeBarrido{errAt: 1}, "barrido de desafíos de email fallido", ""},
	}
	for _, tc := range casos {
		t.Run(tc.name, func(t *testing.T) {
			tc.repo.called = make(chan struct{}, 1)
			logs := &syncBuffer{}
			s, _ := emailchallenge.NewSweeper(tc.repo, time.Hour, 5, slog.New(slog.NewTextHandler(logs, nil)))

			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan struct{})
			go func() { defer close(done); s.Run(ctx) }()
			<-tc.repo.called
			// Da tiempo a que el ciclo termine de loguear antes de apagar.
			deadline := time.Now().Add(2 * time.Second)
			for !strings.Contains(logs.String(), tc.want) && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			cancel()
			<-done

			out := logs.String()
			if !strings.Contains(out, tc.want) {
				t.Errorf("el log no contiene %q:\n%s", tc.want, out)
			}
			if tc.not != "" && strings.Contains(out, tc.not) {
				t.Errorf("el log contiene %q:\n%s", tc.not, out)
			}
		})
	}
}

// syncBuffer es un buffer seguro para que lo escriba la goroutine de Run y lo
// lea el test.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// repoQueCancela cancela el contexto del barrido y falla, como un apagado a mitad
// de una sentencia.
type repoQueCancela struct {
	domain.EmailChallengeRepository
	cancel context.CancelFunc
}

func (r repoQueCancela) DeleteExpired(context.Context, time.Time, int) (int64, error) {
	r.cancel()
	return 0, errors.New("conexión cerrada por el apagado")
}

// Un barrido interrumpido por el apagado no es un error: se registra como
// información y no como falla.
func TestRunTrataElApagadoALaMitadDeUnBarridoComoInformacion(t *testing.T) {
	logs := &syncBuffer{}
	ctx, cancel := context.WithCancel(t.Context())
	s, err := emailchallenge.NewSweeper(repoQueCancela{cancel: cancel}, time.Hour, 5, slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run no terminó tras el apagado")
	}

	out := logs.String()
	if !strings.Contains(out, "interrumpido por el apagado") {
		t.Errorf("el log no registra la interrupción:\n%s", out)
	}
	if strings.Contains(out, "level=ERROR") {
		t.Errorf("un apagado no es un error:\n%s", out)
	}
}
