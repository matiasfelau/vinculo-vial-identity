package sanction_test

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
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/sanction"
)

// repoFake simula una tabla de sanciones vencidas: cada DeleteExpired borra hasta
// limit y devuelve cuántos había.
type repoFake struct {
	mu        sync.Mutex
	pending   int64
	err       error
	errAtCall int

	calls  int
	limits []int
	nows   []time.Time
	// llamado avisa cada llamada, para sincronizar los tests de Run.
	llamado chan struct{}
}

func (r *repoFake) DeleteExpired(_ context.Context, now time.Time, limit int) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.calls++
	r.limits = append(r.limits, limit)
	r.nows = append(r.nows, now)
	if r.llamado != nil {
		select {
		case r.llamado <- struct{}{}:
		default:
		}
	}

	if r.err != nil && (r.errAtCall == 0 || r.errAtCall == r.calls) {
		return 0, r.err
	}
	n := r.pending
	if n > int64(limit) {
		n = int64(limit)
	}
	r.pending -= n
	return n, nil
}

var _ domain.SanctionCarryoverRepository = (*repoFake)(nil)

func sweeper(t *testing.T, repo *repoFake, batch int, logs *bytes.Buffer) *sanction.Sweeper {
	t.Helper()

	var logger *slog.Logger
	if logs != nil {
		logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	s, err := sanction.NewSweeper(repo, 10*time.Millisecond, batch, logger)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	return s
}

// Borra todas las vencidas, de a lotes, y devuelve el total.
func TestSweepOnceBorraTodasLasVencidasDeALotes(t *testing.T) {
	repo := &repoFake{pending: 25}

	deleted, err := sweeper(t, repo, 10, nil).SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if deleted != 25 {
		t.Errorf("borradas = %d, se esperaban 25", deleted)
	}
	// 10 + 10 + 5: el lote incompleto corta el barrido sin una llamada de más.
	if repo.calls != 3 {
		t.Errorf("llamadas = %d, se esperaban 3", repo.calls)
	}
	for _, l := range repo.limits {
		if l != 10 {
			t.Errorf("límite = %d, se esperaba el tamaño de lote 10", l)
		}
	}
}

func TestSweepOnceSinVencidosNoHaceNada(t *testing.T) {
	repo := &repoFake{}

	deleted, err := sweeper(t, repo, 10, nil).SweepOnce(context.Background())
	if err != nil || deleted != 0 {
		t.Fatalf("borradas=%d err=%v, se esperaba 0 y nil", deleted, err)
	}
	if repo.calls != 1 {
		t.Errorf("llamadas = %d, se esperaba 1", repo.calls)
	}
}

// Un múltiplo exacto del lote obliga a una llamada más para confirmar que no
// queda nada.
func TestSweepOnceConUnMultiploExactoDelLote(t *testing.T) {
	repo := &repoFake{pending: 20}

	deleted, err := sweeper(t, repo, 10, nil).SweepOnce(context.Background())
	if err != nil || deleted != 20 {
		t.Fatalf("borradas=%d err=%v, se esperaba 20 y nil", deleted, err)
	}
	if repo.calls != 3 {
		t.Errorf("llamadas = %d, se esperaban 3 (10 + 10 + 0)", repo.calls)
	}
}

// El corte se hace contra el reloj: solo vence lo que tiene expires_at <= ahora.
func TestSweepOnceUsaLaHoraActual(t *testing.T) {
	repo := &repoFake{pending: 1}

	antes := time.Now()
	if _, err := sweeper(t, repo, 10, nil).SweepOnce(context.Background()); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	despues := time.Now()

	if got := repo.nows[0]; got.Before(antes) || got.After(despues) {
		t.Errorf("now = %v, se esperaba la hora actual entre %v y %v", got, antes, despues)
	}
}

// Ante un error devuelve igual lo borrado hasta ahí, con el error alcanzable.
func TestSweepOnceConErrorDevuelveLoBorradoYElError(t *testing.T) {
	repo := &repoFake{pending: 100, err: domain.ErrDatabaseUnavailable, errAtCall: 3}

	deleted, err := sweeper(t, repo, 10, nil).SweepOnce(context.Background())

	if !errors.Is(err, domain.ErrDatabaseUnavailable) {
		t.Fatalf("error = %v, se esperaba ErrDatabaseUnavailable", err)
	}
	if deleted != 20 {
		t.Errorf("borradas = %d, se esperaban los 20 de los dos lotes previos", deleted)
	}
}

func TestSweepOnceSeDetieneConElContextoCancelado(t *testing.T) {
	repo := &repoFake{pending: 100}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := sweeper(t, repo, 10, nil).SweepOnce(ctx)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, se esperaba context.Canceled", err)
	}
	if repo.calls != 0 {
		t.Errorf("con el contexto cancelado no se debe tocar la base")
	}
}

// Run barra al arrancar, sin esperar el primer intervalo, y sigue barriendo.
func TestRunBarreAlArrancarYPeriodicamente(t *testing.T) {
	repo := &repoFake{llamado: make(chan struct{}, 16)}
	s := sweeper(t, repo, 10, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx)
	}()

	for i := 0; i < 3; i++ {
		select {
		case <-repo.llamado:
		case <-time.After(2 * time.Second):
			t.Fatalf("el barrido %d no se ejecutó a tiempo", i+1)
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run no terminó tras cancelar el contexto")
	}
}

// El apagado ordenado: cancelar el contexto hace volver a Run y no deja ninguna
// goroutine barriendo.
func TestRunTerminaAlCancelarElContexto(t *testing.T) {
	repo := &repoFake{}
	s, err := sanction.NewSweeper(repo, time.Hour, 10, nil)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run no terminó tras cancelar el contexto")
	}
}

// Un barrido que falla no detiene el proceso: se loguea y el próximo ciclo
// reintenta.
func TestRunSobreviveAUnBarridoFallidoYLoLoguea(t *testing.T) {
	repo := &repoFake{err: errors.New("deadlock"), llamado: make(chan struct{}, 16)}
	var logs bytes.Buffer
	s := sweeper(t, repo, 10, &logs)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx)
	}()

	for i := 0; i < 2; i++ {
		select {
		case <-repo.llamado:
		case <-time.After(2 * time.Second):
			t.Fatalf("tras el fallo no hubo un nuevo barrido (%d)", i+1)
		}
	}
	cancel()
	<-done

	if !strings.Contains(logs.String(), "level=ERROR") {
		t.Errorf("el barrido fallido debe quedar en el log en ERROR: %s", logs.String())
	}
}

func TestSweepLogueaLoBorradoSinDatosDeNadie(t *testing.T) {
	repo := &repoFake{pending: 3, llamado: make(chan struct{}, 16)}
	var logs bytes.Buffer
	s := sweeper(t, repo, 10, &logs)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx)
	}()
	<-repo.llamado
	cancel()
	<-done

	if !strings.Contains(logs.String(), "deleted=3") {
		t.Errorf("se esperaba el conteo de sanciones borradas en el log: %s", logs.String())
	}
}

func TestNewSweeperValidaSusParametros(t *testing.T) {
	repo := &repoFake{}

	casos := map[string]func() (*sanction.Sweeper, error){
		"sin repositorio":    func() (*sanction.Sweeper, error) { return sanction.NewSweeper(nil, time.Hour, 10, nil) },
		"intervalo en cero":  func() (*sanction.Sweeper, error) { return sanction.NewSweeper(repo, 0, 10, nil) },
		"intervalo negativo": func() (*sanction.Sweeper, error) { return sanction.NewSweeper(repo, -time.Second, 10, nil) },
		"lote en cero":       func() (*sanction.Sweeper, error) { return sanction.NewSweeper(repo, time.Hour, 0, nil) },
	}

	for nombre, construir := range casos {
		t.Run(nombre, func(t *testing.T) {
			if _, err := construir(); err == nil {
				t.Error("se esperaba un error")
			}
		})
	}
}
