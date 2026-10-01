package renaper_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/matiasfelau/vinculo-vial-identity/internal/renaper"
)

// blockingRenaper nunca responde por sí misma: solo vuelve cuando el contexto
// se cancela o vence, igual que un cliente HTTP real contra una RENAPER caída
// y sin ningún timeout propio.
type blockingRenaper struct{}

func (blockingRenaper) ValidateIdentity(ctx context.Context, _, _, _, _ []byte) (bool, error) {
	<-ctx.Done()
	return false, ctx.Err()
}

type immediateRenaper struct{}

func (immediateRenaper) ValidateIdentity(context.Context, []byte, []byte, []byte, []byte) (bool, error) {
	return true, nil
}

func TestWithTimeoutCortaUnaConsultaQueNuncaResponde(t *testing.T) {
	svc := renaper.WithTimeout(blockingRenaper{}, 20*time.Millisecond)

	inicio := time.Now()
	_, err := svc.ValidateIdentity(t.Context(), nil, nil, nil, nil)
	transcurrido := time.Since(inicio)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, se esperaba context.DeadlineExceeded", err)
	}
	// Margen generoso: el test solo busca detectar que el timeout configurado
	// (20ms) rige de verdad y no un default sin límite.
	if transcurrido > 500*time.Millisecond {
		t.Errorf("tardó %v, el timeout configurado era 20ms", transcurrido)
	}
}

func TestWithTimeoutNoAlteraUnaRespuestaDentroDelPlazo(t *testing.T) {
	svc := renaper.WithTimeout(immediateRenaper{}, time.Second)

	ok, err := svc.ValidateIdentity(t.Context(), nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if !ok {
		t.Error("se esperaba que la identidad se confirmara")
	}
}

// Si el contexto de la petición entrante ya trae un deadline más corto que el
// timeout configurado, ese deadline más corto es el que tiene que cortar la
// espera: WithTimeout acota, nunca extiende.
func TestWithTimeoutNoExtiendeUnDeadlineMasCorto(t *testing.T) {
	svc := renaper.WithTimeout(blockingRenaper{}, time.Hour)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()

	inicio := time.Now()
	_, err := svc.ValidateIdentity(ctx, nil, nil, nil, nil)
	transcurrido := time.Since(inicio)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, se esperaba context.DeadlineExceeded", err)
	}
	if transcurrido > 500*time.Millisecond {
		t.Errorf("tardó %v, el deadline externo era de 20ms", transcurrido)
	}
}
