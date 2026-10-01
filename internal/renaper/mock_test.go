package renaper_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/renaper"
)

func TestMockConfirmaLaIdentidad(t *testing.T) {
	m := &renaper.Mock{Latency: time.Millisecond}

	ok, err := m.ValidateIdentity(t.Context(),
		[]byte("30123456"), []byte("12345678901"), []byte("F"), []byte{0x89, 0x50, 0x4E, 0x47})
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if !ok {
		t.Error("el mock debería confirmar siempre la identidad")
	}
}

// No mide el valor exacto —eso haría el test lento y frágil sin sumar cobertura
// real— pero sí confirma que DefaultMockLatency se usa de verdad cuando no se
// configura Latency, y no que el mock vuelve instantáneo.
func TestMockUsaLaLatenciaPorDefectoSiNoSeConfigura(t *testing.T) {
	if renaper.DefaultMockLatency < 100*time.Millisecond {
		t.Fatalf("DefaultMockLatency = %v, se esperaba una demora perceptible", renaper.DefaultMockLatency)
	}

	m := &renaper.Mock{}

	start := time.Now()
	if _, err := m.ValidateIdentity(t.Context(), nil, nil, nil, nil); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if elapsed := time.Since(start); elapsed < renaper.DefaultMockLatency/2 {
		t.Errorf("el mock devolvió en %v, se esperaba una demora cercana a %v", elapsed, renaper.DefaultMockLatency)
	}
}

// Con Latency en una hora, este test solo pasa rápido si la cancelación del
// contexto de verdad corta la espera en vez de bloquear hasta que se cumpla la
// latencia simulada.
func TestMockRespetaLaCancelacionDelContexto(t *testing.T) {
	m := &renaper.Mock{Latency: time.Hour}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	ok, err := m.ValidateIdentity(ctx, nil, nil, nil, nil)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, se esperaba context.Canceled", err)
	}
	if ok {
		t.Error("no debe confirmarse una identidad cuando el contexto se cancela")
	}
}

// El contrato de resiliencia de la plataforma exige que un fallo de RENAPER
// se pueda clasificar como "dependencia no disponible" sin inspeccionar texto
// de error: domain.ErrUpstreamUnavailable es lo que abortWithDomainError usa
// para mapear a 503.
func TestMockClasificaLaCancelacionComoUpstreamNoDisponible(t *testing.T) {
	m := &renaper.Mock{Latency: time.Hour}

	ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel()

	_, err := m.ValidateIdentity(ctx, nil, nil, nil, nil)
	if !errors.Is(err, domain.ErrUpstreamUnavailable) {
		t.Errorf("error = %v, se esperaba que envolviera domain.ErrUpstreamUnavailable", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, se esperaba que conservara context.DeadlineExceeded", err)
	}
}
