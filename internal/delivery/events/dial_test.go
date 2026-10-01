// Tests del dial acotado por contexto (X1 del contrato de resiliencia). Solo
// el cálculo del presupuesto y el corte temprano por contexto ya vencido se
// prueban acá: abrir una conexión de verdad requiere un broker real, fuera
// del alcance de los tests unitarios de este paquete (ver envelope_test.go).
package events

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRemainingOrFallbackUsaElFallbackSinDeadline(t *testing.T) {
	got := remainingOrFallback(context.Background(), 7*time.Second)

	if got != 7*time.Second {
		t.Errorf("timeout = %v, se esperaban 7s (el fallback)", got)
	}
}

func TestRemainingOrFallbackUsaElMenorDeLosDos(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// El fallback (DialTimeout) es mucho más generoso que lo que le queda al
	// ctx: tiene que ganar el remanente del ctx, no el fallback.
	got := remainingOrFallback(ctx, 10*time.Second)

	if got <= 0 || got > 50*time.Millisecond {
		t.Errorf("timeout = %v, se esperaba acotado por el remanente del contexto (≤ 50ms)", got)
	}
}

func TestRemainingOrFallbackUsaElFallbackCuandoEsElMenor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()

	got := remainingOrFallback(ctx, 3*time.Second)

	if got > 3*time.Second {
		t.Errorf("timeout = %v, se esperaba acotado por el fallback (3s)", got)
	}
}

// Con el contexto ya cancelado, dialWithDeadline no debe intentar abrir
// ninguna conexión: tiene que devolver el error del contexto de inmediato.
// Es justamente lo que faltaba antes de X1, donde el dial de reconexión
// corría con su propia ventana de tiempo sin mirar el contexto del publish.
func TestDialWithDeadlineNoMarcaConElContextoYaVencido(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	dial := dialWithDeadline(ctx, 10*time.Second)

	inicio := time.Now()
	_, err := dial("tcp", "127.0.0.1:1")
	transcurrido := time.Since(inicio)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, se esperaba context.Canceled", err)
	}
	// Sin intento de red: tiene que volver de inmediato, no esperar nada
	// cercano al fallback de 10s.
	if transcurrido > 100*time.Millisecond {
		t.Errorf("tardó %v; un contexto ya cancelado no debería intentar conectar", transcurrido)
	}
}
