package renaper_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/renaper"
)

// countingRenaper es un domain.RenaperService configurable a mano: devuelve
// siempre el mismo (ok, err) y cuenta cuántas veces se lo llamó de verdad,
// que es justamente lo que un circuito abierto tiene que evitar.
type countingRenaper struct {
	mu    sync.Mutex
	calls int
	ok    bool
	err   error
}

func (f *countingRenaper) ValidateIdentity(context.Context, []byte, []byte, []byte, []byte) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.ok, f.err
}

func (f *countingRenaper) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *countingRenaper) setResult(ok bool, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ok, f.err = ok, err
}

func errFallaUpstream() error {
	return fmt.Errorf("renaper no responde: %w", domain.ErrUpstreamUnavailable)
}

func TestWithCircuitBreakerAbreTrasElUmbralDeFallasYDejaDeTocarLaRed(t *testing.T) {
	fake := &countingRenaper{err: errFallaUpstream()}
	svc := renaper.WithCircuitBreaker(fake, renaper.BreakerConfig{
		FailureThreshold: 3,
		Window:           time.Minute,
		OpenDuration:     time.Hour, // no debe vencer durante este test
	}, nil)

	for i := 0; i < 3; i++ {
		if _, err := svc.ValidateIdentity(t.Context(), nil, nil, nil, nil); !errors.Is(err, domain.ErrUpstreamUnavailable) {
			t.Fatalf("llamada %d: error = %v, se esperaba ErrUpstreamUnavailable", i, err)
		}
	}
	if fake.callCount() != 3 {
		t.Fatalf("calls = %d, se esperaban 3 (circuito todavía cerrado)", fake.callCount())
	}

	// Cuarta llamada: el circuito ya debería estar abierto y no debe tocar a
	// fake en absoluto.
	if _, err := svc.ValidateIdentity(t.Context(), nil, nil, nil, nil); !errors.Is(err, domain.ErrUpstreamUnavailable) {
		t.Errorf("error = %v, se esperaba ErrUpstreamUnavailable (circuito abierto)", err)
	}
	if fake.callCount() != 3 {
		t.Errorf("calls = %d, se esperaban 3: el circuito abierto no debe tocar la red", fake.callCount())
	}
}

// Un rechazo legítimo de RENAPER —(false, nil)— es un resultado válido, no una
// falla de la dependencia: nunca tiene que abrir el circuito, sin importar
// cuántas veces se repita.
func TestWithCircuitBreakerIgnoraUnRechazoLegitimo(t *testing.T) {
	fake := &countingRenaper{ok: false, err: nil}
	svc := renaper.WithCircuitBreaker(fake, renaper.BreakerConfig{
		FailureThreshold: 2,
		Window:           time.Minute,
		OpenDuration:     time.Hour,
	}, nil)

	for i := 0; i < 10; i++ {
		ok, err := svc.ValidateIdentity(t.Context(), nil, nil, nil, nil)
		if err != nil {
			t.Fatalf("llamada %d: error inesperado: %v", i, err)
		}
		if ok {
			t.Fatalf("llamada %d: se esperaba (false, nil)", i)
		}
	}
	if fake.callCount() != 10 {
		t.Errorf("calls = %d, se esperaban 10: un rechazo legítimo no debe abrir el circuito", fake.callCount())
	}
}

func TestWithCircuitBreakerVuelveACerrarTrasUnaPruebaExitosa(t *testing.T) {
	fake := &countingRenaper{err: errFallaUpstream()}
	svc := renaper.WithCircuitBreaker(fake, renaper.BreakerConfig{
		FailureThreshold: 1,
		Window:           time.Minute,
		OpenDuration:     20 * time.Millisecond,
	}, nil)

	if _, err := svc.ValidateIdentity(t.Context(), nil, nil, nil, nil); !errors.Is(err, domain.ErrUpstreamUnavailable) {
		t.Fatalf("error = %v, se esperaba ErrUpstreamUnavailable (abre el circuito)", err)
	}
	if fake.callCount() != 1 {
		t.Fatalf("calls = %d, se esperaba 1", fake.callCount())
	}

	// Todavía abierto: no debe tocar la red.
	if _, err := svc.ValidateIdentity(t.Context(), nil, nil, nil, nil); !errors.Is(err, domain.ErrUpstreamUnavailable) {
		t.Errorf("error = %v, se esperaba ErrUpstreamUnavailable (abierto)", err)
	}
	if fake.callCount() != 1 {
		t.Fatalf("calls = %d, se esperaba que siguiera en 1", fake.callCount())
	}

	time.Sleep(30 * time.Millisecond)
	fake.setResult(true, nil)

	// Vencido OpenDuration, esta llamada es la prueba de medio abierto.
	ok, err := svc.ValidateIdentity(t.Context(), nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("error inesperado en la prueba: %v", err)
	}
	if !ok {
		t.Error("se esperaba que la prueba confirmara la identidad")
	}
	if fake.callCount() != 2 {
		t.Fatalf("calls = %d, se esperaban 2: la prueba sí debe tocar la red", fake.callCount())
	}

	// Ya cerrado: la siguiente llamada pasa directo.
	if _, err := svc.ValidateIdentity(t.Context(), nil, nil, nil, nil); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if fake.callCount() != 3 {
		t.Errorf("calls = %d, se esperaban 3", fake.callCount())
	}
}

func TestWithCircuitBreakerReabreSiLaPruebaFalla(t *testing.T) {
	fake := &countingRenaper{err: errFallaUpstream()}
	svc := renaper.WithCircuitBreaker(fake, renaper.BreakerConfig{
		FailureThreshold: 1,
		Window:           time.Minute,
		OpenDuration:     20 * time.Millisecond,
	}, nil)

	if _, err := svc.ValidateIdentity(t.Context(), nil, nil, nil, nil); !errors.Is(err, domain.ErrUpstreamUnavailable) {
		t.Fatalf("error = %v, se esperaba ErrUpstreamUnavailable (abre el circuito)", err)
	}

	time.Sleep(30 * time.Millisecond)

	// La prueba de medio abierto también falla.
	if _, err := svc.ValidateIdentity(t.Context(), nil, nil, nil, nil); !errors.Is(err, domain.ErrUpstreamUnavailable) {
		t.Fatalf("error = %v, se esperaba ErrUpstreamUnavailable (la prueba falla)", err)
	}
	if fake.callCount() != 2 {
		t.Fatalf("calls = %d, se esperaban 2: la prueba sí debe tocar la red una vez", fake.callCount())
	}

	// Vuelve a estar abierto de inmediato: sin otra llamada a la red.
	if _, err := svc.ValidateIdentity(t.Context(), nil, nil, nil, nil); !errors.Is(err, domain.ErrUpstreamUnavailable) {
		t.Errorf("error = %v, se esperaba ErrUpstreamUnavailable (abierto otra vez)", err)
	}
	if fake.callCount() != 2 {
		t.Errorf("calls = %d, se esperaba que siguiera en 2", fake.callCount())
	}
}

// Las fallas fuera de la ventana no deben acumularse hacia el umbral: es lo
// que distingue "N fallas seguidas" de "N fallas dentro de los últimos X".
func TestWithCircuitBreakerNoAcumulaFallasFueraDeLaVentana(t *testing.T) {
	fake := &countingRenaper{err: errFallaUpstream()}
	svc := renaper.WithCircuitBreaker(fake, renaper.BreakerConfig{
		FailureThreshold: 2,
		Window:           20 * time.Millisecond,
		OpenDuration:     time.Hour,
	}, nil)

	if _, err := svc.ValidateIdentity(t.Context(), nil, nil, nil, nil); !errors.Is(err, domain.ErrUpstreamUnavailable) {
		t.Fatalf("error = %v, se esperaba ErrUpstreamUnavailable", err)
	}

	time.Sleep(30 * time.Millisecond) // la primera falla sale de la ventana

	if _, err := svc.ValidateIdentity(t.Context(), nil, nil, nil, nil); !errors.Is(err, domain.ErrUpstreamUnavailable) {
		t.Fatalf("error = %v, se esperaba ErrUpstreamUnavailable", err)
	}
	if fake.callCount() != 2 {
		t.Fatalf("calls = %d, se esperaban 2", fake.callCount())
	}

	// El circuito debería seguir cerrado: una tercera llamada tiene que tocar
	// la red de nuevo, no fallar rápido.
	if _, err := svc.ValidateIdentity(t.Context(), nil, nil, nil, nil); !errors.Is(err, domain.ErrUpstreamUnavailable) {
		t.Fatalf("error = %v, se esperaba ErrUpstreamUnavailable", err)
	}
	if fake.callCount() != 3 {
		t.Errorf("calls = %d, se esperaban 3: la ventana debería haber descartado la falla vieja", fake.callCount())
	}
}

// Un error que no es ninguno de los dos centinelas de upstream no cuenta como
// falla del circuito: el contrato de resiliencia solo abre el circuito ante
// timeout, conexión rechazada o 5xx del upstream.
func TestWithCircuitBreakerNoCuentaUnErrorSinClasificar(t *testing.T) {
	fake := &countingRenaper{err: errors.New("algo no contemplado")}
	svc := renaper.WithCircuitBreaker(fake, renaper.BreakerConfig{
		FailureThreshold: 1,
		Window:           time.Minute,
		OpenDuration:     time.Hour,
	}, nil)

	for i := 0; i < 5; i++ {
		if _, err := svc.ValidateIdentity(t.Context(), nil, nil, nil, nil); err == nil {
			t.Fatalf("llamada %d: se esperaba que el error se propagara", i)
		}
	}
	if fake.callCount() != 5 {
		t.Errorf("calls = %d, se esperaban 5: un error sin clasificar no debe abrir el circuito", fake.callCount())
	}
}
