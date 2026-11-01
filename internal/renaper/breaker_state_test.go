package renaper_test

import (
	"testing"
	"time"

	"github.com/matiasfelau/vinculo-vial-identity/internal/renaper"
)

func TestStateEmpiezaCerrado(t *testing.T) {
	b := renaper.WithCircuitBreaker(&countingRenaper{ok: true}, renaper.BreakerConfig{}, nil)

	if got := b.State(); got != renaper.BreakerStateClosed {
		t.Errorf("State = %q, se esperaba closed", got)
	}
}

func TestStateInformaOpenTrasElUmbralDeFallas(t *testing.T) {
	fake := &countingRenaper{err: errFallaUpstream()}
	b := renaper.WithCircuitBreaker(fake, renaper.BreakerConfig{
		FailureThreshold: 2, Window: time.Minute, OpenDuration: time.Hour,
	}, nil)

	for i := 0; i < 2; i++ {
		_, _ = b.ValidateIdentity(t.Context(), nil, nil, nil, nil)
	}

	if got := b.State(); got != renaper.BreakerStateOpen {
		t.Errorf("State = %q, se esperaba open", got)
	}
}

// Un rechazo legítimo de RENAPER —(false, nil)— no es una falla: el circuito
// sigue cerrado y /health/deps no se degrada por identidades que no califican.
func TestStateSigueCerradoConRechazosLegitimos(t *testing.T) {
	b := renaper.WithCircuitBreaker(&countingRenaper{ok: false}, renaper.BreakerConfig{
		FailureThreshold: 1, Window: time.Minute, OpenDuration: time.Hour,
	}, nil)

	for i := 0; i < 5; i++ {
		_, _ = b.ValidateIdentity(t.Context(), nil, nil, nil, nil)
	}

	if got := b.State(); got != renaper.BreakerStateClosed {
		t.Errorf("State = %q, se esperaba closed", got)
	}
}

// Vencido OpenDuration, State informa half_open —lo que va a encontrar la
// próxima llamada— sin consumir la prueba: consultar el estado no tiene
// efectos, y la llamada siguiente sigue siendo la que decide.
func TestStateEsHalfOpenTrasOpenDurationSinConsumirLaPrueba(t *testing.T) {
	fake := &countingRenaper{err: errFallaUpstream()}
	b := renaper.WithCircuitBreaker(fake, renaper.BreakerConfig{
		FailureThreshold: 1, Window: time.Minute, OpenDuration: 20 * time.Millisecond,
	}, nil)
	_, _ = b.ValidateIdentity(t.Context(), nil, nil, nil, nil)
	if got := b.State(); got != renaper.BreakerStateOpen {
		t.Fatalf("State = %q, se esperaba open", got)
	}

	time.Sleep(30 * time.Millisecond)

	for i := 0; i < 3; i++ {
		if got := b.State(); got != renaper.BreakerStateHalfOpen {
			t.Fatalf("consulta %d: State = %q, se esperaba half_open", i+1, got)
		}
	}
	llamadas := fake.callCount()

	fake.setResult(true, nil)
	if _, err := b.ValidateIdentity(t.Context(), nil, nil, nil, nil); err != nil {
		t.Fatalf("la prueba debía pasar: %v", err)
	}
	if fake.callCount() != llamadas+1 {
		t.Errorf("la llamada de prueba no llegó a RENAPER: %d llamadas, se esperaban %d", fake.callCount(), llamadas+1)
	}
	if got := b.State(); got != renaper.BreakerStateClosed {
		t.Errorf("tras la prueba exitosa: State = %q, se esperaba closed", got)
	}
}
