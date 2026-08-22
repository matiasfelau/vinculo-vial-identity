package secure_test

import (
	"testing"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/secure"
)

func TestWipeSobreescribeElBufferConCeros(t *testing.T) {
	b := []byte("un DNI o contraseña en claro")

	secure.Wipe(b)

	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte[%d] = %d, se esperaba 0 tras Wipe", i, v)
		}
	}
}

// Wipe opera in-place sobre el slice recibido: no debe reasignar ni cambiar
// su longitud, porque el llamador puede seguir sosteniendo referencias al
// mismo backing array (por ejemplo, un defer capturado antes de que el
// buffer se reasigne).
func TestWipePreservaLaLongitudDelSlice(t *testing.T) {
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(i + 1)
	}

	secure.Wipe(b)

	if len(b) != 16 {
		t.Fatalf("len(b) = %d, se esperaba 16", len(b))
	}
}

func TestWipeNoPanicaConSliceVacioNiNil(t *testing.T) {
	secure.Wipe([]byte{})
	secure.Wipe(nil)
}
