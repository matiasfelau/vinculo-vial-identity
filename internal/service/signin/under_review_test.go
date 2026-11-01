package signin_test

import (
	"context"
	"testing"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// UNDER_REVIEW restringe solo la creación de alertas (US-08), que decide Alert.
// El login no consulta account_status: un emisor en revisión tiene que poder
// entrar y recibir sus tokens como cualquier otro.
func TestSignInDeUnUsuarioEnRevisionEmiteLosTokens(t *testing.T) {
	h := newHarness()
	h.users.user.AccountStatus = domain.AccountStatusUnderReview
	svc := h.service(t)

	access, refresh, err := svc.SignIn(context.Background(), []byte("clave-efimera"), []byte("ciphertext"))
	if err != nil {
		t.Fatalf("un usuario UNDER_REVIEW debe poder iniciar sesión: %v", err)
	}

	if access != h.tokens.accessToken || refresh != h.tokens.refreshToken {
		t.Errorf("tokens = (%q, %q), se esperaban los emitidos por el generador", access, refresh)
	}
	if h.sessions.calls != 1 {
		t.Errorf("se crearon %d sesiones, se esperaba 1", h.sessions.calls)
	}
}
