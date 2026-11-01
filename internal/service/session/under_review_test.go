package session_test

import (
	"context"
	"testing"
)

// UNDER_REVIEW restringe solo la creación de alertas (US-08), que decide Alert.
// El refresh rota la sesión sin consultar al usuario: RefreshDeps no tiene
// siquiera un repositorio de usuarios, así que el estado de la cuenta no puede
// influir. La sesión de un emisor en revisión rota igual que cualquier otra y
// no dispara la Defensa Activa.
func TestRefreshDeUnUsuarioEnRevisionRotaLaSesion(t *testing.T) {
	h := newHarness()
	svc := h.service(t)

	access, refresh, err := svc.Refresh(context.Background(), validRefreshToken)
	if err != nil {
		t.Fatalf("un usuario UNDER_REVIEW debe poder refrescar: %v", err)
	}

	if access != h.tokens.accessToken || refresh != h.tokens.refreshToken {
		t.Errorf("tokens = (%q, %q), se esperaban los emitidos por el generador", access, refresh)
	}
	if h.sessions.rotateCallCount() != 1 {
		t.Errorf("RotateSession se llamó %d veces, se esperaba 1", h.sessions.rotateCallCount())
	}
}
