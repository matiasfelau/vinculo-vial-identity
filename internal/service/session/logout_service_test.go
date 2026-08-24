package session_test

import (
	"context"
	"errors"
	"testing"

	"github.com/matiasfelau/vinculo-vial-identity/internal/service/session"
)

const logoutRefreshToken = "refresh-token-a-cerrar"

func newLogoutService(t *testing.T, sessions *sessionsMock, tokens *tokensMock) *session.LogoutService {
	t.Helper()

	svc, err := session.NewLogoutService(session.LogoutDeps{
		Sessions: sessions,
		Tokens:   tokens,
	})
	if err != nil {
		t.Fatalf("no se pudo construir el servicio: %v", err)
	}
	return svc
}

// El caso feliz: el hash calculado a partir del token recibido es el que se
// pasa a RevokeByHash, sin pasar por FindByHash — Logout no necesita saber si
// la sesión existía para revocarla.
func TestLogoutRevocaPorElHashDelTokenRecibido(t *testing.T) {
	sessions := &sessionsMock{}
	tokens := &tokensMock{}
	svc := newLogoutService(t, sessions, tokens)

	if err := svc.Logout(context.Background(), logoutRefreshToken); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if sessions.revokeHashCallCount() != 1 {
		t.Fatalf("RevokeByHash se llamó %d veces, se esperaba 1", sessions.revokeHashCallCount())
	}
	if got := sessions.revokedHashes[0]; got != tokens.Hash(logoutRefreshToken) {
		t.Errorf("se revocó el hash %q, se esperaba %q", got, tokens.Hash(logoutRefreshToken))
	}
	if sessions.findCalls != 0 {
		t.Error("Logout no debería buscar la sesión: solo revocarla por hash")
	}
}

// El contrato de /logout es 200 siempre, exista o no la sesión: acá se
// verifica que el servicio no distinga el caso, ya que RevokeByHash no
// devuelve ningún error cuando ninguna fila coincide (ver
// internal/repository/postgres).
func TestLogoutNoFallaConUnTokenQueNoCorrespondeANingunaSesion(t *testing.T) {
	sessions := &sessionsMock{}
	tokens := &tokensMock{}
	svc := newLogoutService(t, sessions, tokens)

	if err := svc.Logout(context.Background(), "token-que-nunca-existio"); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
}

// Un fallo real de infraestructura (la base no responde) sí debe propagarse:
// el 200 incondicional es sobre el estado del token, no sobre la
// disponibilidad de la base.
func TestLogoutPropagaUnFalloDeInfraestructura(t *testing.T) {
	sessions := &sessionsMock{revokeByHashErr: errors.New("la base no responde")}
	tokens := &tokensMock{}
	svc := newLogoutService(t, sessions, tokens)

	if err := svc.Logout(context.Background(), logoutRefreshToken); err == nil {
		t.Error("se esperaba un error cuando la revocación no se pudo persistir")
	}
}

func TestNewLogoutServiceValidaLasDependencias(t *testing.T) {
	sessions := &sessionsMock{}
	tokens := &tokensMock{}
	base := session.LogoutDeps{Sessions: sessions, Tokens: tokens}

	cases := map[string]func(*session.LogoutDeps){
		"sin sessions": func(d *session.LogoutDeps) { d.Sessions = nil },
		"sin tokens":   func(d *session.LogoutDeps) { d.Tokens = nil },
	}

	for name, degradar := range cases {
		t.Run(name, func(t *testing.T) {
			d := base
			degradar(&d)
			if _, err := session.NewLogoutService(d); err == nil {
				t.Error("se esperaba un error de construcción")
			}
		})
	}
}
