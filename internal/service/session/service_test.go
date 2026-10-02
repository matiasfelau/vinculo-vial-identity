package session_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/session"
)

const validRefreshToken = "refresh-token-recibido-del-cliente"

func vigenteSession() *domain.Session {
	return &domain.Session{
		ID:               uuid.New(),
		UserID:           uuid.New(),
		RefreshTokenHash: "hash-de:" + validRefreshToken,
		IsRevoked:        false,
		ExpiresAt:        time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC),
		CreatedAt:        time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC),
	}
}

// harness agrupa los dos dobles de RefreshService y el logger, para que cada
// test arme la vía feliz completa y degrade solo lo que le interesa
// ejercitar.
type harness struct {
	sessions *sessionsMock
	tokens   *tokensMock
	logs     *strings.Builder
	now      time.Time
}

func newHarness() *harness {
	now := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	return &harness{
		sessions: &sessionsMock{found: vigenteSession()},
		tokens: &tokensMock{
			accessToken:      "access-token-rotado",
			refreshToken:     "refresh-token-rotado",
			refreshHash:      "hash-del-refresh-token-rotado",
			refreshExpiresAt: now.Add(30 * 24 * time.Hour),
		},
		logs: &strings.Builder{},
		now:  now,
	}
}

func (h *harness) service(t *testing.T) *session.RefreshService {
	t.Helper()

	svc, err := session.NewRefreshService(session.RefreshDeps{
		Sessions: h.sessions,
		Tokens:   h.tokens,
		Logger:   slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now:      func() time.Time { return h.now },
	})
	if err != nil {
		t.Fatalf("no se pudo construir el servicio: %v", err)
	}
	return svc
}

func TestRefreshRotaLaSesionVigente(t *testing.T) {
	h := newHarness()
	svc := h.service(t)

	access, refresh, err := svc.Refresh(context.Background(), validRefreshToken)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if access != h.tokens.accessToken {
		t.Errorf("access token = %q, se esperaba %q", access, h.tokens.accessToken)
	}
	if refresh != h.tokens.refreshToken {
		t.Errorf("refresh token = %q, se esperaba %q", refresh, h.tokens.refreshToken)
	}
	if h.tokens.accessUserID != h.sessions.found.UserID {
		t.Errorf("el access token se emitió para %v, se esperaba %v", h.tokens.accessUserID, h.sessions.found.UserID)
	}

	if h.sessions.rotateCallCount() != 1 {
		t.Fatalf("RotateSession se llamó %d veces, se esperaba 1", h.sessions.rotateCallCount())
	}
	if h.sessions.rotatedOld != h.sessions.found.ID {
		t.Errorf("se revocó la sesión %v, se esperaba %v", h.sessions.rotatedOld, h.sessions.found.ID)
	}
	rotated := h.sessions.rotatedNew
	if rotated.UserID != h.sessions.found.UserID {
		t.Errorf("session.UserID = %v, se esperaba %v", rotated.UserID, h.sessions.found.UserID)
	}
	if rotated.RefreshTokenHash != h.tokens.refreshHash {
		t.Errorf("session.RefreshTokenHash = %q, se esperaba %q", rotated.RefreshTokenHash, h.tokens.refreshHash)
	}
	if rotated.IsRevoked {
		t.Error("la sesión rotada no debe nacer revocada")
	}
	if !rotated.ExpiresAt.Equal(h.tokens.refreshExpiresAt) {
		t.Errorf("session.ExpiresAt = %v, se esperaba %v", rotated.ExpiresAt, h.tokens.refreshExpiresAt)
	}
}

func TestRefreshBuscaPorElHashDelTokenRecibido(t *testing.T) {
	h := newHarness()
	svc := h.service(t)

	if _, _, err := svc.Refresh(context.Background(), validRefreshToken); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if h.sessions.findCalls != 1 {
		t.Fatalf("FindByHash se llamó %d veces, se esperaba 1", h.sessions.findCalls)
	}
	if got := h.sessions.findHashes[0]; got != h.tokens.Hash(validRefreshToken) {
		t.Errorf("se buscó con el hash %q, se esperaba %q", got, h.tokens.Hash(validRefreshToken))
	}
}

func TestRefreshSesionInexistente(t *testing.T) {
	h := newHarness()
	h.sessions.findErr = domain.ErrSessionNotFound
	svc := h.service(t)

	access, refresh, err := svc.Refresh(context.Background(), "token-que-no-existe")

	if !errors.Is(err, domain.ErrSessionNotFound) {
		t.Errorf("error = %v, se esperaba ErrSessionNotFound", err)
	}
	if access != "" || refresh != "" {
		t.Error("un refresh rechazado no debe emitir tokens")
	}
	if h.sessions.rotateCallCount() != 0 {
		t.Error("un refresh rechazado no debe intentar rotar nada")
	}

	logs := h.logs.String()
	for _, esperado := range []string{"WARN", "intento de refresh rechazado", "sesión inexistente", "refresh_token_hash"} {
		if !strings.Contains(logs, esperado) {
			t.Errorf("el log debería incluir %q: %s", esperado, logs)
		}
	}
}

func TestRefreshSesionExpirada(t *testing.T) {
	h := newHarness()
	h.sessions.found.ExpiresAt = h.now.Add(-time.Second)
	svc := h.service(t)

	access, refresh, err := svc.Refresh(context.Background(), validRefreshToken)

	if !errors.Is(err, domain.ErrSessionExpired) {
		t.Errorf("error = %v, se esperaba ErrSessionExpired", err)
	}
	if access != "" || refresh != "" {
		t.Error("un refresh token expirado no debe emitir tokens")
	}
	if h.sessions.rotateCallCount() != 0 {
		t.Error("un refresh token expirado no debe intentar rotar nada")
	}
	if h.tokens.accessCalls != 0 {
		t.Error("un refresh token expirado no debe emitir un access token")
	}

	logs := h.logs.String()
	for _, esperado := range []string{"WARN", "intento de refresh rechazado", "sesión expirada", h.sessions.found.UserID.String()} {
		if !strings.Contains(logs, esperado) {
			t.Errorf("el log debería incluir %q: %s", esperado, logs)
		}
	}
}

// El reúso de un Refresh Token ya rotado no debe, bajo ninguna circunstancia,
// terminar en una rotación exitosa: es la Defensa Activa, que además revoca
// toda la familia de sesiones del usuario, no solo la sesión reusada.
func TestRefreshSesionYaRevocadaDisparaLaDefensaActiva(t *testing.T) {
	h := newHarness()
	h.sessions.found.IsRevoked = true
	svc := h.service(t)

	access, refresh, err := svc.Refresh(context.Background(), validRefreshToken)

	if !errors.Is(err, domain.ErrSessionReused) {
		t.Errorf("error = %v, se esperaba ErrSessionReused", err)
	}
	if access != "" || refresh != "" {
		t.Error("un refresh token reusado no debe emitir tokens")
	}
	if h.sessions.rotateCallCount() != 0 {
		t.Error("un refresh token reusado no debe intentar rotar nada")
	}
	if h.sessions.revokeAllCallCount() != 1 {
		t.Fatalf("RevokeAllByUserID se llamó %d veces, se esperaba 1", h.sessions.revokeAllCallCount())
	}
	if h.sessions.revokedUserID != h.sessions.found.UserID {
		t.Errorf("se revocó al usuario %v, se esperaba %v", h.sessions.revokedUserID, h.sessions.found.UserID)
	}

	// La Defensa Activa persiste exactamente un evento de outbox, en la misma
	// llamada que la revocación (ver sessionsMock.RevokeAllByUserID): con el
	// UUID del usuario afectado, que es la referencia que Notification
	// necesita para dar de baja los tokens FCM en todos sus dispositivos.
	evento := h.sessions.lastOutboxEvent()
	if evento == nil {
		t.Fatal("se esperaba que la Defensa Activa encolara un evento de outbox")
	}
	if evento.ID == uuid.Nil {
		t.Error("el evento de outbox debe llevar un ID propio, reutilizable entre reintentos")
	}
	if evento.UserID != h.sessions.found.UserID {
		t.Errorf("user_id del evento = %v, se esperaba %v", evento.UserID, h.sessions.found.UserID)
	}
	if evento.Reason != domain.SessionsRevokedReasonReuseDetected {
		t.Errorf("reason del evento = %q, se esperaba %q", evento.Reason, domain.SessionsRevokedReasonReuseDetected)
	}
	if !evento.CreatedAt.Equal(h.now) {
		t.Errorf("created_at del evento = %v, se esperaba %v", evento.CreatedAt, h.now)
	}

	logs := h.logs.String()
	for _, esperado := range []string{"WARN", "reúso de refresh token detectado", "defensa activa ejecutada", h.sessions.found.UserID.String()} {
		if !strings.Contains(logs, esperado) {
			t.Errorf("el log debería incluir %q: %s", esperado, logs)
		}
	}
}

// Un logout normal no debe publicar user.sessions.revoked bajo ninguna
// circunstancia: LogoutService ni siquiera declara un domain.EventPublisher
// entre sus dependencias (ver LogoutDeps), así que no hay forma de que lo
// invoque. Emitirlo en cada logout apagaría las notificaciones de todos los
// dispositivos del usuario por haber cerrado sesión en uno solo.
func TestLogoutNuncaPublicaSessionsRevoked(t *testing.T) {
	sessions := &sessionsMock{}
	tokens := &tokensMock{}
	svc, err := session.NewLogoutService(session.LogoutDeps{Sessions: sessions, Tokens: tokens})
	if err != nil {
		t.Fatalf("no se pudo construir el servicio: %v", err)
	}

	if err := svc.Logout(context.Background(), "cualquier-refresh-token"); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
}

// Si la propia Defensa Activa no se pudo persistir, no debe quedar ningún
// evento de outbox encolado: como ahora la revocación y el evento comparten
// una única transacción (ver SessionRepository.RevokeAllByUserID), un fallo
// de la primera deshace también al segundo — no hay forma de que quede un
// evento sobre una revocación que en verdad falló.
func TestRefreshSiFallaLaDefensaActivaNoDejaEventoDeOutboxEncolado(t *testing.T) {
	h := newHarness()
	h.sessions.found.IsRevoked = true
	h.sessions.revokeAllErr = errors.New("la base no responde")
	svc := h.service(t)

	if _, _, err := svc.Refresh(context.Background(), validRefreshToken); err == nil {
		t.Fatal("se esperaba un error")
	}

	if evento := h.sessions.lastOutboxEvent(); evento != nil {
		t.Errorf("se esperaba que no quedara ningún evento de outbox encolado, quedó %+v", evento)
	}
}

// Ninguno de los tres motivos de rechazo de /refresh debe filtrar el Refresh
// Token en claro en el log del servidor: el hash y el user_id alcanzan para
// diagnosticar sin exponer una credencial reutilizable.
//
// El hash se fija a un valor opaco (en vez del "hash-de:"+token por defecto
// del doble) por el mismo motivo que en signin: el hash por defecto incluye
// el token como substring a propósito para poder afirmar qué se buscó en
// otros tests, y probaría un artefacto del doble en vez del comportamiento
// real del servicio.
func TestLosIntentosRechazadosNoFiltranElTokenEnClaro(t *testing.T) {
	const token = "el-refresh-token-secreto-del-cliente"
	const hashOpaco = "5f4dcc3b5aa765d61d8327deb882cf99"

	cases := map[string]func(*harness){
		"sesión inexistente": func(h *harness) { h.sessions.findErr = domain.ErrSessionNotFound },
		"sesión expirada":    func(h *harness) { h.sessions.found.ExpiresAt = h.now.Add(-time.Second) },
		"sesión reusada":     func(h *harness) { h.sessions.found.IsRevoked = true },
	}

	for name, degradar := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness()
			h.tokens.hash = hashOpaco
			degradar(h)
			svc := h.service(t)

			if _, _, err := svc.Refresh(context.Background(), token); err == nil {
				t.Fatal("se esperaba un error")
			}

			if strings.Contains(h.logs.String(), token) {
				t.Errorf("el log filtra el refresh token en claro: %s", h.logs.String())
			}
		})
	}
}

// Si la propia Defensa Activa no se puede persistir, el pedido igual debe
// rechazarse —nunca debe llegar a rotar— aunque el error ya no sea
// ErrSessionReused: hay que poder distinguir "se rechazó y se contuvo el
// incidente" de "se rechazó pero la contención falló".
func TestRefreshSiFallaLaDefensaActivaNoRotaYPropagaElError(t *testing.T) {
	h := newHarness()
	h.sessions.found.IsRevoked = true
	h.sessions.revokeAllErr = errors.New("la base no responde")
	svc := h.service(t)

	access, refresh, err := svc.Refresh(context.Background(), validRefreshToken)

	if err == nil {
		t.Fatal("se esperaba un error")
	}
	if errors.Is(err, domain.ErrSessionReused) {
		t.Error("si la defensa activa falla, el error no debería colapsar en ErrSessionReused")
	}
	if access != "" || refresh != "" {
		t.Error("un refresh token reusado no debe emitir tokens aunque falle la defensa activa")
	}
	if h.sessions.rotateCallCount() != 0 {
		t.Error("un refresh token reusado no debe intentar rotar nada")
	}
}

// Requisito de atomicidad de US-03: revocar la sesión vieja e insertar la
// nueva es una única operación (RotateSession) precisamente para que un fallo
// a mitad de camino no pueda dejar al servicio en un estado a medias — no hay
// ningún otro punto del código en el que pudiera "revocar y no insertar" por
// separado. El rollback real de la transacción de PostgreSQL se ejercita con
// el docker-compose local, igual que el resto de las sentencias contra la
// base (ver internal/repository/postgres).
func TestRefreshSiFallaLaRotacionNoDevuelveTokensParciales(t *testing.T) {
	h := newHarness()
	h.sessions.rotateErr = errors.New("constraint violation")
	svc := h.service(t)

	access, refresh, err := svc.Refresh(context.Background(), validRefreshToken)

	if err == nil {
		t.Fatal("se esperaba un error")
	}
	if access != "" || refresh != "" {
		t.Errorf("no debería haber tokens ante un fallo de rotación: access=%q refresh=%q", access, refresh)
	}
	if h.sessions.rotateCallCount() != 1 {
		t.Errorf("RotateSession debía llamarse una vez, se llamó %d", h.sessions.rotateCallCount())
	}
}

func TestRefreshPropagaElErrorDeBusquedaSinTraducirlo(t *testing.T) {
	h := newHarness()
	h.sessions.findErr = errors.New("la base no responde")
	svc := h.service(t)

	_, _, err := svc.Refresh(context.Background(), validRefreshToken)

	if err == nil {
		t.Fatal("se esperaba un error")
	}
	if errors.Is(err, domain.ErrSessionNotFound) {
		t.Error("un fallo de infraestructura no debería traducirse en ErrSessionNotFound")
	}
}

func TestNewRefreshServiceValidaLasDependencias(t *testing.T) {
	h := newHarness()
	base := session.RefreshDeps{
		Sessions: h.sessions,
		Tokens:   h.tokens,
	}

	cases := map[string]func(*session.RefreshDeps){
		"sin sessions": func(d *session.RefreshDeps) { d.Sessions = nil },
		"sin tokens":   func(d *session.RefreshDeps) { d.Tokens = nil },
	}

	for name, degradar := range cases {
		t.Run(name, func(t *testing.T) {
			d := base
			degradar(&d)
			if _, err := session.NewRefreshService(d); err == nil {
				t.Error("se esperaba un error de construcción")
			}
		})
	}
}
