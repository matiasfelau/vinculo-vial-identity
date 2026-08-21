// Package session implementa los casos de uso de gestión de sesión de US-03:
// la rotación de Refresh Token (RefreshService) y, más adelante, el cierre de
// sesión (LogoutService). Depende únicamente de los puertos de domain, igual
// que internal/service/signin, para poder ejercitarse entero con dobles, sin
// Postgres.
package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// RefreshDeps son las dependencias de RefreshService. Todas son puertos de
// domain.
type RefreshDeps struct {
	Sessions domain.SessionRepository
	Tokens   domain.TokenGenerator
	Logger   *slog.Logger
	// Now permite fijar el reloj en los tests. Si es nil se usa time.Now.
	Now func() time.Time
}

// RefreshService es el caso de uso de rotación de Refresh Token (RTR) de
// /refresh.
type RefreshService struct {
	deps RefreshDeps
}

// NewRefreshService valida que estén todas las dependencias y construye el
// servicio.
func NewRefreshService(d RefreshDeps) (*RefreshService, error) {
	switch {
	case d.Sessions == nil:
		return nil, errors.New("session: falta el repositorio de sesiones")
	case d.Tokens == nil:
		return nil, errors.New("session: falta el generador de tokens")
	}

	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}

	return &RefreshService{deps: d}, nil
}

// Refresh rota el par de tokens de una sesión vigente.
//
// Devuelve, ante fallos, uno de los centinelas de domain: ErrSessionNotFound
// si ningún hash coincide, ErrSessionExpired si la sesión encontrada ya
// venció, o ErrSessionReused si el Refresh Token ya había sido rotado
// (is_revoked = true). Este último caso es Defensa Activa: un cliente
// legítimo nunca reutiliza un Refresh Token después de rotarlo, así que su
// reaparición es la señal de un posible robo de sesión, y la respuesta es
// revocar de una vez toda la familia de sesiones del usuario —no solo la
// comprometida— para forzar una reautenticación completa con credenciales.
//
// La rotación en sí —revocar la sesión vieja e insertar la nueva— se delega
// enteramente a SessionRepository.RotateSession, que la ejecuta como una
// única operación atómica: ver la nota de ese método en domain/ports.go.
func (s *RefreshService) Refresh(ctx context.Context, refreshToken string) (accessToken, newRefreshToken string, err error) {
	hash := s.deps.Tokens.Hash(refreshToken)

	found, err := s.deps.Sessions.FindByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, domain.ErrSessionNotFound) {
			return "", "", domain.ErrSessionNotFound
		}
		return "", "", fmt.Errorf("session: no se pudo buscar la sesión: %w", err)
	}

	if s.deps.Now().After(found.ExpiresAt) {
		return "", "", domain.ErrSessionExpired
	}

	if found.IsRevoked {
		// Defensa Activa: se prefiere el falso positivo (un cliente mal
		// implementado que reintenta un token ya rotado paga un re-login) al
		// falso negativo (una cuenta secuestrada), así que la revocación
		// alcanza a todas las sesiones del usuario, vigentes o no.
		if err := s.deps.Sessions.RevokeAllByUserID(ctx, found.UserID); err != nil {
			return "", "", fmt.Errorf("session: no se pudo ejecutar la defensa activa: %w", err)
		}
		return "", "", domain.ErrSessionReused
	}

	accessToken, err = s.deps.Tokens.NewAccessToken(found.UserID)
	if err != nil {
		return "", "", fmt.Errorf("session: no se pudo emitir el access token: %w", err)
	}

	newRefreshToken, newHash, newExpiresAt, err := s.deps.Tokens.NewRefreshToken()
	if err != nil {
		return "", "", fmt.Errorf("session: no se pudo emitir el refresh token: %w", err)
	}

	rotated, err := domain.NewSession(found.UserID, newHash, newExpiresAt, s.deps.Now())
	if err != nil {
		return "", "", err
	}

	if err := s.deps.Sessions.RotateSession(ctx, found.ID, rotated); err != nil {
		return "", "", fmt.Errorf("session: no se pudo rotar la sesión: %w", err)
	}

	s.deps.Logger.InfoContext(ctx, "sesión rotada", slog.String("user_id", found.UserID.String()))

	return accessToken, newRefreshToken, nil
}
