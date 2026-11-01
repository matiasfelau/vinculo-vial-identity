// Package session implementa los casos de uso de gestión de sesión de US-03:
// la rotación de Refresh Token (RefreshService) y el cierre de sesión
// (LogoutService). Depende únicamente de los puertos de domain, igual que
// internal/service/signin, para poder ejercitarse entero con dobles, sin
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
//
// No incluye domain.EventPublisher: la Defensa Activa persiste el evento de
// outbox junto con la revocación (ver SessionRepository.RevokeAllByUserID),
// y es internal/service/outbox.Worker quien lo publica después, en
// background. RefreshService nunca habla con el broker.
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
			s.logFailedAttempt(ctx, "sesión inexistente", slog.String("refresh_token_hash", hash))
			return "", "", domain.ErrSessionNotFound
		}
		return "", "", fmt.Errorf("session: no se pudo buscar la sesión: %w", err)
	}

	if s.deps.Now().After(found.ExpiresAt) {
		s.logFailedAttempt(ctx, "sesión expirada", slog.String("user_id", found.UserID.String()))
		return "", "", domain.ErrSessionExpired
	}

	if found.IsRevoked {
		// Defensa Activa: se prefiere el falso positivo (un cliente mal
		// implementado que reintenta un token ya rotado paga un re-login) al
		// falso negativo (una cuenta secuestrada), así que la revocación
		// alcanza a todas las sesiones del usuario, vigentes o no.
		//
		// El evento de outbox se persiste en la misma transacción que la
		// revocación (ver SessionRepository.RevokeAllByUserID): no hay doble
		// escritura, y por lo tanto no hay forma de que la revocación quede
		// persistida sin que el evento a publicar también lo quede, ni
		// viceversa.
		outboxEvent, err := domain.NewOutboxEvent("user.sessions.revoked", map[string]string{
			"user_id": found.UserID.String(),
			"reason":  string(domain.SessionsRevokedReasonReuseDetected),
		})
		if err != nil {
			return "", "", fmt.Errorf("session: no se pudo armar el evento de outbox: %w", err)
		}
		outboxEvent.CreatedAt = s.deps.Now()
		if err := s.deps.Sessions.RevokeAllByUserID(ctx, found.UserID, &outboxEvent); err != nil {
			return "", "", fmt.Errorf("session: no se pudo ejecutar la defensa activa: %w", err)
		}
		s.deps.Logger.WarnContext(ctx, "reúso de refresh token detectado: defensa activa ejecutada",
			slog.String("user_id", found.UserID.String()),
		)

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

// logFailedAttempt deja constancia de un intento de refresh rechazado.
//
// Se identifica la sesión por el atributo que esté disponible en cada
// caso —el hash del Refresh Token cuando ninguna sesión coincidió, el
// user_id cuando sí— pero nunca por el token en claro ni por ningún otro
// dato personal. El motivo sí se distingue acá porque es un log interno del
// servidor: la respuesta HTTP es la misma (401) tanto si la sesión no
// existe como si ya venció.
func (s *RefreshService) logFailedAttempt(ctx context.Context, motivo string, identificador slog.Attr) {
	s.deps.Logger.LogAttrs(ctx, slog.LevelWarn, "intento de refresh rechazado",
		identificador,
		slog.String("motivo", motivo),
	)
}

// LogoutDeps son las dependencias de LogoutService. Todas son puertos de
// domain.
type LogoutDeps struct {
	Sessions domain.SessionRepository
	Tokens   domain.TokenGenerator
	Logger   *slog.Logger
}

// LogoutService es el caso de uso de cierre de sesión de /logout.
type LogoutService struct {
	deps LogoutDeps
}

// NewLogoutService valida que estén todas las dependencias y construye el
// servicio.
func NewLogoutService(d LogoutDeps) (*LogoutService, error) {
	switch {
	case d.Sessions == nil:
		return nil, errors.New("session: falta el repositorio de sesiones")
	case d.Tokens == nil:
		return nil, errors.New("session: falta el generador de tokens")
	}

	if d.Logger == nil {
		d.Logger = slog.Default()
	}

	return &LogoutService{deps: d}, nil
}

// Logout revoca la sesión asociada al Refresh Token recibido.
//
// Siempre termina en éxito desde la perspectiva del llamador —exista o no
// una sesión con ese hash, esté o no ya revocada, no hay forma de
// distinguirlo desde afuera (anti-enumeración)— salvo que la propia
// revocación no se pueda persistir, que es un fallo de infraestructura, no
// un caso del contrato de /logout.
func (s *LogoutService) Logout(ctx context.Context, refreshToken string) error {
	hash := s.deps.Tokens.Hash(refreshToken)

	if err := s.deps.Sessions.RevokeByHash(ctx, hash); err != nil {
		return fmt.Errorf("session: no se pudo revocar la sesión: %w", err)
	}

	return nil
}
