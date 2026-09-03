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

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// RefreshDeps son las dependencias de RefreshService. Todas son puertos de
// domain.
type RefreshDeps struct {
	Sessions  domain.SessionRepository
	Tokens    domain.TokenGenerator
	Publisher domain.EventPublisher
	Logger    *slog.Logger
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
	case d.Publisher == nil:
		return nil, errors.New("session: falta el publisher de eventos")
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
		if err := s.deps.Sessions.RevokeAllByUserID(ctx, found.UserID); err != nil {
			return "", "", fmt.Errorf("session: no se pudo ejecutar la defensa activa: %w", err)
		}
		s.deps.Logger.WarnContext(ctx, "reúso de refresh token detectado: defensa activa ejecutada",
			slog.String("user_id", found.UserID.String()),
		)

		// TECH DEBT (MVP): doble escritura no atómica.
		// La revocación de sesiones y el publish a RabbitMQ no comparten transacción:
		// si el publish falla, los tokens FCM del usuario no se borran.
		// Solución pendiente: patrón Outbox. Aprobado como limitación conocida para el MVP.
		s.publishSessionsRevoked(ctx, found.UserID)

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

// publishSessionsRevoked emite user.sessions.revoked tras la Defensa Activa,
// sin poner en riesgo la respuesta de /refresh: la revocación ya está
// persistida y devolver un error acá haría que el cliente reintentara sobre
// un Refresh Token que la Defensa Activa ya invalidó. Se registra el fallo y
// se sigue, con la misma contrapartida (deuda técnica de doble escritura no
// atómica) documentada en el comentario del llamador.
func (s *RefreshService) publishSessionsRevoked(ctx context.Context, userID uuid.UUID) {
	evt := domain.NewSessionsRevoked(userID, domain.SessionsRevokedReasonReuseDetected)
	if err := s.deps.Publisher.PublishSessionsRevoked(ctx, evt); err != nil {
		s.deps.Logger.ErrorContext(ctx, "no se pudo publicar user.sessions.revoked; la defensa activa se mantiene",
			slog.String("user_id", userID.String()),
			slog.String("error", err.Error()),
		)
	}
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
