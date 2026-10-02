package domain

import (
	"time"

	"github.com/google/uuid"
)

// Session es una credencial de sesión de larga vida: el Refresh Token opaco
// que el login (US-02) emite junto con el Access Token, y que US-03 rota y
// revoca.
//
// Solo se persiste el SHA-256 del token (RefreshTokenHash); el valor opaco en
// sí únicamente existe en la respuesta HTTP que recibe el cliente y nunca se
// guarda en ningún lado.
type Session struct {
	ID               uuid.UUID
	UserID           uuid.UUID
	RefreshTokenHash string
	IsRevoked        bool
	ExpiresAt        time.Time
	CreatedAt        time.Time
}

// NewSession construye una sesión nueva, no revocada, a partir del hash del
// Refresh Token recién emitido.
func NewSession(userID uuid.UUID, refreshTokenHash string, expiresAt, now time.Time) (*Session, error) {
	switch {
	case userID == uuid.Nil:
		return nil, invalidSession("user_id vacío")
	case refreshTokenHash == "":
		return nil, invalidSession("hash de refresh token vacío")
	case !expiresAt.After(now):
		return nil, invalidSession("expires_at no es posterior a la fecha de creación")
	}

	return &Session{
		ID:               uuid.New(),
		UserID:           userID,
		RefreshTokenHash: refreshTokenHash,
		IsRevoked:        false,
		ExpiresAt:        expiresAt.UTC(),
		CreatedAt:        now.UTC(),
	}, nil
}

// SessionsRevokedReason acota los motivos admitidos del evento
// user.sessions.revoked, pensado para auditoría.
type SessionsRevokedReason string

const (
	// SessionsRevokedReasonReuseDetected es el motivo que dispara la Defensa
	// Activa de US-03: se detectó el reúso de un Refresh Token ya rotado y se
	// revocaron todas las sesiones del usuario.
	SessionsRevokedReasonReuseDetected SessionsRevokedReason = "REUSE_DETECTED"
)

// SessionsRevoked es el evento de dominio que dispara la revocación masiva de
// sesiones de un usuario. Se publica como `user.sessions.revoked` para que
// vinculo-vial-notification dé de baja los tokens FCM del usuario en todos
// sus dispositivos.
//
// No se emite en un logout normal de un solo dispositivo: ver la nota de
// EventPublisher.PublishSessionsRevoked en ports.go.
//
// EventID es estable por evento de outbox: si una publicación se reintenta
// (el broker nunca confirmó, o confirmó pero el worker no pudo marcarlo como
// enviado), el reintento reutiliza el mismo EventID, para que un consumidor
// que deduplique por event_id lo trate como el mismo evento, no uno nuevo.
type SessionsRevoked struct {
	EventID uuid.UUID
	UserID  uuid.UUID
	Reason  SessionsRevokedReason
}

// NewSessionsRevoked construye el evento de la Defensa Activa a partir de un
// OutboxEvent ya persistido: eventID es el mismo OutboxEvent.ID, nunca uno
// generado en este punto.
func NewSessionsRevoked(eventID, userID uuid.UUID, reason SessionsRevokedReason) SessionsRevoked {
	return SessionsRevoked{EventID: eventID, UserID: userID, Reason: reason}
}

// OutboxEvent es un evento de dominio pendiente de publicar, persistido en la
// misma transacción que el cambio de estado que lo origina (patrón
// Transactional Outbox). Hoy es exclusivamente el de la Defensa Activa de
// US-03: la publicación de user.sessions.revoked se demora hasta el worker en
// background de internal/service/outbox, en vez de intentarse de forma
// síncrona dentro de /refresh — un evento sin fila de outbox persistida es
// indistinguible de uno que nunca pasó, así que esta tabla es la única fuente
// de verdad de "qué falta publicar".
//
// Resuelve el TECH DEBT (MVP) que documentaba session.RefreshService antes de
// esta versión: la revocación de sesiones y el evento a publicar ya no son
// una doble escritura no atómica, porque SessionRepository.RevokeAllByUserID
// persiste ambas cosas en la misma transacción.
type OutboxEvent struct {
	// ID es el mismo valor que lleva SessionsRevoked.EventID al publicarse.
	ID        uuid.UUID
	UserID    uuid.UUID
	Reason    SessionsRevokedReason
	CreatedAt time.Time
}
