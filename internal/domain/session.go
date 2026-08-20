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
