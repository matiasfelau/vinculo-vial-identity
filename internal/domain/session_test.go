package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

func TestNewSession(t *testing.T) {
	now := time.Date(2026, 8, 12, 15, 4, 5, 0, time.FixedZone("ART", -3*60*60))
	expiresAt := now.Add(30 * 24 * time.Hour)
	userID := uuid.New()

	t.Run("construye una sesión no revocada con los invariantes cumplidos", func(t *testing.T) {
		s, err := domain.NewSession(userID, "hash-del-refresh-token", expiresAt, now)
		if err != nil {
			t.Fatalf("error inesperado: %v", err)
		}
		if s.ID.String() == "" || s.ID.Variant() == 0 {
			t.Error("se esperaba un UUID generado")
		}
		if s.UserID != userID {
			t.Errorf("user id = %v, se esperaba %v", s.UserID, userID)
		}
		if s.IsRevoked {
			t.Error("una sesión nueva no debe nacer revocada")
		}
		if s.CreatedAt.Location() != time.UTC || s.ExpiresAt.Location() != time.UTC {
			t.Error("las marcas de tiempo deben normalizarse a UTC")
		}
		if !s.CreatedAt.Equal(now) {
			t.Errorf("created at = %v, se esperaba el mismo instante que %v", s.CreatedAt, now)
		}
		if !s.ExpiresAt.Equal(expiresAt) {
			t.Errorf("expires at = %v, se esperaba el mismo instante que %v", s.ExpiresAt, expiresAt)
		}
	})

	t.Run("cada sesión recibe un identificador distinto", func(t *testing.T) {
		a, _ := domain.NewSession(userID, "hash-a", expiresAt, now)
		b, _ := domain.NewSession(userID, "hash-b", expiresAt, now)
		if a.ID == b.ID {
			t.Error("dos sesiones distintas no pueden compartir ID")
		}
	})

	t.Run("rechaza sesiones inconsistentes", func(t *testing.T) {
		cases := map[string]struct {
			userID    uuid.UUID
			hash      string
			expiresAt time.Time
		}{
			"sin user_id":            {uuid.Nil, "hash", expiresAt},
			"sin hash":               {userID, "", expiresAt},
			"expires_at en el pasado": {userID, "hash", now.Add(-time.Hour)},
			"expires_at igual a now":  {userID, "hash", now},
		}
		for name, tc := range cases {
			t.Run(name, func(t *testing.T) {
				if _, err := domain.NewSession(tc.userID, tc.hash, tc.expiresAt, now); !errors.Is(err, domain.ErrInvalidSession) {
					t.Errorf("error = %v, se esperaba ErrInvalidSession", err)
				}
			})
		}
	})
}
