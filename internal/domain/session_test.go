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
	startedAt := now.Add(-2 * time.Hour)

	t.Run("construye una sesión no revocada con los invariantes cumplidos", func(t *testing.T) {
		s, err := domain.NewSession(userID, "hash-del-refresh-token", expiresAt, startedAt, now)
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
		if !s.StartedAt.Equal(startedAt) || s.StartedAt.Location() != time.UTC {
			t.Errorf("started at = %v, se esperaba %v en UTC", s.StartedAt, startedAt)
		}
	})

	t.Run("cada sesión recibe un identificador distinto", func(t *testing.T) {
		a, _ := domain.NewSession(userID, "hash-a", expiresAt, now, now)
		b, _ := domain.NewSession(userID, "hash-b", expiresAt, now, now)
		if a.ID == b.ID {
			t.Error("dos sesiones distintas no pueden compartir ID")
		}
	})

	t.Run("rechaza sesiones inconsistentes", func(t *testing.T) {
		cases := map[string]struct {
			userID    uuid.UUID
			hash      string
			expiresAt time.Time
			startedAt time.Time
		}{
			"sin user_id":             {uuid.Nil, "hash", expiresAt, now},
			"sin hash":                {userID, "", expiresAt, now},
			"expires_at en el pasado": {userID, "hash", now.Add(-time.Hour), now},
			"expires_at igual a now":  {userID, "hash", now, now},
			"sin started_at":          {userID, "hash", expiresAt, time.Time{}},
			"started_at en el futuro": {userID, "hash", expiresAt, now.Add(time.Second)},
		}
		for name, tc := range cases {
			t.Run(name, func(t *testing.T) {
				if _, err := domain.NewSession(tc.userID, tc.hash, tc.expiresAt, tc.startedAt, now); !errors.Is(err, domain.ErrInvalidSession) {
					t.Errorf("error = %v, se esperaba ErrInvalidSession", err)
				}
			})
		}
	})
}

func TestSessionMaxLifetimeExceeded(t *testing.T) {
	inicio := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	maxima := 90 * 24 * time.Hour
	s := &domain.Session{StartedAt: inicio}

	casos := map[string]struct {
		now  time.Time
		max  time.Duration
		want bool
	}{
		"recién iniciada":          {inicio, maxima, false},
		"dentro de la vida máxima": {inicio.Add(maxima - time.Second), maxima, false},
		"justo en el límite":       {inicio.Add(maxima), maxima, false},
		"un segundo después":       {inicio.Add(maxima + time.Second), maxima, true},
		"vida máxima cero":         {inicio, 0, true},
		"vida máxima negativa":     {inicio, -time.Hour, true},
	}

	for nombre, caso := range casos {
		t.Run(nombre, func(t *testing.T) {
			if got := s.MaxLifetimeExceeded(caso.max, caso.now); got != caso.want {
				t.Errorf("MaxLifetimeExceeded = %v, se esperaba %v", got, caso.want)
			}
		})
	}
}
