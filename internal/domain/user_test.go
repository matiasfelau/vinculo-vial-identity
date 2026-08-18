package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

func TestNewUser(t *testing.T) {
	now := time.Date(2026, 8, 12, 15, 4, 5, 0, time.FixedZone("ART", -3*60*60))

	t.Run("construye un usuario activo con los invariantes cumplidos", func(t *testing.T) {
		u, err := domain.NewUser("vecino@example.com", "$argon2id$hash", "blindindex", "cifrado", now)
		if err != nil {
			t.Fatalf("error inesperado: %v", err)
		}
		if u.ID.String() == "" || u.ID.Variant() == 0 {
			t.Error("se esperaba un UUID generado")
		}
		if u.AccountStatus != domain.AccountStatusActive {
			t.Errorf("account status = %q, se esperaba %q", u.AccountStatus, domain.AccountStatusActive)
		}
		if u.CreatedAt.Location() != time.UTC || u.UpdatedAt.Location() != time.UTC {
			t.Error("las marcas de tiempo deben normalizarse a UTC")
		}
		if !u.CreatedAt.Equal(now) {
			t.Errorf("created at = %v, se esperaba el mismo instante que %v", u.CreatedAt, now)
		}
	})

	t.Run("cada alta recibe un identificador distinto", func(t *testing.T) {
		a, _ := domain.NewUser("a@example.com", "h", "b", "c", now)
		b, _ := domain.NewUser("b@example.com", "h", "b", "c", now)
		if a.ID == b.ID {
			t.Error("dos usuarios distintos no pueden compartir ID")
		}
	})

	t.Run("rechaza entidades inconsistentes", func(t *testing.T) {
		cases := map[string]struct {
			email, passwordHash, dniHashed, dniEncrypted string
		}{
			"sin email":       {"", "h", "b", "c"},
			"sin hash":        {"a@example.com", "", "b", "c"},
			"sin blind index": {"a@example.com", "h", "", "c"},
			"sin DNI cifrado": {"a@example.com", "h", "b", ""},
			"todo vacío":      {"", "", "", ""},
		}
		for name, tc := range cases {
			t.Run(name, func(t *testing.T) {
				if _, err := domain.NewUser(tc.email, tc.passwordHash, tc.dniHashed, tc.dniEncrypted, now); !errors.Is(err, domain.ErrInvalidUser) {
					t.Errorf("error = %v, se esperaba ErrInvalidUser", err)
				}
			})
		}
	})
}

func TestNewUserCreated(t *testing.T) {
	now := time.Now()
	u, err := domain.NewUser("vecino@example.com", "$argon2id$hash", "blindindex", "cifrado", now)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	evt := domain.NewUserCreated(u)

	if evt.UserID != u.ID {
		t.Errorf("user id = %v, se esperaba %v", evt.UserID, u.ID)
	}
	if evt.AccountStatus != domain.AccountStatusActive {
		t.Errorf("account status = %q, se esperaba %q", evt.AccountStatus, domain.AccountStatusActive)
	}
	if !evt.OccurredAt.Equal(u.CreatedAt) {
		t.Errorf("occurred at = %v, se esperaba %v", evt.OccurredAt, u.CreatedAt)
	}
}
