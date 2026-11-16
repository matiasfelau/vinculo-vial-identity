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

// US-19: AcceptTerms deja la versión y el instante de la aceptación, en UTC.
func TestAcceptTerms(t *testing.T) {
	now := time.Date(2026, 11, 16, 9, 30, 0, 0, time.FixedZone("ART", -3*60*60))
	u, err := domain.NewUser("vecino@example.com", "$argon2id$hash", "blindindex", "cifrado", now)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if u.TermsVersion != "" || u.TermsAcceptedAt != nil {
		t.Fatalf("un usuario nuevo no tiene consentimiento registrado: (%q, %v)", u.TermsVersion, u.TermsAcceptedAt)
	}

	u.AcceptTerms("1.0", now)

	if u.TermsVersion != "1.0" {
		t.Errorf("terms version = %q, se esperaba \"1.0\"", u.TermsVersion)
	}
	if u.TermsAcceptedAt == nil || !u.TermsAcceptedAt.Equal(now) || u.TermsAcceptedAt.Location() != time.UTC {
		t.Errorf("terms accepted at = %v, se esperaba %v en UTC", u.TermsAcceptedAt, now)
	}
}
