package domain_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

func usuarioConSancion(t *testing.T, status domain.AccountStatus, score, reports int) *domain.User {
	t.Helper()

	u, err := domain.NewUser("vecino@example.com", "hash", "blind-index", "cifrado", time.Now())
	if err != nil {
		t.Fatalf("no se pudo armar el usuario: %v", err)
	}
	u.AccountStatus, u.ReputationScore, u.ReportCount = status, score, reports
	return u
}

// "Penalizada" es cualquiera de las tres señales del contrato: en revisión,
// con reportes, o con reputación negativa.
func TestIsPenalized(t *testing.T) {
	casos := map[string]struct {
		status  domain.AccountStatus
		score   int
		reports int
		want    bool
	}{
		"limpia":                {domain.AccountStatusActive, 0, 0, false},
		"reputación positiva":   {domain.AccountStatusActive, 5, 0, false},
		"en revisión":           {domain.AccountStatusUnderReview, 0, 0, true},
		"con un reporte":        {domain.AccountStatusActive, 0, 1, true},
		"reputación negativa":   {domain.AccountStatusActive, -1, 0, true},
		"revisión y reportes":   {domain.AccountStatusUnderReview, -10, 3, true},
		"reportes y reputación": {domain.AccountStatusActive, -10, 3, true},
	}

	for nombre, caso := range casos {
		t.Run(nombre, func(t *testing.T) {
			u := usuarioConSancion(t, caso.status, caso.score, caso.reports)

			if got := u.IsPenalized(); got != caso.want {
				t.Errorf("IsPenalized = %v, se esperaba %v", got, caso.want)
			}
		})
	}
}

func TestInheritSanction(t *testing.T) {
	u := usuarioConSancion(t, domain.AccountStatusActive, 0, 0)

	u.InheritSanction(domain.SanctionCarryover{
		DNIHMAC:         "no-se-copia-a-la-cuenta",
		AccountStatus:   domain.AccountStatusUnderReview,
		ReputationScore: -20,
		ReportCount:     3,
	})

	if u.AccountStatus != domain.AccountStatusUnderReview || u.ReputationScore != -20 || u.ReportCount != 3 {
		t.Errorf("cuenta = estado %q reputación %d reportes %d", u.AccountStatus, u.ReputationScore, u.ReportCount)
	}
	if u.DNIHashed != "blind-index" {
		t.Errorf("heredar la sanción no debe tocar el Blind Index de la cuenta: %q", u.DNIHashed)
	}
}

func unaBajaValida(t *testing.T) domain.AccountDeletion {
	t.Helper()

	evt, err := domain.NewOutboxEvent(domain.EventTypeUserDeleted, map[string]string{"user_id": uuid.NewString()})
	if err != nil {
		t.Fatalf("no se pudo armar el evento: %v", err)
	}
	baja := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	return domain.AccountDeletion{
		UserID:             uuid.New(),
		DeletedAt:          baja,
		CarryoverExpiresAt: baja.AddDate(0, 0, 1095),
		Events:             []domain.OutboxEvent{evt},
	}
}

func TestAccountDeletionValidate(t *testing.T) {
	if err := unaBajaValida(t).Validate(); err != nil {
		t.Fatalf("una baja completa debería validar: %v", err)
	}

	casos := map[string]func(d *domain.AccountDeletion){
		"sin usuario":              func(d *domain.AccountDeletion) { d.UserID = uuid.Nil },
		"sin fecha de baja":        func(d *domain.AccountDeletion) { d.DeletedAt = time.Time{} },
		"vencimiento igual a baja": func(d *domain.AccountDeletion) { d.CarryoverExpiresAt = d.DeletedAt },
		"vencimiento anterior":     func(d *domain.AccountDeletion) { d.CarryoverExpiresAt = d.DeletedAt.Add(-time.Hour) },
		"sin vencimiento":          func(d *domain.AccountDeletion) { d.CarryoverExpiresAt = time.Time{} },
		"sin eventos":              func(d *domain.AccountDeletion) { d.Events = nil },
	}

	for nombre, degradar := range casos {
		t.Run(nombre, func(t *testing.T) {
			d := unaBajaValida(t)
			degradar(&d)

			if err := d.Validate(); err == nil {
				t.Error("se esperaba un error")
			}
		})
	}
}

// Una cuenta sin penalizaciones no deja nada: ni Blind Index ni estado ni
// conteos.
func TestCarryoverForUnaCuentaLimpiaNoDejaSancion(t *testing.T) {
	d := unaBajaValida(t)
	u := usuarioConSancion(t, domain.AccountStatusActive, 0, 0)

	if got := d.CarryoverFor(u); got != nil {
		t.Errorf("una cuenta limpia no debe dejar sanción: %+v", got)
	}
}

func TestCarryoverForUnaCuentaPenalizadaDejaLaSancion(t *testing.T) {
	d := unaBajaValida(t)
	u := usuarioConSancion(t, domain.AccountStatusUnderReview, -30, 2)

	got := d.CarryoverFor(u)

	if got == nil {
		t.Fatal("una cuenta penalizada debe dejar su sanción")
	}
	want := domain.SanctionCarryover{
		DNIHMAC:         "blind-index",
		AccountStatus:   domain.AccountStatusUnderReview,
		ReputationScore: -30,
		ReportCount:     2,
		CreatedAt:       d.DeletedAt,
		ExpiresAt:       d.CarryoverExpiresAt,
	}
	if *got != want {
		t.Errorf("sanción = %+v, se esperaba %+v", *got, want)
	}
}

// El vencimiento es el de la baja más el plazo, y las fechas se normalizan a UTC.
func TestCarryoverForNormalizaLasFechasAUTC(t *testing.T) {
	d := unaBajaValida(t)
	art := time.FixedZone("ART", -3*60*60)
	d.DeletedAt = d.DeletedAt.In(art)
	d.CarryoverExpiresAt = d.CarryoverExpiresAt.In(art)

	got := d.CarryoverFor(usuarioConSancion(t, domain.AccountStatusUnderReview, 0, 0))

	if got.CreatedAt.Location() != time.UTC || got.ExpiresAt.Location() != time.UTC {
		t.Errorf("las fechas de la sanción no están en UTC: %v y %v", got.CreatedAt.Location(), got.ExpiresAt.Location())
	}
}

func TestNewUserDeletedNormalizaLaFechaAUTC(t *testing.T) {
	art := time.FixedZone("ART", -3*60*60)
	en := time.Date(2026, 11, 2, 9, 0, 0, 0, art)
	id, usuario := uuid.New(), uuid.New()

	evt := domain.NewUserDeleted(id, usuario, en)

	if evt.EventID != id || evt.UserID != usuario {
		t.Errorf("evento = %+v", evt)
	}
	if !evt.DeletedAt.Equal(en) || evt.DeletedAt.Location() != time.UTC {
		t.Errorf("DeletedAt = %v, se esperaba el mismo instante en UTC", evt.DeletedAt)
	}
}

func TestNewUserStatusChangedOutboxEventLlevaElMotivoHeredado(t *testing.T) {
	usuario := uuid.New()

	evt, err := domain.NewUserStatusChangedOutboxEvent(usuario, domain.AccountStatusUnderReview, domain.UserStatusReasonInheritedOnSignup)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if evt.Type != "user.status.changed" || evt.ID == uuid.Nil {
		t.Errorf("evento = %+v", evt)
	}
	want := `{"user_id":"` + usuario.String() + `","account_status":"UNDER_REVIEW","reason":"INHERITED_ON_SIGNUP"}`
	if string(evt.Payload) != want {
		t.Errorf("payload = %s, se esperaba %s", evt.Payload, want)
	}
}
