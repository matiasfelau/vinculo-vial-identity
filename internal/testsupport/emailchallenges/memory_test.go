package emailchallenges_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/testsupport/emailchallenges"
)

var ahora = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

// Si la mutación falla, ni el desafío ni el outbox cambian: es la garantía de
// atomicidad que los servicios esperan del repositorio real.
func TestMutateQueFallaNoDejaNadaHecho(t *testing.T) {
	repo := emailchallenges.New()
	boom := errors.New("boom")

	err := repo.Mutate(t.Context(), domain.EmailChallengePurposePasswordReset, "s", true,
		func(c *domain.EmailChallenge) ([]domain.OutboxEvent, error) {
			c.CodeAttempts = 9
			return []domain.OutboxEvent{{ID: uuid.New()}}, boom
		})
	if !errors.Is(err, boom) {
		t.Fatalf("error = %v, se esperaba el de la mutación", err)
	}
	if repo.Get(domain.EmailChallengePurposePasswordReset, "s") != nil {
		t.Error("el desafío quedó creado pese al error")
	}
	if len(repo.Outbox()) != 0 {
		t.Error("quedaron eventos encolados pese al error")
	}
}

func TestMutateSinCrearDevuelveNoEncontrado(t *testing.T) {
	repo := emailchallenges.New()
	err := repo.Mutate(t.Context(), domain.EmailChallengePurposePasswordReset, "s", false,
		func(*domain.EmailChallenge) ([]domain.OutboxEvent, error) { return nil, nil })
	if !errors.Is(err, domain.ErrChallengeNotFound) {
		t.Fatalf("error = %v, se esperaba ErrChallengeNotFound", err)
	}
}

func TestErrSimulaUnaBaseCaidaEnTodasLasOperaciones(t *testing.T) {
	repo := emailchallenges.New()
	repo.Err = domain.ErrDatabaseUnavailable

	if err := repo.Mutate(t.Context(), domain.EmailChallengePurposePasswordReset, "s", true,
		func(*domain.EmailChallenge) ([]domain.OutboxEvent, error) { return nil, nil }); !errors.Is(err, domain.ErrDatabaseUnavailable) {
		t.Errorf("Mutate: %v", err)
	}
	if _, err := repo.FindByGrantHash(t.Context(), "g"); !errors.Is(err, domain.ErrDatabaseUnavailable) {
		t.Errorf("FindByGrantHash: %v", err)
	}
	if err := repo.AddGrantAttempt(t.Context(), "g"); !errors.Is(err, domain.ErrDatabaseUnavailable) {
		t.Errorf("AddGrantAttempt: %v", err)
	}
	if err := repo.CompletePasswordReset(t.Context(), domain.PasswordResetCompletion{}); !errors.Is(err, domain.ErrDatabaseUnavailable) {
		t.Errorf("CompletePasswordReset: %v", err)
	}
	if _, err := repo.DeleteExpired(t.Context(), ahora, 10); !errors.Is(err, domain.ErrDatabaseUnavailable) {
		t.Errorf("DeleteExpired: %v", err)
	}
}

func grantVigente(hash string) domain.EmailChallenge {
	expira := ahora.Add(time.Hour)
	return domain.EmailChallenge{
		ID: uuid.New(), Purpose: domain.EmailChallengePurposePasswordReset, SubjectHMAC: "s-" + hash,
		GrantHash: hash, GrantExpiresAt: &expira, CreatedAt: ahora,
	}
}

func TestCompletePasswordResetConsumeElGrantUnaSolaVez(t *testing.T) {
	repo := emailchallenges.New()
	repo.Put(grantVigente("g1"))
	c := domain.PasswordResetCompletion{GrantHash: "g1", MaxIdentityAttempts: 3, Now: ahora}

	if err := repo.CompletePasswordReset(t.Context(), c); err != nil {
		t.Fatalf("primera: %v", err)
	}
	if err := repo.CompletePasswordReset(t.Context(), c); !errors.Is(err, domain.ErrInvalidResetToken) {
		t.Fatalf("segunda: %v, se esperaba ErrInvalidResetToken", err)
	}
	if got := len(repo.Completions()); got != 1 {
		t.Errorf("completions = %d, se esperaba 1", got)
	}
	if got := len(repo.Outbox()); got != 2 {
		t.Errorf("outbox = %d eventos, se esperaban los 2 de la recuperación", got)
	}
}

func TestCompletePasswordResetRechazaVencidoSinIntentosYDesconocido(t *testing.T) {
	repo := emailchallenges.New()
	vencido := grantVigente("vencido")
	pasado := ahora.Add(-time.Minute)
	vencido.GrantExpiresAt = &pasado
	repo.Put(vencido)

	agotado := grantVigente("agotado")
	agotado.GrantAttempts = 3
	repo.Put(agotado)

	for _, hash := range []string{"vencido", "agotado", "desconocido"} {
		err := repo.CompletePasswordReset(t.Context(),
			domain.PasswordResetCompletion{GrantHash: hash, MaxIdentityAttempts: 3, Now: ahora})
		if !errors.Is(err, domain.ErrInvalidResetToken) {
			t.Errorf("%s: error = %v, se esperaba ErrInvalidResetToken", hash, err)
		}
	}
}

func TestCompleteErrYGrantAttemptErrSeInyectan(t *testing.T) {
	repo := emailchallenges.New()
	repo.CompleteErr = errors.New("falla")
	if err := repo.CompletePasswordReset(t.Context(), domain.PasswordResetCompletion{}); err == nil {
		t.Error("CompleteErr no se devolvió")
	}
	repo.GrantAttemptErr = errors.New("falla")
	if err := repo.AddGrantAttempt(t.Context(), "g"); err == nil {
		t.Error("GrantAttemptErr no se devolvió")
	}
}

func TestAddGrantAttemptSumaSoloSiNoSeConsumio(t *testing.T) {
	repo := emailchallenges.New()
	vivo := grantVigente("vivo")
	repo.Put(vivo)
	usado := grantVigente("usado")
	consumido := ahora
	usado.ConsumedAt = &consumido
	repo.Put(usado)

	for _, hash := range []string{"vivo", "usado"} {
		if err := repo.AddGrantAttempt(t.Context(), hash); err != nil {
			t.Fatalf("%s: %v", hash, err)
		}
	}
	if got := repo.Get(domain.EmailChallengePurposePasswordReset, vivo.SubjectHMAC).GrantAttempts; got != 1 {
		t.Errorf("intentos del grant vivo = %d, se esperaba 1", got)
	}
	if got := repo.Get(domain.EmailChallengePurposePasswordReset, usado.SubjectHMAC).GrantAttempts; got != 0 {
		t.Errorf("intentos del grant consumido = %d, se esperaba 0", got)
	}
}

func TestDeleteExpiredBorraSoloLoQueVencioPorCompleto(t *testing.T) {
	repo := emailchallenges.New()
	viejo := ahora.Add(-48 * time.Hour)

	vencido := domain.EmailChallenge{ID: uuid.New(), Purpose: domain.EmailChallengePurposeEmailVerification, SubjectHMAC: "vencido",
		CodeExpiresAt: &viejo, GrantExpiresAt: &viejo, SendsWindowStartedAt: &viejo}
	repo.Put(vencido)

	ventanaViva := ahora.Add(-time.Hour)
	enVentana := domain.EmailChallenge{ID: uuid.New(), Purpose: domain.EmailChallengePurposeEmailVerification, SubjectHMAC: "ventana",
		CodeExpiresAt: &viejo, GrantExpiresAt: &viejo, SendsWindowStartedAt: &ventanaViva}
	repo.Put(enVentana)

	n, err := repo.DeleteExpired(t.Context(), ahora, 10)
	if err != nil || n != 1 {
		t.Fatalf("DeleteExpired = (%d, %v), se esperaba (1, nil)", n, err)
	}
	if repo.Get(domain.EmailChallengePurposeEmailVerification, "vencido") != nil {
		t.Error("el vencido no se borró")
	}
	if repo.Get(domain.EmailChallengePurposeEmailVerification, "ventana") == nil {
		t.Error("el que sigue en su ventana de envíos se borró")
	}
}

func TestDeleteExpiredRespetaElLimite(t *testing.T) {
	repo := emailchallenges.New()
	viejo := ahora.Add(-48 * time.Hour)
	for _, s := range []string{"a", "b", "c"} {
		repo.Put(domain.EmailChallenge{ID: uuid.New(), Purpose: domain.EmailChallengePurposeEmailVerification, SubjectHMAC: s,
			CodeExpiresAt: &viejo, GrantExpiresAt: &viejo, SendsWindowStartedAt: &viejo})
	}
	if n, _ := repo.DeleteExpired(t.Context(), ahora, 2); n != 2 {
		t.Errorf("borró %d, se esperaban 2", n)
	}
}

func TestMutationsCuentaLasMutacionesExitosas(t *testing.T) {
	repo := emailchallenges.New()
	for range 3 {
		if err := repo.Mutate(t.Context(), domain.EmailChallengePurposePasswordReset, "s", true,
			func(*domain.EmailChallenge) ([]domain.OutboxEvent, error) { return nil, nil }); err != nil {
			t.Fatal(err)
		}
	}
	if got := repo.Mutations(); got != 3 {
		t.Errorf("Mutations = %d, se esperaba 3", got)
	}
}

func TestFindByGrantHashEncuentraPorHashYDevuelveUnaCopia(t *testing.T) {
	repo := emailchallenges.New()
	repo.Put(grantVigente("g1"))

	got, err := repo.FindByGrantHash(t.Context(), "g1")
	if err != nil || got.GrantHash != "g1" {
		t.Fatalf("FindByGrantHash = (%+v, %v)", got, err)
	}
	got.GrantAttempts = 99 // modificar la copia no puede cambiar lo guardado
	if again, _ := repo.FindByGrantHash(t.Context(), "g1"); again.GrantAttempts != 0 {
		t.Error("el doble devolvió el desafío guardado, no una copia")
	}

	if _, err := repo.FindByGrantHash(t.Context(), "otro"); !errors.Is(err, domain.ErrChallengeNotFound) {
		t.Errorf("hash desconocido: %v, se esperaba ErrChallengeNotFound", err)
	}
}
