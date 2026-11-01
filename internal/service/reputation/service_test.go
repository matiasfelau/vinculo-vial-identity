package reputation_test

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/reputation"
)

const (
	colaDePrueba   = "identity.alert-rejected.q"
	penalizacionDe = 10
)

func nuevoServicio(t *testing.T, repo *repoMock, logger *slog.Logger) *reputation.RejectionService {
	t.Helper()

	svc, err := reputation.NewRejectionService(reputation.RejectionDeps{
		Repo:         repo,
		Consumer:     colaDePrueba,
		FraudPenalty: penalizacionDe,
		Logger:       logger,
		Now:          func() time.Time { return time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	return svc
}

func rechazo(codes ...string) domain.AlertRejection {
	return domain.AlertRejection{EventID: uuid.New(), UserID: uuid.New(), ReasonCodes: codes}
}

func TestUnCodigoDeFraudeRestaLaPenalizacionConfigurada(t *testing.T) {
	for _, code := range []string{"NO_VEHICLE", "BURST_MISMATCH", "PLATE_MISMATCH"} {
		t.Run(code, func(t *testing.T) {
			repo := &repoMock{}
			svc := nuevoServicio(t, repo, nil)

			r := rechazo(code)
			if err := svc.Apply(t.Context(), r); err != nil {
				t.Fatalf("error inesperado: %v", err)
			}

			if len(repo.penalties) != 1 || repo.penalties[0] != penalizacionDe {
				t.Errorf("penalizaciones = %v, se esperaba [%d]", repo.penalties, penalizacionDe)
			}
			if repo.usuarios[0] != r.UserID {
				t.Errorf("se penalizó a %v, se esperaba al emisor %v", repo.usuarios[0], r.UserID)
			}
		})
	}
}

func TestLaPenalizacionSalaDeLaConfiguracionNoDeUnValorFijo(t *testing.T) {
	repo := &repoMock{}
	svc, err := reputation.NewRejectionService(reputation.RejectionDeps{Repo: repo, Consumer: colaDePrueba, FraudPenalty: 37})
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if err := svc.Apply(t.Context(), rechazo("NO_VEHICLE")); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if repo.penalties[0] != 37 {
		t.Errorf("penalización = %d, se esperaba 37", repo.penalties[0])
	}
}

// EVIDENCE_UNREADABLE es RED pero no es culpa del emisor: el evento se
// registra como procesado y la reputación no se toca.
func TestUnRechazoSinFraudeNoPenalizaPeroSeRegistra(t *testing.T) {
	repo := &repoMock{}
	svc := nuevoServicio(t, repo, nil)

	if err := svc.Apply(t.Context(), rechazo("EVIDENCE_UNREADABLE")); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if len(repo.penalties) != 1 || repo.penalties[0] != 0 {
		t.Errorf("penalizaciones = %v, se esperaba [0]", repo.penalties)
	}
}

func TestFraudeEntreOtrosCodigosPenaliza(t *testing.T) {
	repo := &repoMock{}
	svc := nuevoServicio(t, repo, nil)

	if err := svc.Apply(t.Context(), rechazo("EVIDENCE_UNREADABLE", "PLATE_MISMATCH")); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if repo.penalties[0] != penalizacionDe {
		t.Errorf("penalización = %d, se esperaba %d", repo.penalties[0], penalizacionDe)
	}
}

// La clave de deduplicación es (eventId, cola): se registra con la cola de
// trabajo, no con un nombre cualquiera.
func TestElEventoSeRegistraConSuIdYLaColaDeTrabajo(t *testing.T) {
	repo := &repoMock{}
	svc := nuevoServicio(t, repo, nil)

	r := rechazo("NO_VEHICLE")
	if err := svc.Apply(t.Context(), r); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	e := repo.eventos[0]
	if e.EventID != r.EventID || e.Consumer != colaDePrueba || e.EventType != "alert.rejected" {
		t.Errorf("evento registrado = %+v", e)
	}
	if !e.ProcessedAt.Equal(time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("processed_at = %v, se esperaba el reloj inyectado", e.ProcessedAt)
	}
}

// Una reentrega del mismo eventId no vuelve a restar: el repositorio la
// reconoce como duplicada y el servicio la da por procesada.
func TestElMismoEventIdDosVecesRestaUnaSolaVez(t *testing.T) {
	repo := &repoMock{}
	svc := nuevoServicio(t, repo, nil)

	r := rechazo("NO_VEHICLE")
	for range 2 {
		if err := svc.Apply(t.Context(), r); err != nil {
			t.Fatalf("error inesperado: %v", err)
		}
	}

	if repo.llamadas != 2 {
		t.Errorf("llamadas al repositorio = %d, se esperaban 2", repo.llamadas)
	}
	if len(repo.penalties) != 1 {
		t.Errorf("penalizaciones aplicadas = %d, se esperaba 1", len(repo.penalties))
	}
}

// Que el usuario no exista no es un error: se loguea y el evento se da por
// procesado, para que el consumidor haga ack.
func TestUnUsuarioInexistenteSeLogueaYNoEsError(t *testing.T) {
	repo := &repoMock{notFound: true}
	var registro bytes.Buffer
	svc := nuevoServicio(t, repo, slog.New(slog.NewTextHandler(&registro, nil)))

	r := rechazo("NO_VEHICLE")
	if err := svc.Apply(t.Context(), r); err != nil {
		t.Fatalf("un usuario inexistente no debe ser un error: %v", err)
	}

	out := registro.String()
	if !strings.Contains(out, "WARN") || !strings.Contains(out, r.EventID.String()) {
		t.Errorf("se esperaba un WARN con el eventId: %s", out)
	}
}

// Un error de base se propaga: el consumidor lo trata como transitorio y
// reintenta.
func TestUnErrorDeBaseSePropaga(t *testing.T) {
	repo := &repoMock{err: domain.ErrDatabaseUnavailable}
	svc := nuevoServicio(t, repo, nil)

	err := svc.Apply(t.Context(), rechazo("NO_VEHICLE"))
	if !errors.Is(err, domain.ErrDatabaseUnavailable) {
		t.Errorf("err = %v, se esperaba ErrDatabaseUnavailable", err)
	}
}

func TestNewRejectionServiceValidaSusDependencias(t *testing.T) {
	casos := map[string]reputation.RejectionDeps{
		"sin repositorio":       {Consumer: colaDePrueba, FraudPenalty: 10},
		"sin consumidor":        {Repo: &repoMock{}, FraudPenalty: 10},
		"penalización negativa": {Repo: &repoMock{}, Consumer: colaDePrueba, FraudPenalty: -1},
	}
	for nombre, deps := range casos {
		t.Run(nombre, func(t *testing.T) {
			if _, err := reputation.NewRejectionService(deps); err == nil {
				t.Errorf("se esperaba un error")
			}
		})
	}
}
