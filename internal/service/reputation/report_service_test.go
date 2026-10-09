package reputation_test

import (
	"bytes"
	"encoding/json"
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
	colaDeReportes = "identity.alert-reported.q"
	umbralDePrueba = 3
)

var ahoraDePrueba = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func nuevoServicioDeReportes(t *testing.T, repo *repoMock, logger *slog.Logger) *reputation.ReportService {
	t.Helper()

	svc, err := reputation.NewReportService(reputation.ReportDeps{
		Repo:            repo,
		Consumer:        colaDeReportes,
		ReviewThreshold: umbralDePrueba,
		Logger:          logger,
		Now:             func() time.Time { return ahoraDePrueba },
	})
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	return svc
}

func reporte() domain.AlertReport {
	return domain.AlertReport{EventID: uuid.New(), UserID: uuid.New(), Reason: domain.ReportReasonFalseAlert}
}

// El umbral llega al repositorio desde la configuración, no de un valor fijo.
func TestApplyDelegaEnElRepositorioConElUmbralConfigurado(t *testing.T) {
	repo := &repoMock{}
	svc := nuevoServicioDeReportes(t, repo, nil)

	r := reporte()
	if err := svc.Apply(t.Context(), r); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if len(repo.umbrales) != 1 || repo.umbrales[0] != umbralDePrueba {
		t.Errorf("umbral = %v, se esperaba [%d]", repo.umbrales, umbralDePrueba)
	}
	if repo.usuarios[0] != r.UserID {
		t.Errorf("se contó contra %v, se esperaba el emisor reportado %v", repo.usuarios[0], r.UserID)
	}
}

func TestElReporteSeRegistraConSuIdYLaColaDeTrabajo(t *testing.T) {
	repo := &repoMock{}
	svc := nuevoServicioDeReportes(t, repo, nil)

	r := reporte()
	if err := svc.Apply(t.Context(), r); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	e := repo.eventos[0]
	if e.EventID != r.EventID || e.Consumer != colaDeReportes || e.EventType != "alert.reported" {
		t.Errorf("evento registrado = %+v", e)
	}
	if !e.ProcessedAt.Equal(ahoraDePrueba) {
		t.Errorf("processed_at = %v, se esperaba el reloj inyectado", e.ProcessedAt)
	}
}

// El evento que se encola en la transición es exactamente el del contrato:
// user.status.changed con el usuario, UNDER_REVIEW y REPORTS_THRESHOLD, sin
// nada más ni ningún dato de quién reportó.
func TestElEventoDeEstadoEsElDelContrato(t *testing.T) {
	repo := &repoMock{}
	svc := nuevoServicioDeReportes(t, repo, nil)

	r := reporte()
	if err := svc.Apply(t.Context(), r); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	evt := repo.statusEvent[0]
	if evt.Type != "user.status.changed" {
		t.Errorf("type = %q, se esperaba user.status.changed", evt.Type)
	}
	if evt.ID == uuid.Nil {
		t.Errorf("el evento de outbox necesita un id propio")
	}
	if !evt.CreatedAt.Equal(ahoraDePrueba) {
		t.Errorf("created_at = %v, se esperaba el reloj inyectado", evt.CreatedAt)
	}

	var payload map[string]any
	if err := json.Unmarshal(evt.Payload, &payload); err != nil {
		t.Fatalf("payload ilegible: %v", err)
	}
	want := map[string]any{
		"user_id":        r.UserID.String(),
		"account_status": "UNDER_REVIEW",
		"reason":         "REPORTS_THRESHOLD",
	}
	if len(payload) != len(want) {
		t.Errorf("payload = %v, se esperaban solo %v", payload, want)
	}
	for k, v := range want {
		if payload[k] != v {
			t.Errorf("payload[%s] = %v, se esperaba %v", k, payload[k], v)
		}
	}
}

func TestLosResultadosDelRepositorioNoSonErrores(t *testing.T) {
	casos := map[domain.ReportOutcome]string{
		domain.ReportCounted:      "INFO",
		domain.ReportEscalated:    "INFO",
		domain.ReportDuplicate:    "INFO",
		domain.ReportUserNotFound: "WARN",
	}
	for resultado, nivel := range casos {
		repo := &repoMock{resultado: resultado}
		var registro bytes.Buffer
		svc := nuevoServicioDeReportes(t, repo, slog.New(slog.NewTextHandler(&registro, nil)))

		r := reporte()
		if err := svc.Apply(t.Context(), r); err != nil {
			t.Errorf("resultado %v: error inesperado: %v", resultado, err)
		}
		out := registro.String()
		if !strings.Contains(out, nivel) || !strings.Contains(out, r.EventID.String()) {
			t.Errorf("resultado %v: se esperaba un %s con el eventId: %s", resultado, nivel, out)
		}
	}
}

// Nunca se loguea el motivo del reporte ni nada del denunciante: Identity no
// los guarda.
func TestElLogNoLlevaElMotivoDelReporte(t *testing.T) {
	repo := &repoMock{}
	var registro bytes.Buffer
	svc := nuevoServicioDeReportes(t, repo, slog.New(slog.NewTextHandler(&registro, nil)))

	if err := svc.Apply(t.Context(), reporte()); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if strings.Contains(registro.String(), "FALSE_ALERT") {
		t.Errorf("el log no debería llevar el motivo: %s", registro.String())
	}
}

// Un error de base se propaga: el consumidor lo trata como transitorio.
func TestUnErrorDeBaseAlContarSePropaga(t *testing.T) {
	repo := &repoMock{err: domain.ErrDatabaseUnavailable}
	svc := nuevoServicioDeReportes(t, repo, nil)

	if err := svc.Apply(t.Context(), reporte()); !errors.Is(err, domain.ErrDatabaseUnavailable) {
		t.Errorf("err = %v, se esperaba ErrDatabaseUnavailable", err)
	}
}

func TestNewReportServiceValidaSusDependencias(t *testing.T) {
	casos := map[string]reputation.ReportDeps{
		"sin repositorio": {Consumer: colaDeReportes, ReviewThreshold: 1},
		"sin consumidor":  {Repo: &repoMock{}, ReviewThreshold: 1},
		// Con umbral 0 todo usuario quedaría en revisión sin un solo reporte.
		"umbral cero":     {Repo: &repoMock{}, Consumer: colaDeReportes, ReviewThreshold: 0},
		"umbral negativo": {Repo: &repoMock{}, Consumer: colaDeReportes, ReviewThreshold: -1},
	}
	for nombre, deps := range casos {
		t.Run(nombre, func(t *testing.T) {
			if _, err := reputation.NewReportService(deps); err == nil {
				t.Errorf("se esperaba un error")
			}
		})
	}
}
