package review_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/review"
)

// repoMock implementa domain.ReviewRepository y registra lo que recibe.
type repoMock struct {
	err error

	page      domain.ReviewCasePage
	decisions []domain.ReviewDecision

	listStatus domain.AccountStatus
	listLimit  int
	listCursor string

	unblockCalls  int
	decision      domain.ReviewDecision
	statusChanged domain.OutboxEvent

	decisionsOf uuid.UUID
}

func (m *repoMock) ListCases(_ context.Context, status domain.AccountStatus, limit int, cursor string) (domain.ReviewCasePage, error) {
	m.listStatus, m.listLimit, m.listCursor = status, limit, cursor
	return m.page, m.err
}

func (m *repoMock) Unblock(_ context.Context, decision domain.ReviewDecision, statusChanged domain.OutboxEvent) error {
	m.unblockCalls++
	m.decision, m.statusChanged = decision, statusChanged
	return m.err
}

func (m *repoMock) ListDecisions(_ context.Context, userID uuid.UUID) ([]domain.ReviewDecision, error) {
	m.decisionsOf = userID
	return m.decisions, m.err
}

var ahora = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

func nuevoServicio(t *testing.T, repo domain.ReviewRepository, logs *bytes.Buffer) *review.Service {
	t.Helper()

	var logger *slog.Logger
	if logs != nil {
		logger = slog.New(slog.NewJSONHandler(logs, nil))
	}
	svc, err := review.New(review.Deps{Repo: repo, Logger: logger, Now: func() time.Time { return ahora }})
	if err != nil {
		t.Fatalf("no se pudo armar el servicio: %v", err)
	}
	return svc
}

func TestNewExigeElRepositorio(t *testing.T) {
	if _, err := review.New(review.Deps{}); err == nil {
		t.Fatal("se esperaba un error al faltar el repositorio")
	}
}

// El desbloqueo registra la decisión con el motivo y el operador recortados, y
// encola user.status.changed con ACTIVE y MANUAL_UNBLOCK, con la misma hora.
func TestUnblockArmaLaDecisionYElEvento(t *testing.T) {
	repo := &repoMock{}
	svc := nuevoServicio(t, repo, nil)
	userID := uuid.New()

	id, err := svc.Unblock(t.Context(), userID, "  Se revisó la evidencia y no hay fraude.  ", "  ana.perez  ")
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	d := repo.decision
	if id == uuid.Nil || d.ID != id {
		t.Errorf("el id devuelto (%s) no es el de la decisión (%s)", id, d.ID)
	}
	if d.UserID != userID || d.Decision != "UNBLOCK" || !d.DecidedAt.Equal(ahora) {
		t.Errorf("decisión = %+v", d)
	}
	if d.Reason != "Se revisó la evidencia y no hay fraude." || d.Operator != "ana.perez" {
		t.Errorf("motivo u operador sin recortar: %q, %q", d.Reason, d.Operator)
	}

	evt := repo.statusChanged
	if evt.Type != domain.EventTypeUserStatusChanged || !evt.CreatedAt.Equal(ahora) {
		t.Errorf("evento = %+v", evt)
	}
	var payload map[string]string
	if err := json.Unmarshal(evt.Payload, &payload); err != nil {
		t.Fatalf("payload ilegible: %v", err)
	}
	if payload["user_id"] != userID.String() || payload["account_status"] != "ACTIVE" || payload["reason"] != "MANUAL_UNBLOCK" {
		t.Errorf("payload = %v", payload)
	}
	if strings.Contains(string(evt.Payload), "ana.perez") || strings.Contains(string(evt.Payload), "evidencia") {
		t.Errorf("el payload del evento no debe llevar el motivo ni el operador: %s", evt.Payload)
	}
}

func TestUnblockValidaElMotivoYElOperador(t *testing.T) {
	cases := map[string]struct{ reason, operator string }{
		"motivo de 9 caracteres":            {"123456789", "ana"},
		"motivo de espacios":                {strings.Repeat(" ", 20), "ana"},
		"motivo vacío":                      {"", "ana"},
		"motivo de 501 caracteres":          {strings.Repeat("a", 501), "ana"},
		"motivo de 9 caracteres multibyte":  {strings.Repeat("ñ", 9), "ana"},
		"operador vacío":                    {"motivo suficiente", ""},
		"operador de espacios":              {"motivo suficiente", "   "},
		"operador de 101 caracteres":        {"motivo suficiente", strings.Repeat("o", 101)},
		"operador de 101 caracteres multib": {"motivo suficiente", strings.Repeat("ó", 101)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			repo := &repoMock{}
			svc := nuevoServicio(t, repo, nil)

			_, err := svc.Unblock(t.Context(), uuid.New(), c.reason, c.operator)
			if !errors.Is(err, domain.ErrInvalidReviewDecision) {
				t.Fatalf("error = %v, se esperaba ErrInvalidReviewDecision", err)
			}
			if repo.unblockCalls != 0 {
				t.Error("no debería llegar al repositorio con una decisión inválida")
			}
		})
	}
}

// Los largos se cuentan en caracteres: 10 y 500 "ñ" (2 bytes cada una) valen, y
// 100 operadores multibyte también.
func TestUnblockAceptaLosLimitesDeLargoEnCaracteres(t *testing.T) {
	cases := map[string]struct{ reason, operator string }{
		"motivo de 10":              {strings.Repeat("ñ", 10), "a"},
		"motivo de 500":             {strings.Repeat("ñ", 500), "a"},
		"operador de 100 multibyte": {"motivo suficiente", strings.Repeat("ó", 100)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			repo := &repoMock{}
			svc := nuevoServicio(t, repo, nil)

			if _, err := svc.Unblock(t.Context(), uuid.New(), c.reason, c.operator); err != nil {
				t.Fatalf("error inesperado: %v", err)
			}
			if repo.unblockCalls != 1 {
				t.Errorf("llamadas al repositorio = %d, se esperaba 1", repo.unblockCalls)
			}
		})
	}
}

// Los errores del repositorio salen sin tocar: la capa HTTP los traduce.
func TestUnblockDevuelveLosErroresDelRepositorio(t *testing.T) {
	for _, want := range []error{domain.ErrUserNotFound, domain.ErrNotUnderReview, domain.ErrDatabaseUnavailable} {
		repo := &repoMock{err: want}
		svc := nuevoServicio(t, repo, nil)

		id, err := svc.Unblock(t.Context(), uuid.New(), "motivo suficiente", "ana")
		if !errors.Is(err, want) {
			t.Errorf("error = %v, se esperaba %v", err, want)
		}
		if id != uuid.Nil {
			t.Errorf("con error no debería devolver un id de decisión, devolvió %s", id)
		}
	}
}

// El log registra el id de la decisión y el usuario, y nunca el motivo ni el
// operador.
func TestUnblockLogueaElIdDeLaDecisionYNoElMotivo(t *testing.T) {
	logs := &bytes.Buffer{}
	repo := &repoMock{}
	svc := nuevoServicio(t, repo, logs)
	userID := uuid.New()

	id, err := svc.Unblock(t.Context(), userID, "Motivo secreto que no debe loguearse", "operadora.reservada")
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	out := logs.String()
	if !strings.Contains(out, id.String()) || !strings.Contains(out, userID.String()) {
		t.Errorf("el log no tiene el id de la decisión ni el del usuario: %s", out)
	}
	for _, prohibido := range []string{"Motivo secreto", "operadora.reservada"} {
		if strings.Contains(out, prohibido) {
			t.Errorf("el log filtra %q: %s", prohibido, out)
		}
	}
}

// Una decisión inválida ni siquiera deja rastro del motivo en el log.
func TestUnblockInvalidoNoLogueaElMotivo(t *testing.T) {
	logs := &bytes.Buffer{}
	svc := nuevoServicio(t, &repoMock{}, logs)

	_, _ = svc.Unblock(t.Context(), uuid.New(), "corto", "operadora.reservada")

	if strings.Contains(logs.String(), "operadora.reservada") || strings.Contains(logs.String(), "corto") {
		t.Errorf("el log filtra el contenido de la decisión: %s", logs.String())
	}
}

func TestListCasesPasaLosParametrosAlRepositorio(t *testing.T) {
	want := domain.ReviewCasePage{
		Items:      []domain.ReviewCase{{UserID: uuid.New(), AccountStatus: domain.AccountStatusUnderReview, ReportCount: 2}},
		NextCursor: "abc",
	}
	repo := &repoMock{page: want}
	svc := nuevoServicio(t, repo, nil)

	got, err := svc.ListCases(t.Context(), domain.AccountStatusUnderReview, 25, "cursor-previo")
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if got.NextCursor != "abc" || len(got.Items) != 1 || got.Items[0].UserID != want.Items[0].UserID {
		t.Errorf("página = %+v", got)
	}
	if repo.listStatus != domain.AccountStatusUnderReview || repo.listLimit != 25 || repo.listCursor != "cursor-previo" {
		t.Errorf("parámetros = %v, %d, %q", repo.listStatus, repo.listLimit, repo.listCursor)
	}
}

func TestListCasesDevuelveElErrorDelCursor(t *testing.T) {
	svc := nuevoServicio(t, &repoMock{err: domain.ErrInvalidCursor}, nil)

	if _, err := svc.ListCases(t.Context(), domain.AccountStatusUnderReview, 10, "basura"); !errors.Is(err, domain.ErrInvalidCursor) {
		t.Errorf("error = %v, se esperaba ErrInvalidCursor", err)
	}
}

func TestDecisionsLeeElHistorialDelUsuario(t *testing.T) {
	userID := uuid.New()
	repo := &repoMock{decisions: []domain.ReviewDecision{{ID: uuid.New(), UserID: userID, Decision: "UNBLOCK"}}}
	svc := nuevoServicio(t, repo, nil)

	got, err := svc.Decisions(t.Context(), userID)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if len(got) != 1 || repo.decisionsOf != userID {
		t.Errorf("decisiones = %+v para %s", got, repo.decisionsOf)
	}
}
