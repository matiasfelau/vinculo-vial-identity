// Package review implementa los casos de uso de administración de usuarios
// reportados (US-17): consultar los casos en revisión, desbloquear con motivo y
// operador, y leer el historial de decisiones.
package review

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// Deps son las dependencias del Service.
type Deps struct {
	Repo   domain.ReviewRepository
	Logger *slog.Logger
	// Now es el reloj; si es nil usa time.Now.
	Now func() time.Time
}

// Service son los casos de uso de US-17.
type Service struct {
	deps Deps
}

// New valida las dependencias y construye el servicio.
func New(d Deps) (*Service, error) {
	if d.Repo == nil {
		return nil, errors.New("review: falta el repositorio de revisión")
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Service{deps: d}, nil
}

// ListCases devuelve una página de las cuentas en el estado status, de la más
// antigua a la más nueva. limit y cursor los valida el llamador; un cursor que no
// sea uno devuelto antes da domain.ErrInvalidCursor.
func (s *Service) ListCases(ctx context.Context, status domain.AccountStatus, limit int, cursor string) (domain.ReviewCasePage, error) {
	return s.deps.Repo.ListCases(ctx, status, limit, cursor)
}

// Unblock levanta la revisión de la cuenta y devuelve el id de la decisión.
//
// El motivo y el operador se validan acá, no solo en el borde HTTP: el historial
// es un registro de auditoría y ningún llamador debería poder escribir en él una
// fila que el contrato no admite. Los largos se cuentan en caracteres y no en
// bytes, y los espacios de los extremos no cuentan: un motivo de diez espacios no
// es un motivo.
//
// El user.status.changed va al outbox en la misma transacción que el cambio, con
// ACTIVE y MANUAL_UNBLOCK. Alert ignora el motivo y levanta la restricción por el
// estado.
//
// El log registra el id de la decisión y el usuario, nunca el motivo ni el
// operador.
func (s *Service) Unblock(ctx context.Context, userID uuid.UUID, reason, operator string) (uuid.UUID, error) {
	reason = strings.TrimSpace(reason)
	operator = strings.TrimSpace(operator)

	if n := utf8.RuneCountInString(reason); n < domain.ReviewReasonMinLength || n > domain.ReviewReasonMaxLength {
		return uuid.Nil, fmt.Errorf("%w: el motivo debe tener entre %d y %d caracteres",
			domain.ErrInvalidReviewDecision, domain.ReviewReasonMinLength, domain.ReviewReasonMaxLength)
	}
	if n := utf8.RuneCountInString(operator); n < 1 || n > domain.ReviewOperatorMaxLength {
		return uuid.Nil, fmt.Errorf("%w: el operador debe tener entre 1 y %d caracteres",
			domain.ErrInvalidReviewDecision, domain.ReviewOperatorMaxLength)
	}

	now := s.deps.Now().UTC()

	decision := domain.ReviewDecision{
		ID:        uuid.New(),
		UserID:    userID,
		Decision:  domain.ReviewDecisionUnblock,
		Reason:    reason,
		Operator:  operator,
		DecidedAt: now,
	}

	statusChanged, err := domain.NewUserStatusChangedOutboxEvent(userID, domain.AccountStatusActive, domain.UserStatusReasonManualUnblock)
	if err != nil {
		return uuid.Nil, fmt.Errorf("review: no se pudo armar user.status.changed: %w", err)
	}
	statusChanged.CreatedAt = now

	if err := s.deps.Repo.Unblock(ctx, decision, statusChanged); err != nil {
		return uuid.Nil, err
	}

	s.deps.Logger.InfoContext(ctx, "cuenta desbloqueada por un operador",
		slog.String("decision_id", decision.ID.String()),
		slog.String("user_id", userID.String()))
	return decision.ID, nil
}

// Decisions devuelve el historial de decisiones sobre la cuenta, de la más nueva a
// la más vieja.
func (s *Service) Decisions(ctx context.Context, userID uuid.UUID) ([]domain.ReviewDecision, error) {
	return s.deps.Repo.ListDecisions(ctx, userID)
}
