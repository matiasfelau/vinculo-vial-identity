package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// ReviewDecisionUnblock es la única decisión que registra review_decisions
// (US-17): un operador levantó la revisión de una cuenta.
const ReviewDecisionUnblock = "UNBLOCK"

// Largos admitidos del motivo y del operador de una decisión, en caracteres. Son
// los del contrato de US-17 y los de las columnas de review_decisions.
const (
	ReviewReasonMinLength   = 10
	ReviewReasonMaxLength   = 500
	ReviewOperatorMaxLength = 100
)

// ReviewCase es un caso de revisión: una cuenta en UNDER_REVIEW, con lo que un
// operador necesita para decidir. No lleva email ni DNI.
type ReviewCase struct {
	UserID          uuid.UUID
	AccountStatus   AccountStatus
	ReportCount     int
	ReputationScore int
	// UnderReviewSince es cuándo pasó a revisión. Nil en las cuentas que ya
	// estaban en revisión antes de US-17 y en las que nacieron así por herencia de
	// sanción (US-11): ahí el listado ordena por la última modificación de la fila.
	UnderReviewSince *time.Time
	// LastReportedAt es cuándo se contó el último reporte. Nil si ninguno se
	// contó desde US-17.
	LastReportedAt *time.Time
}

// ReviewCasePage es una página del listado de casos. NextCursor es opaco y está
// vacío en la última página.
type ReviewCasePage struct {
	Items      []ReviewCase
	NextCursor string
}

// ReviewDecision es una decisión de un operador sobre un caso.
type ReviewDecision struct {
	ID       uuid.UUID
	UserID   uuid.UUID
	Decision string
	// Reason es el texto libre del operador. Nunca se loguea.
	Reason    string
	Operator  string
	DecidedAt time.Time
}

// ReviewRepository es la persistencia de los casos de revisión de US-17.
type ReviewRepository interface {
	// ListCases devuelve hasta limit cuentas en el estado status, de la que lleva
	// más tiempo en revisión a la más nueva, a partir de cursor (vacío para la
	// primera página). Un cursor que no sea uno devuelto por este método da
	// ErrInvalidCursor.
	ListCases(ctx context.Context, status AccountStatus, limit int, cursor string) (ReviewCasePage, error)

	// Unblock levanta la revisión, en una única transacción: pasa la cuenta a
	// ACTIVE con report_count = 0 y under_review_since = null, inserta decision en
	// review_decisions y encola statusChanged en el outbox. Devuelve
	// ErrUserNotFound si la cuenta no existe y ErrNotUnderReview si no estaba en
	// UNDER_REVIEW; en los dos casos no cambia nada. Dos desbloqueos concurrentes
	// de la misma cuenta: uno gana y el otro recibe ErrNotUnderReview.
	Unblock(ctx context.Context, decision ReviewDecision, statusChanged OutboxEvent) error

	// ListDecisions devuelve las decisiones sobre la cuenta, de la más nueva a la
	// más vieja. Una cuenta sin decisiones, o inexistente, da una lista vacía.
	ListDecisions(ctx context.Context, userID uuid.UUID) ([]ReviewDecision, error)
}
