package reputation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// EventTypeAlertReported es el tipo del evento que Alert publica cuando el
// destinatario de una alerta reporta a su emisor.
const EventTypeAlertReported = "alert.reported"

// ReportDeps son las dependencias de ReportService.
type ReportDeps struct {
	Repo domain.ReputationRepository
	// Consumer identifica a quien procesa el evento en la clave de
	// deduplicación: la cola de trabajo.
	Consumer string
	// ReviewThreshold es la cantidad de reportes que pone al usuario en
	// revisión (REPORT_REVIEW_THRESHOLD). Al menos 1.
	ReviewThreshold int
	Logger          *slog.Logger
	// Now es el reloj; si es nil usa time.Now.
	Now func() time.Time
}

// ReportService es el caso de uso de alert.reported: contar el reporte contra
// el emisor y, al llegar al umbral, ponerlo en revisión.
type ReportService struct {
	deps ReportDeps
}

// NewReportService valida las dependencias y construye el servicio.
func NewReportService(d ReportDeps) (*ReportService, error) {
	switch {
	case d.Repo == nil:
		return nil, errors.New("reputation: falta el repositorio de reputación")
	case d.Consumer == "":
		return nil, errors.New("reputation: falta el nombre del consumidor")
	case d.ReviewThreshold < 1:
		return nil, errors.New("reputation: el umbral de revisión debe ser al menos 1")
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &ReportService{deps: d}, nil
}

// statusChangedPayload es el payload de user.status.changed, en snake_case
// como fija el contrato. El worker del outbox lo lee con la misma forma.
type statusChangedPayload struct {
	UserID        string `json:"user_id"`
	AccountStatus string `json:"account_status"`
	Reason        string `json:"reason"`
}

// Apply procesa un reporte: suma uno al conteo del emisor y, si llega a
// REPORT_REVIEW_THRESHOLD estando ACTIVE, lo pasa a UNDER_REVIEW y encola
// user.status.changed en el outbox, todo en la misma transacción. Un usuario
// que ya está en revisión sigue contando reportes pero no vuelve a publicar.
//
// Es idempotente: la entrega es at-least-once y el repositorio descarta el
// evento si su eventId ya se procesó para este consumidor, sin volver a
// contar. Un usuario inexistente no es un error: se loguea y se da por
// procesado. Cualquier error de infraestructura se devuelve para que el
// consumidor reintente.
//
// No se guarda quién reportó ni qué alerta fue: solo el conteo.
func (s *ReportService) Apply(ctx context.Context, report domain.AlertReport) error {
	now := s.deps.Now().UTC()

	// El evento se arma antes de la transacción pero solo se persiste si hay
	// transición: su contenido no depende de lo que lea la base.
	statusChanged, err := domain.NewOutboxEvent(domain.EventTypeUserStatusChanged, statusChangedPayload{
		UserID:        report.UserID.String(),
		AccountStatus: string(domain.AccountStatusUnderReview),
		Reason:        string(domain.UserStatusReasonReportsThreshold),
	})
	if err != nil {
		return fmt.Errorf("reputation: no se pudo armar user.status.changed: %w", err)
	}
	statusChanged.CreatedAt = now

	outcome, err := s.deps.Repo.ApplyReport(ctx, domain.ProcessedEvent{
		EventID:     report.EventID,
		Consumer:    s.deps.Consumer,
		EventType:   EventTypeAlertReported,
		ProcessedAt: now,
	}, report.UserID, s.deps.ReviewThreshold, statusChanged)
	if err != nil {
		return fmt.Errorf("reputation: no se pudo aplicar el reporte del evento %s: %w", report.EventID, err)
	}

	switch outcome {
	case domain.ReportDuplicate:
		s.deps.Logger.InfoContext(ctx, "reporte ya procesado: se descarta el duplicado",
			slog.String("event_id", report.EventID.String()))
	case domain.ReportUserNotFound:
		s.deps.Logger.WarnContext(ctx, "reporte de un usuario inexistente: no hay a quién contárselo",
			slog.String("event_id", report.EventID.String()),
			slog.String("user_id", report.UserID.String()))
	case domain.ReportEscalated:
		s.deps.Logger.InfoContext(ctx, "usuario en revisión por reportes",
			slog.String("event_id", report.EventID.String()),
			slog.String("user_id", report.UserID.String()),
			slog.Int("threshold", s.deps.ReviewThreshold))
	case domain.ReportCounted:
		s.deps.Logger.InfoContext(ctx, "reporte contado",
			slog.String("event_id", report.EventID.String()),
			slog.String("user_id", report.UserID.String()))
	}
	return nil
}
