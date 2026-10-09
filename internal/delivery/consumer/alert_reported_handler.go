package consumer

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// ReportApplier es el caso de uso que cuenta un reporte contra un emisor.
type ReportApplier interface {
	Apply(ctx context.Context, report domain.AlertReport) error
}

// AlertReportedHandler traduce un alert.reported al caso de uso de revisión.
// Valida el sobre y el payload antes de tocar nada: un mensaje inválido es un
// fallo permanente y va directo a la DLQ.
type AlertReportedHandler struct {
	applier ReportApplier
}

var _ Handler = (*AlertReportedHandler)(nil)

// NewAlertReportedHandler construye el handler.
func NewAlertReportedHandler(applier ReportApplier) (*AlertReportedHandler, error) {
	if applier == nil {
		return nil, errors.New("consumer: falta el caso de uso de reportes")
	}
	return &AlertReportedHandler{applier: applier}, nil
}

// alertReportedPayload es el payload de alert.reported. No trae el
// identificador del denunciante, y Identity no lo guarda: alert_id se valida
// pero no se usa.
type alertReportedPayload struct {
	AlertID string `json:"alert_id"`
	Reason  string `json:"reason"`
}

// Handle procesa un alert.reported. El actor del sobre es el emisor
// reportado: sin actor, o con uno que no es un UUID, el mensaje es inválido.
func (h *AlertReportedHandler) Handle(ctx context.Context, envelope Envelope) error {
	userID, err := actorUserID(envelope)
	if err != nil {
		return err
	}

	var payload alertReportedPayload
	if err := decodePayload(envelope.Payload, &payload); err != nil {
		return err
	}
	if _, err := uuid.Parse(payload.AlertID); err != nil {
		return Permanent(errors.New("payload sin alert_id válido"))
	}
	if !domain.IsValidReportReason(payload.Reason) {
		return Permanent(errors.New("payload con un reason fuera del contrato"))
	}

	// Un error del caso de uso es de infraestructura (la base): transitorio, se
	// devuelve sin marcar para que el consumidor reintente.
	return h.applier.Apply(ctx, domain.AlertReport{
		EventID: envelope.EventID,
		UserID:  userID,
		Reason:  payload.Reason,
	})
}
