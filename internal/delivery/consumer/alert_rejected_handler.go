package consumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// RejectionApplier es el caso de uso que penaliza a un emisor.
type RejectionApplier interface {
	Apply(ctx context.Context, rejection domain.AlertRejection) error
}

// AlertRejectedHandler traduce un alert.rejected al caso de uso de reputación.
// Valida el sobre y el payload antes de tocar nada: un mensaje inválido es un
// fallo permanente y va directo a la DLQ.
type AlertRejectedHandler struct {
	applier RejectionApplier
}

var _ Handler = (*AlertRejectedHandler)(nil)

// NewAlertRejectedHandler construye el handler.
func NewAlertRejectedHandler(applier RejectionApplier) (*AlertRejectedHandler, error) {
	if applier == nil {
		return nil, errors.New("consumer: falta el caso de uso de rechazos")
	}
	return &AlertRejectedHandler{applier: applier}, nil
}

// alertRejectedPayload es el payload de alert.rejected. alert_id se valida
// pero no se usa: Identity no necesita saber qué alerta fue.
type alertRejectedPayload struct {
	AlertID     string   `json:"alert_id"`
	ReasonCodes []string `json:"reason_codes"`
}

// Handle procesa un alert.rejected. El actor del sobre es el emisor de la
// alerta: sin actor, o con uno que no es un UUID, el mensaje es inválido.
func (h *AlertRejectedHandler) Handle(ctx context.Context, envelope Envelope) error {
	userID, err := actorUserID(envelope)
	if err != nil {
		return err
	}

	var payload alertRejectedPayload
	if err := decodePayload(envelope.Payload, &payload); err != nil {
		return err
	}
	if _, err := uuid.Parse(payload.AlertID); err != nil {
		return Permanent(errors.New("payload sin alert_id válido"))
	}
	if len(payload.ReasonCodes) == 0 {
		return Permanent(errors.New("payload sin reason_codes"))
	}
	for _, code := range payload.ReasonCodes {
		if code == "" {
			return Permanent(errors.New("payload con un reason_code vacío"))
		}
	}

	// Un error del caso de uso es de infraestructura (la base): transitorio, se
	// devuelve sin marcar para que el consumidor reintente.
	return h.applier.Apply(ctx, domain.AlertRejection{
		EventID:     envelope.EventID,
		UserID:      userID,
		ReasonCodes: payload.ReasonCodes,
	})
}

// actorUserID lee el actor del sobre como el UUID del usuario afectado.
func actorUserID(envelope Envelope) (uuid.UUID, error) {
	if envelope.Actor == nil {
		return uuid.Nil, Permanent(errors.New("sobre sin actor"))
	}
	userID, err := uuid.Parse(*envelope.Actor)
	if err != nil || userID == uuid.Nil {
		return uuid.Nil, Permanent(errors.New("el actor no es un uuid válido"))
	}
	return userID, nil
}

// decodePayload decodifica el payload del sobre en dst. Cualquier fallo es
// permanente: reintentar no cambia el resultado.
func decodePayload(raw []byte, dst any) error {
	if len(raw) == 0 {
		return Permanent(errors.New("sobre sin payload"))
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return Permanent(fmt.Errorf("payload ilegible: %w", err))
	}
	return nil
}
