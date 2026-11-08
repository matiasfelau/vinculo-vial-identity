package consumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

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
	logger  *slog.Logger
}

var _ Handler = (*AlertRejectedHandler)(nil)

// NewAlertRejectedHandler construye el handler. Si logger es nil usa
// slog.Default.
func NewAlertRejectedHandler(applier RejectionApplier, logger *slog.Logger) (*AlertRejectedHandler, error) {
	if applier == nil {
		return nil, errors.New("consumer: falta el caso de uso de rechazos")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &AlertRejectedHandler{applier: applier, logger: logger}, nil
}

// alertRejectedPayload es el payload de alert.rejected. alert_id se valida
// pero no se usa: Identity no necesita saber qué alerta fue.
type alertRejectedPayload struct {
	AlertID     string   `json:"alert_id"`
	ReasonCodes []string `json:"reason_codes"`
}

// Handle procesa un alert.rejected. El actor del sobre es el emisor de la
// alerta. Un actor que no es un UUID hace inválido el mensaje; un actor nulo,
// en cambio, no: la alerta es de un emisor dado de baja (issuer_id = NULL), no
// hay a quién penalizar y el mensaje se confirma sin efecto.
//
// El payload se valida antes de mirar el actor: un payload inválido es un
// defecto del productor y va a la DLQ aunque el actor falte.
func (h *AlertRejectedHandler) Handle(ctx context.Context, envelope Envelope) error {
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

	userID, hasActor, err := actorUserID(envelope)
	if err != nil {
		return err
	}
	if !hasActor {
		h.logger.InfoContext(ctx, "rechazo sin actor: el emisor fue dado de baja, no hay a quién penalizar",
			slog.String("event_id", envelope.EventID.String()))
		return nil
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
// hasActor es false, sin error, cuando el sobre no trae actor: lo que eso
// significa lo decide cada handler. Un actor presente que no es un UUID es un
// fallo permanente.
func actorUserID(envelope Envelope) (userID uuid.UUID, hasActor bool, err error) {
	if envelope.Actor == nil {
		return uuid.Nil, false, nil
	}
	userID, err = uuid.Parse(*envelope.Actor)
	if err != nil || userID == uuid.Nil {
		return uuid.Nil, false, Permanent(errors.New("el actor no es un uuid válido"))
	}
	return userID, true, nil
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
