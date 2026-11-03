package domain

import (
	"time"

	"github.com/google/uuid"
)

// Códigos de motivo del veredicto de IA que Alert reenvía en alert.rejected
// (contrato de US-08). Solo los de fraude penalizan al emisor.
const (
	// ReasonNoVehicle indica que la evidencia no muestra ningún vehículo.
	ReasonNoVehicle = "NO_VEHICLE"
	// ReasonBurstMismatch indica que las fotos no corresponden al mismo hecho.
	ReasonBurstMismatch = "BURST_MISMATCH"
	// ReasonPlateMismatch indica que la patente de la evidencia no es la del
	// vehículo denunciado.
	ReasonPlateMismatch = "PLATE_MISMATCH"
)

// HasFraudReasonCode informa si alguno de los códigos es de fraude:
// NO_VEHICLE, BURST_MISMATCH o PLATE_MISMATCH. Cualquier otro código, incluido
// EVIDENCE_UNREADABLE (rechazo sin culpa del emisor), no penaliza.
func HasFraudReasonCode(codes []string) bool {
	for _, code := range codes {
		switch code {
		case ReasonNoVehicle, ReasonBurstMismatch, ReasonPlateMismatch:
			return true
		}
	}
	return false
}

// AlertRejection es el hecho de que Alert rechazó una alerta del usuario
// UserID (evento alert.rejected). No lleva el identificador de la alerta:
// Identity solo necesita saber a quién penalizar y por qué.
type AlertRejection struct {
	// EventID es el eventId del sobre, la clave de deduplicación.
	EventID uuid.UUID
	// UserID es el emisor de la alerta rechazada.
	UserID uuid.UUID
	// ReasonCodes son los códigos del veredicto que motivaron el rechazo.
	ReasonCodes []string
}

// ProcessedEvent identifica un evento ya consumido: la clave de
// deduplicación de los consumidores, que son at-least-once.
type ProcessedEvent struct {
	EventID uuid.UUID
	// Consumer es la cola de trabajo que lo procesó. La clave es
	// (EventID, Consumer): el mismo evento entregado a otro consumidor no
	// cuenta como duplicado.
	Consumer    string
	EventType   string
	ProcessedAt time.Time
}

// RejectionResult es lo que pasó al aplicar un rechazo.
type RejectionResult int

const (
	// RejectionApplied indica que el evento se registró y, si correspondía, el
	// usuario fue penalizado.
	RejectionApplied RejectionResult = iota
	// RejectionDuplicate indica que el evento ya se había procesado: no se
	// cambió nada.
	RejectionDuplicate
	// RejectionUserNotFound indica que el evento se registró pero el usuario
	// ya no existe: no hay a quién penalizar.
	RejectionUserNotFound
)

// Motivos de un reporte (alert.reported), los únicos que admite el contrato.
const (
	// ReportReasonFalseAlert indica que el destinatario considera falsa la alerta.
	ReportReasonFalseAlert = "FALSE_ALERT"
	// ReportReasonSpam indica que el destinatario considera la alerta spam.
	ReportReasonSpam = "SPAM"
)

// IsValidReportReason informa si reason es un motivo de reporte del contrato.
func IsValidReportReason(reason string) bool {
	return reason == ReportReasonFalseAlert || reason == ReportReasonSpam
}

// AlertReport es el hecho de que el destinatario de una alerta reportó a su
// emisor (evento alert.reported). Identity guarda solo el conteo: ni quién
// reportó ni qué alerta fue.
type AlertReport struct {
	// EventID es el eventId del sobre, la clave de deduplicación.
	EventID uuid.UUID
	// UserID es el emisor reportado.
	UserID uuid.UUID
	// Reason es FALSE_ALERT o SPAM.
	Reason string
}

// ReportOutcome es lo que pasó al aplicar un reporte.
type ReportOutcome int

const (
	// ReportCounted indica que el reporte se contó y el usuario sigue como
	// estaba: no llegó al umbral, o ya estaba en revisión.
	ReportCounted ReportOutcome = iota
	// ReportEscalated indica que el reporte llevó al usuario a UNDER_REVIEW y
	// que user.status.changed quedó encolado en el outbox.
	ReportEscalated
	// ReportDuplicate indica que el evento ya se había procesado: no se
	// cambió nada.
	ReportDuplicate
	// ReportUserNotFound indica que el evento se registró pero el usuario ya
	// no existe.
	ReportUserNotFound
)

// UserStatusReason acota los motivos admitidos de user.status.changed.
type UserStatusReason string

const (
	// UserStatusReasonReportsThreshold indica que el usuario pasó a revisión
	// por alcanzar REPORT_REVIEW_THRESHOLD reportes.
	UserStatusReasonReportsThreshold UserStatusReason = "REPORTS_THRESHOLD"
	// UserStatusReasonInheritedOnSignup indica que la cuenta nació en revisión
	// porque el mismo DNI había sido dado de baja con una sanción vigente (US-11).
	UserStatusReasonInheritedOnSignup UserStatusReason = "INHERITED_ON_SIGNUP"
)

// EventTypeUserStatusChanged es el tipo del evento que anuncia un cambio de
// account_status, y también su routing key. Se encola en el outbox en la
// misma transacción que el cambio.
const EventTypeUserStatusChanged = "user.status.changed"

// UserStatusChanged es el evento de dominio user.status.changed: Alert lo
// consume para bloquear al emisor mientras esté en revisión. Lleva el estado
// nuevo y el motivo, sin PII. EventID es el ID de la fila del outbox y se
// reutiliza entre reintentos del worker, para que un consumidor que
// deduplique por eventId no lo cuente dos veces.
type UserStatusChanged struct {
	EventID       uuid.UUID
	UserID        uuid.UUID
	AccountStatus AccountStatus
	Reason        UserStatusReason
}

// userStatusChangedPayload es el payload de user.status.changed en el outbox,
// en snake_case como fija el contrato. El worker lo lee con la misma forma.
type userStatusChangedPayload struct {
	UserID        string `json:"user_id"`
	AccountStatus string `json:"account_status"`
	Reason        string `json:"reason"`
}

// NewUserStatusChangedOutboxEvent arma la fila de outbox de un
// user.status.changed, lista para persistirse en la misma transacción que el
// cambio de estado.
func NewUserStatusChangedOutboxEvent(userID uuid.UUID, status AccountStatus, reason UserStatusReason) (OutboxEvent, error) {
	return NewOutboxEvent(EventTypeUserStatusChanged, userStatusChangedPayload{
		UserID:        userID.String(),
		AccountStatus: string(status),
		Reason:        string(reason),
	})
}

// NewUserStatusChanged arma el evento a partir de un OutboxEvent ya
// persistido: eventID es OutboxEvent.ID, nunca uno generado en este punto.
func NewUserStatusChanged(eventID, userID uuid.UUID, status AccountStatus, reason UserStatusReason) UserStatusChanged {
	return UserStatusChanged{EventID: eventID, UserID: userID, AccountStatus: status, Reason: reason}
}
