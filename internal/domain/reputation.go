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
