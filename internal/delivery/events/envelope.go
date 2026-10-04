package events

import (
	"time"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// EventTypeSessionsRevoked es el tipo de evento que emite la Defensa Activa
// de US-03 (US-06). Es también el routing key con el que se publica.
const EventTypeSessionsRevoked = "user.sessions.revoked"

// Envelope es el sobre estándar de eventos de la plataforma. La forma es común
// a todos los productores; lo específico de cada evento va en Payload.
type Envelope struct {
	EventID   string `json:"eventId"`
	EventType string `json:"eventType"`
	Timestamp string `json:"timestamp"`
	Producer  string `json:"producer"`
	// Actor es el usuario autenticado que provocó el hecho. Es un puntero y no
	// un string porque el contrato distingue "no hubo actor" (null) de un actor
	// vacío; hoy el único evento publicado lo informa siempre.
	Actor   *string `json:"actor"`
	Payload any     `json:"payload"`
}

// sessionsRevokedPayload es el contenido de user.sessions.revoked.
//
// Reason es el único campo, tal como fija el contrato: no lleva PII —ni DNI,
// ni email, ni hashes de token—, y es un enum acotado pensado para auditoría.
type sessionsRevokedPayload struct {
	Reason string `json:"reason"`
}

// newSessionsRevokedEnvelope arma el sobre de una revocación masiva de
// sesiones.
//
// A diferencia de newEnvelope, acá Actor sí lleva un valor: es el usuario
// cuyas sesiones se revocaron, la referencia que Notification necesita para
// saber de quién dar de baja los tokens FCM.
//
// EventID reutiliza evt.EventID en vez de generar uno nuevo: viene del
// patrón Transactional Outbox (domain.OutboxEvent.ID), y tiene que ser
// estable entre reintentos del worker para que un consumidor que deduplique
// por event_id no cuente dos veces una publicación reintentada.
func newSessionsRevokedEnvelope(evt domain.SessionsRevoked, producer string, now time.Time) Envelope {
	actor := evt.UserID.String()
	return Envelope{
		EventID:   evt.EventID.String(),
		EventType: EventTypeSessionsRevoked,
		Timestamp: now.UTC().Format(time.RFC3339Nano),
		Producer:  producer,
		Actor:     &actor,
		Payload: sessionsRevokedPayload{
			Reason: string(evt.Reason),
		},
	}
}
