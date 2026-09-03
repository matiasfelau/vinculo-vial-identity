package events

import (
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// EventTypeUserCreated es el tipo de evento que emite US-01. Es también el
// routing key con el que se publica.
const EventTypeUserCreated = "user.created"

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
	// vacío, y en el alta la respuesta correcta es la primera.
	Actor   *string `json:"actor"`
	Payload any     `json:"payload"`
}

// userCreatedPayload es el contenido de user.created.
//
// El contrato compartido lo acota a userId, y acá se respeta al pie de la letra:
// el sobre es la interfaz entre tres repositorios y agregarle campos "porque
// pueden servir" es lo que termina volviéndolos obligatorios de facto.
//
// Que sea el único campo también es la decisión correcta en seguridad: no lleva
// PII —ni email, ni DNI, ni el Blind Index del DNI—. Un consumidor que necesite
// datos de la persona los pide a este servicio, que es el único dueño de esa
// información; replicarlos en el bus los expondría a todo el que escuche la cola.
type userCreatedPayload struct {
	UserID string `json:"userId"`
}

// newEnvelope arma el sobre de un alta.
//
// El `actor` va en null por definición del contrato: en el signup todavía no hay
// sesión ni usuario autenticado actuando, el usuario se está creando justo en
// esta petición. No se rellena con el UUID del recién creado —que es el sujeto
// del hecho, no quien lo provoca— ni mucho menos con dni_hashed, que es el
// índice de búsqueda del dato más sensible del sistema y publicarlo en el bus
// destruiría la propiedad que le da sentido al Blind Index.
func newEnvelope(evt domain.UserCreated, producer string, now time.Time) Envelope {
	return Envelope{
		EventID:   uuid.NewString(),
		EventType: EventTypeUserCreated,
		Timestamp: now.UTC().Format(time.RFC3339Nano),
		Producer:  producer,
		Actor:     nil,
		Payload: userCreatedPayload{
			UserID: evt.UserID.String(),
		},
	}
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
func newSessionsRevokedEnvelope(evt domain.SessionsRevoked, producer string, now time.Time) Envelope {
	actor := evt.UserID.String()
	return Envelope{
		EventID:   uuid.NewString(),
		EventType: EventTypeSessionsRevoked,
		Timestamp: now.UTC().Format(time.RFC3339Nano),
		Producer:  producer,
		Actor:     &actor,
		Payload: sessionsRevokedPayload{
			Reason: string(evt.Reason),
		},
	}
}
