package events

import (
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// EventTypeUserRegistered es el tipo de evento que emite US-01.
const EventTypeUserRegistered = "user.registered"

// Envelope es el sobre estándar de eventos de la plataforma. La forma es común
// a todos los productores; lo específico de cada evento va en Payload.
type Envelope struct {
	EventID   string `json:"eventId"`
	EventType string `json:"eventType"`
	Timestamp string `json:"timestamp"`
	Producer  string `json:"producer"`
	Actor     string `json:"actor"`
	Payload   any    `json:"payload"`
}

// userRegisteredPayload es el contenido de user.registered.
//
// No lleva PII: ni email, ni DNI, ni el Blind Index del DNI. Un consumidor que
// necesite datos de la persona los pide a este servicio, que es el único dueño
// de esa información; replicarlos en el bus los expondría a todo el que escuche
// la cola.
type userRegisteredPayload struct {
	UserID        string `json:"userId"`
	AccountStatus string `json:"accountStatus"`
	RegisteredAt  string `json:"registeredAt"`
}

// newEnvelope arma el sobre de un alta.
//
// El `actor` de la plataforma es el user_hash. En US-01 no puede venir del
// gateway —el usuario se está creando justo en esta petición, así que todavía no
// existe ninguna cabecera X-User-Hash que propagar—, de modo que se genera acá y
// se define como el UUID del usuario: ya es un identificador opaco, estable y no
// enumerable, y no obliga a introducir otro secreto de derivación.
//
// Deliberadamente no se usa dni_hashed: es el índice de búsqueda del dato más
// sensible del sistema y publicarlo en el bus destruiría la propiedad que le da
// sentido al Blind Index.
//
// Si la plataforma termina estandarizando otra derivación para user_hash, este
// es el único punto a cambiar.
func newEnvelope(evt domain.UserRegistered, producer string, now time.Time) Envelope {
	return Envelope{
		EventID:   uuid.NewString(),
		EventType: EventTypeUserRegistered,
		Timestamp: now.UTC().Format(time.RFC3339Nano),
		Producer:  producer,
		Actor:     evt.UserID.String(),
		Payload: userRegisteredPayload{
			UserID:        evt.UserID.String(),
			AccountStatus: string(evt.AccountStatus),
			RegisteredAt:  evt.OccurredAt.UTC().Format(time.RFC3339Nano),
		},
	}
}
