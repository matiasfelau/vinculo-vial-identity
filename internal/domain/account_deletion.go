package domain

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// EventTypeUserDeleted es el tipo del evento que anuncia la baja de una cuenta
// (US-11), y también su routing key. Alert y Vehicle lo consumen para borrar
// lo que tenían del usuario.
const EventTypeUserDeleted = "user.deleted"

// UserDeleted es el evento de dominio user.deleted. El usuario dado de baja
// viaja como actor del sobre, no en el payload; el payload solo lleva
// deleted_at. EventID es el ID de la fila del outbox y se reutiliza entre
// reintentos del worker, para que un consumidor que deduplique por eventId no
// lo cuente dos veces.
type UserDeleted struct {
	EventID   uuid.UUID
	UserID    uuid.UUID
	DeletedAt time.Time
}

// NewUserDeleted arma el evento a partir de un OutboxEvent ya persistido:
// eventID es OutboxEvent.ID, nunca uno generado en este punto.
func NewUserDeleted(eventID, userID uuid.UUID, deletedAt time.Time) UserDeleted {
	return UserDeleted{EventID: eventID, UserID: userID, DeletedAt: deletedAt.UTC()}
}

// AccountDeletion es todo lo que el caso de uso de la baja le entrega al
// repositorio para ejecutarla en una única transacción. Lo que depende del
// estado de la cuenta (la sanción) lo lee el repositorio dentro de la propia
// transacción, con la fila bloqueada: así un reporte que llega entre la
// lectura del usuario y la baja no se pierde.
type AccountDeletion struct {
	UserID    uuid.UUID
	DeletedAt time.Time
	// CarryoverExpiresAt es DeletedAt + SANCTION_CARRYOVER_DAYS: hasta cuándo la
	// sanción de una cuenta penalizada se hereda si el mismo DNI se vuelve a
	// registrar.
	CarryoverExpiresAt time.Time
	// Events son los eventos de outbox que la baja publica
	// (user.sessions.revoked y user.deleted); se persisten en la misma
	// transacción que el borrado.
	Events []OutboxEvent
}

// Validate comprueba los invariantes de la baja antes de tocar la base.
func (d AccountDeletion) Validate() error {
	switch {
	case d.UserID == uuid.Nil:
		return errors.New("domain: la baja no tiene usuario")
	case d.DeletedAt.IsZero():
		return errors.New("domain: la baja no tiene fecha")
	case !d.CarryoverExpiresAt.After(d.DeletedAt):
		return errors.New("domain: el vencimiento de la herencia de sanción no es posterior a la baja")
	case len(d.Events) == 0:
		return errors.New("domain: la baja no tiene eventos que publicar")
	}
	return nil
}

// CarryoverFor arma la sanción que deja la cuenta u, tal como está en este
// momento, o nil si la cuenta no estaba penalizada (User.IsPenalized).
func (d AccountDeletion) CarryoverFor(u *User) *SanctionCarryover {
	if !u.IsPenalized() {
		return nil
	}
	return &SanctionCarryover{
		DNIHMAC:         u.DNIHashed,
		AccountStatus:   u.AccountStatus,
		ReputationScore: u.ReputationScore,
		ReportCount:     u.ReportCount,
		CreatedAt:       d.DeletedAt.UTC(),
		ExpiresAt:       d.CarryoverExpiresAt.UTC(),
	}
}
