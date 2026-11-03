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

// HoldSanction es lo que el hold guarda de una cuenta penalizada, para que el
// mismo DNI no pueda borrar su sanción dándose de baja y registrándose de
// nuevo. DNIHMAC es el mismo Blind Index que users.dni_hashed.
type HoldSanction struct {
	DNIHMAC         string
	AccountStatus   AccountStatus
	ReputationScore int
	ReportCount     int
}

// UserHold es el registro mínimo que se conserva por LEGAL_HOLD_DAYS tras la
// baja de una cuenta (art. 16 inc. 5 de la Ley 25.326), aislado en el esquema
// legal_hold y destruido al vencer (art. 4 inc. 7). Ningún endpoint lo lee:
// solo lo tocan la baja, el signup y el sweeper.
//
// DNISealed es el DNI cifrado con HPKE hacia el responsable legal: este
// servicio no puede volver a abrirlo. Sanction es nulo si la cuenta no estaba
// penalizada, y también después de que un nuevo registro heredó la sanción.
type UserHold struct {
	UserID    uuid.UUID
	DNISealed string
	DeletedAt time.Time
	DestroyAt time.Time
	Sanction  *HoldSanction
}

// AccountDeletion es todo lo que el caso de uso de la baja le entrega al
// repositorio para ejecutarla en una única transacción. Lo que depende del
// estado de la cuenta (la sanción) lo lee el repositorio dentro de la propia
// transacción, con la fila bloqueada: así un reporte que llega entre la
// lectura del usuario y la baja no se pierde.
type AccountDeletion struct {
	UserID uuid.UUID
	// DNISealed es el DNI sellado hacia el responsable legal.
	DNISealed string
	DeletedAt time.Time
	// DestroyAt es DeletedAt + LEGAL_HOLD_DAYS.
	DestroyAt time.Time
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
	case d.DNISealed == "":
		return errors.New("domain: la baja no tiene el DNI sellado")
	case d.DeletedAt.IsZero():
		return errors.New("domain: la baja no tiene fecha")
	case !d.DestroyAt.After(d.DeletedAt):
		return errors.New("domain: la destrucción del hold no es posterior a la baja")
	case len(d.Events) == 0:
		return errors.New("domain: la baja no tiene eventos que publicar")
	}
	return nil
}

// HoldFor arma el hold de la cuenta u, tal como está en este momento. Guarda
// la sanción solo si la cuenta estaba penalizada (User.IsPenalized).
func (d AccountDeletion) HoldFor(u *User) UserHold {
	hold := UserHold{
		UserID:    d.UserID,
		DNISealed: d.DNISealed,
		DeletedAt: d.DeletedAt.UTC(),
		DestroyAt: d.DestroyAt.UTC(),
	}
	if u.IsPenalized() {
		hold.Sanction = &HoldSanction{
			DNIHMAC:         u.DNIHashed,
			AccountStatus:   u.AccountStatus,
			ReputationScore: u.ReputationScore,
			ReportCount:     u.ReportCount,
		}
	}
	return hold
}
