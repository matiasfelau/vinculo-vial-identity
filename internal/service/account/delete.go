// Package account implementa el caso de uso de US-11: la baja de cuenta pedida
// por el usuario desde la app y confirmada con su contraseña. Depende
// únicamente de los puertos de domain, igual que el resto de internal/service,
// para poder ejercitarse entero con dobles, sin Postgres ni RabbitMQ.
package account

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// eventTypeSessionsRevoked es el tipo del evento que Notification consume para
// borrar los device tokens del usuario.
const eventTypeSessionsRevoked = "user.sessions.revoked"

// UserFinder es lo único que la baja necesita del repositorio de usuarios,
// declarado del lado del consumidor.
type UserFinder interface {
	FindByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
}

// DeleteDeps son las dependencias de DeleteService.
type DeleteDeps struct {
	Users     UserFinder
	Deletions domain.AccountDeletionRepository
	Hasher    domain.PasswordHasher
	// SanctionCarryoverDays son los días que la sanción de una cuenta penalizada
	// se hereda si el mismo DNI se vuelve a registrar (SANCTION_CARRYOVER_DAYS).
	SanctionCarryoverDays int
	Logger                *slog.Logger
	// Now es el reloj; si es nil usa time.Now.
	Now func() time.Time
}

// DeleteService es el caso de uso de la baja de cuenta.
type DeleteService struct {
	deps DeleteDeps
}

// NewDeleteService valida las dependencias y construye el servicio. Se falla
// en el arranque y no en la primera baja: una dependencia faltante es un error
// de cableado.
func NewDeleteService(d DeleteDeps) (*DeleteService, error) {
	switch {
	case d.Users == nil:
		return nil, errors.New("account: falta el repositorio de usuarios")
	case d.Deletions == nil:
		return nil, errors.New("account: falta el repositorio de la baja")
	case d.Hasher == nil:
		return nil, errors.New("account: falta el hasher de contraseñas")
	case d.SanctionCarryoverDays < 1:
		return nil, errors.New("account: los días de herencia de la sanción deben ser al menos 1")
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &DeleteService{deps: d}, nil
}

// Delete da de baja la cuenta de userID, que viene del JWT ya validado por Kong
// (X-User-Id), tras verificar su contraseña.
//
// Devuelve domain.ErrInvalidPassword si la contraseña no coincide. Un usuario
// que ya no existe no es un error: la baja es idempotente y no revela nada, así
// que devuelve nil, también si desaparece entre la lectura y la transacción.
// Cualquier otro error es de infraestructura (envuelto en
// domain.ErrDatabaseUnavailable si la base no respondió) y no deja nada hecho.
//
// La contraseña se verifica con Argon2 antes de abrir la transacción: es la
// operación cara y no tiene por qué sostener un bloqueo de la fila. El llamador
// es responsable de limpiar password.
func (s *DeleteService) Delete(ctx context.Context, userID uuid.UUID, password []byte) error {
	if userID == uuid.Nil {
		return errors.New("account: falta el usuario")
	}

	user, err := s.deps.Users.FindByID(ctx, userID)
	if errors.Is(err, domain.ErrUserNotFound) {
		s.deps.Logger.InfoContext(ctx, "baja de una cuenta que ya no existe: nada que hacer",
			slog.String("user_id", userID.String()))
		return nil
	}
	if err != nil {
		return fmt.Errorf("account: no se pudo leer al usuario: %w", err)
	}

	// Fail-closed: si el hash guardado está corrupto, Verify falla con error y la
	// baja no avanza, en lugar de tratarlo como una contraseña correcta.
	matches, err := s.deps.Hasher.Verify(password, user.PasswordHash)
	if err != nil {
		return fmt.Errorf("account: no se pudo verificar la contraseña: %w", err)
	}
	if !matches {
		s.deps.Logger.WarnContext(ctx, "baja rechazada: la contraseña no coincide",
			slog.String("user_id", userID.String()))
		return domain.ErrInvalidPassword
	}

	deletion, err := s.buildDeletion(user)
	if err != nil {
		return err
	}

	if err := s.deps.Deletions.DeleteAccount(ctx, deletion); err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			s.deps.Logger.InfoContext(ctx, "la cuenta ya no existe: la baja es idempotente",
				slog.String("user_id", userID.String()))
			return nil
		}
		return fmt.Errorf("account: no se pudo dar de baja la cuenta: %w", err)
	}

	s.deps.Logger.InfoContext(ctx, "cuenta dada de baja",
		slog.String("user_id", userID.String()),
	)
	return nil
}

// buildDeletion arma todo lo que la transacción necesita: las fechas y los dos
// eventos de outbox, con el usuario como actor de ambos al publicarse. La baja
// no guarda nada del usuario más que la sanción de una cuenta penalizada, y eso
// lo decide el repositorio dentro de la transacción.
func (s *DeleteService) buildDeletion(user *domain.User) (domain.AccountDeletion, error) {
	now := s.deps.Now().UTC()

	revoked, err := domain.NewOutboxEvent(eventTypeSessionsRevoked, map[string]string{
		"user_id": user.ID.String(),
		"reason":  string(domain.SessionsRevokedReasonAccountDeleted),
	})
	if err != nil {
		return domain.AccountDeletion{}, fmt.Errorf("account: no se pudo armar user.sessions.revoked: %w", err)
	}
	revoked.CreatedAt = now

	deleted, err := domain.NewOutboxEvent(domain.EventTypeUserDeleted, map[string]string{
		"user_id":    user.ID.String(),
		"deleted_at": now.Format(time.RFC3339Nano),
	})
	if err != nil {
		return domain.AccountDeletion{}, fmt.Errorf("account: no se pudo armar user.deleted: %w", err)
	}
	deleted.CreatedAt = now

	return domain.AccountDeletion{
		UserID:             user.ID,
		DeletedAt:          now,
		CarryoverExpiresAt: now.AddDate(0, 0, s.deps.SanctionCarryoverDays),
		Events:             []domain.OutboxEvent{revoked, deleted},
	}, nil
}
