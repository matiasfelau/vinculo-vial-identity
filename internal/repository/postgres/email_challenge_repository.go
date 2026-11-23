package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// EmailChallengeRepository implementa domain.EmailChallengeRepository.
type EmailChallengeRepository struct {
	db *gorm.DB
}

var _ domain.EmailChallengeRepository = (*EmailChallengeRepository)(nil)

// NewEmailChallengeRepository construye el repositorio y migra email_challenges.
//
// Requiere que users ya exista: la tabla declara una clave foránea hacia ella.
func NewEmailChallengeRepository(ctx context.Context, db *gorm.DB) (*EmailChallengeRepository, error) {
	if db == nil {
		return nil, errors.New("postgres: se requiere una conexión GORM")
	}
	if err := ensureEmailChallenges(ctx, db); err != nil {
		return nil, err
	}
	return &EmailChallengeRepository{db: db}, nil
}

// Mutate bloquea el desafío del subject, le aplica fn y persiste el resultado
// con sus eventos de outbox en una única transacción. Ver
// domain.EmailChallengeRepository.Mutate.
//
// Si el desafío no existe y create es true, lo inserta antes de bloquearlo, con
// ON CONFLICT DO NOTHING: dos pedidos concurrentes del mismo subject no chocan en
// el índice único, el segundo espera al primero en el SELECT ... FOR UPDATE y ve
// su resultado. Que fn falle deshace también esa inserción.
func (r *EmailChallengeRepository) Mutate(ctx context.Context, purpose domain.EmailChallengePurpose, subjectHMAC string, create bool, fn domain.EmailChallengeMutation) error {
	if !purpose.Valid() {
		return fmt.Errorf("postgres: propósito de desafío inválido %q", purpose)
	}
	if subjectHMAC == "" || fn == nil {
		return errors.New("postgres: faltan el subject o la mutación del desafío")
	}

	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if create {
			fresh := emailChallengeModel{
				ID:          uuid.New(),
				Purpose:     string(purpose),
				SubjectHMAC: subjectHMAC,
				CreatedAt:   time.Now().UTC(),
			}
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&fresh).Error; err != nil {
				return fmt.Errorf("no se pudo crear el desafío: %w", err)
			}
		}

		var m emailChallengeModel
		err := tx.Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate}).
			Where("purpose = ? AND subject_hmac = ?", string(purpose), subjectHMAC).
			Take(&m).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return domain.ErrChallengeNotFound
		}
		if err != nil {
			return fmt.Errorf("no se pudo bloquear el desafío: %w", err)
		}

		challenge := m.toDomain()
		events, err := fn(challenge)
		if err != nil {
			return err
		}

		if err := tx.Save(toEmailChallengeModel(challenge)).Error; err != nil {
			return fmt.Errorf("no se pudo guardar el desafío: %w", err)
		}
		for i := range events {
			if err := tx.Create(toOutboxModel(&events[i])).Error; err != nil {
				return fmt.Errorf("no se pudo encolar el evento de outbox: %w", err)
			}
		}
		return nil
	})
	return mapChallengeError(err)
}

// FindByGrantHash busca el desafío por el SHA-256 de su grant.
func (r *EmailChallengeRepository) FindByGrantHash(ctx context.Context, grantHash string) (*domain.EmailChallenge, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	var m emailChallengeModel
	if err := r.db.WithContext(ctx).Where("grant_hash = ?", grantHash).Take(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrChallengeNotFound
		}
		return nil, mapChallengeError(err)
	}
	return m.toDomain(), nil
}

// AddGrantAttempt suma un rechazo de identidad al grant. Es un único UPDATE
// atómico: dos rechazos concurrentes suman los dos.
func (r *EmailChallengeRepository) AddGrantAttempt(ctx context.Context, grantHash string) error {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	err := r.db.WithContext(ctx).Model(&emailChallengeModel{}).
		Where("grant_hash = ? AND consumed_at IS NULL", grantHash).
		Update("grant_attempts", gorm.Expr("grant_attempts + 1")).Error
	return mapChallengeError(err)
}

// CompletePasswordReset consume el grant, cambia la contraseña, revoca todas las
// sesiones y encola los dos eventos en una única transacción. El UPDATE que
// consume el grant va primero y es la guarda de todo lo demás: si no afecta
// ninguna fila, el token ya no sirve y no se toca nada.
func (r *EmailChallengeRepository) CompletePasswordReset(ctx context.Context, c domain.PasswordResetCompletion) error {
	if c.GrantHash == "" || c.UserID == uuid.Nil || c.PasswordHash == "" {
		return errors.New("postgres: faltan datos para completar la recuperación")
	}

	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	now := c.Now.UTC()
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&emailChallengeModel{}).
			Where("grant_hash = ? AND purpose = ? AND user_id = ?",
				c.GrantHash, string(domain.EmailChallengePurposePasswordReset), c.UserID).
			Where("consumed_at IS NULL AND grant_expires_at > ? AND grant_attempts < ?", now, c.MaxIdentityAttempts).
			Update("consumed_at", now)
		if res.Error != nil {
			return fmt.Errorf("no se pudo consumir el token: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return domain.ErrInvalidResetToken
		}

		res = tx.Model(&userModel{}).
			Where("id = ?", c.UserID).
			Updates(map[string]any{"password": c.PasswordHash, "updated_at": now})
		if res.Error != nil {
			return fmt.Errorf("no se pudo cambiar la contraseña: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return domain.ErrInvalidResetToken
		}

		// El mismo código que RevokeAllByUserID, sobre esta transacción: o se
		// cambia la contraseña y se cierran todas las sesiones, o ninguna de las
		// dos cosas.
		if err := revokeAllSessions(tx, c.UserID, &c.SessionsRevoked); err != nil {
			return err
		}

		if err := tx.Create(toOutboxModel(&c.PasswordChanged)).Error; err != nil {
			return fmt.Errorf("no se pudo encolar el evento de outbox: %w", err)
		}
		return nil
	})
	return mapChallengeError(err)
}

// deleteExpiredEmailChallenges borra un lote de desafíos que ya no sirven para
// nada. Las filas se eligen en un CTE MATERIALIZED con FOR UPDATE SKIP LOCKED, por
// el mismo motivo que en el barrido de sanciones: dos réplicas barriendo a la vez
// reparten el trabajo, y nunca se borra más que el lote.
//
// Una fila se borra cuando ya pasaron los tres plazos: el del código, el del
// grant y el de la ventana de 24 h de envíos. Un plazo ausente (NULL) cuenta como
// ya pasado.
const deleteExpiredEmailChallenges = `
WITH doomed AS MATERIALIZED (
	SELECT id FROM email_challenges
	WHERE COALESCE(code_expires_at, '-infinity'::timestamptz) <= ?
		AND COALESCE(grant_expires_at, '-infinity'::timestamptz) <= ?
		AND COALESCE(sends_window_started_at, '-infinity'::timestamptz) <= ?
	ORDER BY created_at
	LIMIT ?
	FOR UPDATE SKIP LOCKED
)
DELETE FROM email_challenges AS c
USING doomed
WHERE c.id = doomed.id`

// DeleteExpired borra hasta limit desafíos vencidos.
func (r *EmailChallengeRepository) DeleteExpired(ctx context.Context, now time.Time, limit int) (int64, error) {
	if limit < 1 {
		return 0, errors.New("postgres: el límite del lote debe ser al menos 1")
	}

	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	now = now.UTC()
	windowCutoff := now.Add(-domain.EmailChallengeSendWindow)
	res := r.db.WithContext(ctx).Exec(deleteExpiredEmailChallenges, now, now, windowCutoff, limit)
	if res.Error != nil {
		return 0, fmt.Errorf("postgres: no se pudieron borrar los desafíos vencidos: %w", classifyDBError(res.Error))
	}
	return res.RowsAffected, nil
}

// mapChallengeError traduce un error de la transacción: los centinelas del
// dominio pasan tal cual, la indisponibilidad de la base se clasifica y el resto
// se envuelve sin exponer nada del contenido (el error del driver puede traer
// valores de la fila).
func mapChallengeError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, domain.ErrChallengeNotFound) || errors.Is(err, domain.ErrInvalidResetToken) {
		return err
	}
	if classified := classifyDBError(err); errors.Is(classified, domain.ErrDatabaseUnavailable) {
		return classified
	}
	return fmt.Errorf("postgres: falló la operación sobre email_challenges: %w", err)
}
