package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// reviewMigrationLockKey es la clave del advisory lock que serializa la migración
// de review_decisions cuando varias réplicas arrancan a la vez.
const reviewMigrationLockKey int64 = 0x6c68_0005

// reviewDecisionModel es la proyección de persistencia de domain.ReviewDecision:
// el historial de decisiones de los operadores sobre los casos de revisión
// (US-17). No guarda nada personal del usuario: solo su id.
type reviewDecisionModel struct {
	ID        uuid.UUID `gorm:"column:id;type:uuid;primaryKey"`
	UserID    uuid.UUID `gorm:"column:user_id;type:uuid;not null;index:idx_review_decisions_user_id"`
	Decision  string    `gorm:"column:decision;type:varchar(16);not null"`
	Reason    string    `gorm:"column:reason;type:varchar(500);not null"`
	Operator  string    `gorm:"column:operator;type:varchar(100);not null"`
	DecidedAt time.Time `gorm:"column:decided_at;type:timestamptz;not null"`
}

// TableName fija el nombre de la tabla en lugar de depender de la pluralización
// automática de GORM.
func (reviewDecisionModel) TableName() string { return "review_decisions" }

func toReviewDecisionModel(d domain.ReviewDecision) *reviewDecisionModel {
	return &reviewDecisionModel{
		ID:        d.ID,
		UserID:    d.UserID,
		Decision:  d.Decision,
		Reason:    d.Reason,
		Operator:  d.Operator,
		DecidedAt: d.DecidedAt.UTC(),
	}
}

func (m *reviewDecisionModel) toDomain() domain.ReviewDecision {
	return domain.ReviewDecision{
		ID:        m.ID,
		UserID:    m.UserID,
		Decision:  m.Decision,
		Reason:    m.Reason,
		Operator:  m.Operator,
		DecidedAt: m.DecidedAt.UTC(),
	}
}

// addReviewDecisionsForeignKey agrega, de forma idempotente, la clave foránea de
// review_decisions.user_id hacia users.id con ON DELETE CASCADE: la baja de una
// cuenta se lleva su historial (Ley 25.326, minimización). Va en SQL crudo por el
// mismo motivo que la de sessions. Se busca por tabla y no solo por nombre, para
// que otro esquema de la misma base con la misma constraint no la dé por hecha.
const addReviewDecisionsForeignKey = `
DO $$
BEGIN
	IF NOT EXISTS (
		SELECT 1 FROM pg_constraint
		WHERE conname = 'fk_review_decisions_user_id' AND conrelid = to_regclass('review_decisions')
	) THEN
		ALTER TABLE review_decisions
			ADD CONSTRAINT fk_review_decisions_user_id
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
	END IF;
END $$;
`

// ReviewRepository implementa domain.ReviewRepository sobre GORM/PostgreSQL.
type ReviewRepository struct {
	db *gorm.DB
}

var _ domain.ReviewRepository = (*ReviewRepository)(nil)

// NewReviewRepository construye el repositorio y migra review_decisions. Requiere
// que users y outbox_events ya estén migradas: la primera por la clave foránea, la
// segunda porque Unblock escribe en ella.
func NewReviewRepository(ctx context.Context, db *gorm.DB) (*ReviewRepository, error) {
	if db == nil {
		return nil, errors.New("postgres: se requiere una conexión GORM")
	}

	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", reviewMigrationLockKey).Error; err != nil {
			return fmt.Errorf("no se pudo tomar el lock de la migración: %w", err)
		}
		if err := tx.AutoMigrate(&reviewDecisionModel{}); err != nil {
			return fmt.Errorf("no se pudo migrar review_decisions: %w", err)
		}
		if err := tx.Exec(addReviewDecisionsForeignKey).Error; err != nil {
			return fmt.Errorf("no se pudo crear la clave foránea de review_decisions: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("postgres: falló la migración de review_decisions: %w", err)
	}

	return &ReviewRepository{db: db}, nil
}

// reviewCaseRow es una fila del listado. sort_key es la clave de orden y de
// paginación: desde cuándo está en revisión o, si no se sabe, cuándo se creó la
// cuenta. Se usa created_at y no updated_at porque este último cambia con cada
// reporte, y una clave que se mueve mientras se pagina saltea o repite casos.
type reviewCaseRow struct {
	ID               uuid.UUID
	AccountStatus    string
	ReportCount      int
	ReputationScore  int
	UnderReviewSince *time.Time
	LastReportedAt   *time.Time
	SortKey          time.Time
}

// ListCases devuelve una página del listado de casos, con paginación por clave
// (keyset) sobre (sort_key, id). Ver domain.ReviewRepository.ListCases.
func (r *ReviewRepository) ListCases(ctx context.Context, status domain.AccountStatus, limit int, cursor string) (domain.ReviewCasePage, error) {
	if limit < 1 {
		return domain.ReviewCasePage{}, errors.New("postgres: el límite de la página debe ser al menos 1")
	}

	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	query := r.db.WithContext(ctx).Table("users").
		Select("id, account_status, report_count, reputation_score, under_review_since, last_reported_at, COALESCE(under_review_since, created_at) AS sort_key").
		Where("account_status = ?", string(status))

	if cursor != "" {
		key, id, err := decodeReviewCursor(cursor)
		if err != nil {
			return domain.ReviewCasePage{}, err
		}
		query = query.Where("(COALESCE(under_review_since, created_at), id) > (?, ?)", key, id)
	}

	var rows []reviewCaseRow
	// Una fila de más para saber si hay página siguiente sin una segunda consulta.
	if err := query.Order("sort_key ASC, id ASC").Limit(limit + 1).Scan(&rows).Error; err != nil {
		return domain.ReviewCasePage{}, fmt.Errorf("postgres: no se pudieron listar los casos: %w", classifyDBError(err))
	}

	page := domain.ReviewCasePage{Items: make([]domain.ReviewCase, 0, len(rows))}
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[limit-1]
		page.NextCursor = encodeReviewCursor(last.SortKey, last.ID)
	}
	for _, row := range rows {
		page.Items = append(page.Items, domain.ReviewCase{
			UserID:           row.ID,
			AccountStatus:    domain.AccountStatus(row.AccountStatus),
			ReportCount:      row.ReportCount,
			ReputationScore:  row.ReputationScore,
			UnderReviewSince: utcPtr(row.UnderReviewSince),
			LastReportedAt:   utcPtr(row.LastReportedAt),
		})
	}
	return page, nil
}

// encodeReviewCursor arma el cursor opaco: la clave de orden en microsegundos
// (la precisión de timestamptz) y el id de la última fila de la página.
func encodeReviewCursor(key time.Time, id uuid.UUID) string {
	raw := strconv.FormatInt(key.UnixMicro(), 10) + "." + id.String()
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeReviewCursor(cursor string) (time.Time, uuid.UUID, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, uuid.Nil, domain.ErrInvalidCursor
	}
	micros, idText, ok := strings.Cut(string(raw), ".")
	if !ok {
		return time.Time{}, uuid.Nil, domain.ErrInvalidCursor
	}
	n, err := strconv.ParseInt(micros, 10, 64)
	if err != nil {
		return time.Time{}, uuid.Nil, domain.ErrInvalidCursor
	}
	id, err := uuid.Parse(idText)
	if err != nil {
		return time.Time{}, uuid.Nil, domain.ErrInvalidCursor
	}
	return time.UnixMicro(n).UTC(), id, nil
}

// Unblock levanta la revisión de una cuenta. Ver domain.ReviewRepository.Unblock.
//
// El UPDATE es condicional (WHERE account_status = 'UNDER_REVIEW') y es la guarda:
// dos desbloqueos concurrentes se serializan por el bloqueo de la fila, y el
// segundo, cuando el primero confirma, ya no la encuentra en revisión. Solo si no
// afectó ninguna fila se consulta si la cuenta existe, para distinguir 404 de 409.
func (r *ReviewRepository) Unblock(ctx context.Context, decision domain.ReviewDecision, statusChanged domain.OutboxEvent) error {
	if statusChanged.Type != domain.EventTypeUserStatusChanged {
		return errors.New("postgres: falta el user.status.changed del desbloqueo")
	}

	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		updated := tx.Model(&userModel{}).
			Where("id = ? AND account_status = ?", decision.UserID, string(domain.AccountStatusUnderReview)).
			Updates(map[string]any{
				"account_status":     string(domain.AccountStatusActive),
				"report_count":       0,
				"under_review_since": nil,
				"updated_at":         decision.DecidedAt.UTC(),
			})
		if updated.Error != nil {
			return fmt.Errorf("no se pudo levantar la revisión: %w", updated.Error)
		}
		if updated.RowsAffected == 0 {
			var count int64
			if err := tx.Model(&userModel{}).Where("id = ?", decision.UserID).Count(&count).Error; err != nil {
				return fmt.Errorf("no se pudo consultar la cuenta: %w", err)
			}
			if count == 0 {
				return domain.ErrUserNotFound
			}
			return domain.ErrNotUnderReview
		}

		if err := tx.Create(toReviewDecisionModel(decision)).Error; err != nil {
			return fmt.Errorf("no se pudo registrar la decisión: %w", err)
		}
		if err := tx.Create(toOutboxModel(&statusChanged)).Error; err != nil {
			return fmt.Errorf("no se pudo encolar el evento de outbox: %w", err)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) || errors.Is(err, domain.ErrNotUnderReview) {
			return err
		}
		return fmt.Errorf("postgres: no se pudo desbloquear la cuenta: %w", classifyDBError(err))
	}
	return nil
}

// ListDecisions devuelve el historial de decisiones de una cuenta, de la más nueva
// a la más vieja.
func (r *ReviewRepository) ListDecisions(ctx context.Context, userID uuid.UUID) ([]domain.ReviewDecision, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	var rows []reviewDecisionModel
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Order("decided_at DESC, id DESC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("postgres: no se pudo leer el historial de decisiones: %w", classifyDBError(err))
	}

	decisions := make([]domain.ReviewDecision, 0, len(rows))
	for i := range rows {
		decisions = append(decisions, rows[i].toDomain())
	}
	return decisions, nil
}
