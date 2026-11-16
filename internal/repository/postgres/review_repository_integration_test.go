//go:build integration

// Pruebas de integración contra un PostgreSQL real de ReviewRepository (US-17):
// el listado de casos, el desbloqueo transaccional, el historial de decisiones y
// las columnas nuevas de users. Mismas reglas que outbox_migration_test.go.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

func repositorioDeRevision(t *testing.T, db *gorm.DB) (*ReviewRepository, *ReputationRepository) {
	t.Helper()

	reputacion := repositorioDeReportes(t, db) // users, processed_events y outbox_events.
	repo, err := NewReviewRepository(t.Context(), db)
	if err != nil {
		t.Fatalf("migración de review_decisions: %v", err)
	}
	return repo, reputacion
}

// enRevision deja al usuario UNDER_REVIEW desde since (nil: como los que ya
// estaban en revisión antes de US-17).
func enRevision(t *testing.T, db *gorm.DB, id uuid.UUID, reportes, reputacion int, since *time.Time) {
	t.Helper()

	err := db.Exec(`UPDATE users SET account_status = 'UNDER_REVIEW', report_count = ?, reputation_score = ?, under_review_since = ? WHERE id = ?`,
		reportes, reputacion, since, id).Error
	if err != nil {
		t.Fatalf("no se pudo poner al usuario en revisión: %v", err)
	}
}

func creadoEn(t *testing.T, db *gorm.DB, id uuid.UUID, cuando time.Time) {
	t.Helper()

	if err := db.Exec(`UPDATE users SET created_at = ? WHERE id = ?`, cuando.UTC(), id).Error; err != nil {
		t.Fatalf("no se pudo fijar created_at: %v", err)
	}
}

func desbloqueo(t *testing.T, userID uuid.UUID, motivo, operador string) (domain.ReviewDecision, domain.OutboxEvent) {
	t.Helper()

	ahora := time.Now().UTC()
	evt, err := domain.NewUserStatusChangedOutboxEvent(userID, domain.AccountStatusActive, domain.UserStatusReasonManualUnblock)
	if err != nil {
		t.Fatalf("no se pudo armar el evento: %v", err)
	}
	evt.CreatedAt = ahora
	return domain.ReviewDecision{
		ID:        uuid.New(),
		UserID:    userID,
		Decision:  domain.ReviewDecisionUnblock,
		Reason:    motivo,
		Operator:  operador,
		DecidedAt: ahora,
	}, evt
}

type filaUsuarioRevision struct {
	AccountStatus    string
	ReportCount      int
	ReputationScore  int
	UnderReviewSince *time.Time
	LastReportedAt   *time.Time
}

func leerRevision(t *testing.T, db *gorm.DB, id uuid.UUID) filaUsuarioRevision {
	t.Helper()

	var f filaUsuarioRevision
	err := db.Raw(`SELECT account_status, report_count, reputation_score, under_review_since, last_reported_at FROM users WHERE id = ?`, id).Scan(&f).Error
	if err != nil {
		t.Fatalf("no se pudo leer el usuario: %v", err)
	}
	return f
}

func contarDecisiones(t *testing.T, db *gorm.DB) int64 {
	t.Helper()

	var n int64
	if err := db.Raw(`SELECT count(*) FROM review_decisions`).Scan(&n).Error; err != nil {
		t.Fatalf("no se pudo contar review_decisions: %v", err)
	}
	return n
}

// Las columnas nuevas de users se agregan nulables sobre una tabla con filas, sin
// tocar nada de lo existente, y review_decisions se crea con su clave foránea y
// sus tipos. Repetir la migración no cambia nada.
func TestIntegracionMigracionDeRevisionSobreUsersConFilas(t *testing.T) {
	db := baseConEsquemaAislado(t)
	if err := db.Exec(ddlUsersPreUS08).Error; err != nil {
		t.Fatalf("no se pudo crear la tabla users previa: %v", err)
	}
	existente := insertarUsuarioPreUS08(t, db, "viejo@example.com", "UNDER_REVIEW")

	if _, err := NewUserRepository(t.Context(), db); err != nil {
		t.Fatalf("la migración de users falló: %v", err)
	}
	if _, err := NewOutboxRepository(t.Context(), db); err != nil {
		t.Fatalf("migración de outbox_events: %v", err)
	}
	for range 2 {
		if _, err := NewReviewRepository(t.Context(), db); err != nil {
			t.Fatalf("la migración de review_decisions falló: %v", err)
		}
	}

	for _, nombre := range []string{"under_review_since", "last_reported_at"} {
		c := columnaDeUsers(t, db, nombre)
		if c.IsNullable != "YES" || c.ColumnDefault != nil || c.DataType != "timestamp with time zone" {
			t.Errorf("users.%s = %+v, se esperaba timestamptz nulable sin default", nombre, c)
		}
	}
	f := leerRevision(t, db, existente)
	if f.AccountStatus != "UNDER_REVIEW" || f.UnderReviewSince != nil || f.LastReportedAt != nil {
		t.Errorf("la migración alteró al usuario existente: %+v", f)
	}

	var cols []struct {
		ColumnName    string
		DataType      string
		IsNullable    string
		MaxLength     *int `gorm:"column:character_maximum_length"`
		ColumnDefault *string
	}
	err := db.Raw(`SELECT column_name, data_type, is_nullable, character_maximum_length, column_default FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'review_decisions' ORDER BY column_name`).Scan(&cols).Error
	if err != nil {
		t.Fatalf("no se pudo leer review_decisions: %v", err)
	}
	want := map[string]struct {
		tipo string
		max  int
	}{
		"id": {"uuid", 0}, "user_id": {"uuid", 0}, "decision": {"character varying", 16},
		"reason": {"character varying", 500}, "operator": {"character varying", 100},
		"decided_at": {"timestamp with time zone", 0},
	}
	if len(cols) != len(want) {
		t.Fatalf("review_decisions tiene %d columnas, se esperaban %d: %+v", len(cols), len(want), cols)
	}
	for _, c := range cols {
		w, ok := want[c.ColumnName]
		if !ok || c.DataType != w.tipo || c.IsNullable != "NO" {
			t.Errorf("columna %s = %+v, se esperaba %s NOT NULL", c.ColumnName, c, w.tipo)
		}
		if w.max != 0 && (c.MaxLength == nil || *c.MaxLength != w.max) {
			t.Errorf("columna %s: largo = %v, se esperaba %d", c.ColumnName, c.MaxLength, w.max)
		}
	}

	var fks []string
	err = db.Raw(`SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE contype = 'f' AND conrelid = 'review_decisions'::regclass`).Scan(&fks).Error
	if err != nil || len(fks) != 1 || !strings.Contains(fks[0], "REFERENCES users(id)") || !strings.Contains(fks[0], "ON DELETE CASCADE") {
		t.Errorf("claves foráneas = %v (err=%v), se esperaba una a users(id) ON DELETE CASCADE", fks, err)
	}
}

// ApplyReport anota cuándo se contó el último reporte y desde cuándo está el
// usuario en revisión: el segundo reporte actualiza last_reported_at pero no
// under_review_since.
func TestIntegracionApplyReportActualizaLasFechasDelCaso(t *testing.T) {
	db := baseConEsquemaAislado(t)
	_, reputacion := repositorioDeRevision(t, db)
	id := usuarioNuevo(t, db)

	primero := eventoDeReporte()
	primero.ProcessedAt = time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	if res := reportarEvento(t, reputacion, primero, id, 1); res != domain.ReportEscalated {
		t.Fatalf("primer reporte = %v, se esperaba ReportEscalated", res)
	}
	f := leerRevision(t, db, id)
	if f.UnderReviewSince == nil || !f.UnderReviewSince.Equal(primero.ProcessedAt) {
		t.Errorf("under_review_since = %v, se esperaba %v", f.UnderReviewSince, primero.ProcessedAt)
	}
	if f.LastReportedAt == nil || !f.LastReportedAt.Equal(primero.ProcessedAt) {
		t.Errorf("last_reported_at = %v, se esperaba %v", f.LastReportedAt, primero.ProcessedAt)
	}

	segundo := eventoDeReporte()
	segundo.ProcessedAt = primero.ProcessedAt.Add(48 * time.Hour)
	if res := reportarEvento(t, reputacion, segundo, id, 1); res != domain.ReportCounted {
		t.Fatalf("segundo reporte = %v, se esperaba ReportCounted", res)
	}
	f = leerRevision(t, db, id)
	if !f.UnderReviewSince.Equal(primero.ProcessedAt) {
		t.Errorf("under_review_since = %v, no debería moverse con el segundo reporte", f.UnderReviewSince)
	}
	if !f.LastReportedAt.Equal(segundo.ProcessedAt) {
		t.Errorf("last_reported_at = %v, se esperaba %v", f.LastReportedAt, segundo.ProcessedAt)
	}

	// Un duplicado no mueve nada.
	repetido := segundo
	repetido.ProcessedAt = segundo.ProcessedAt.Add(time.Hour)
	if res := reportarEvento(t, reputacion, repetido, id, 1); res != domain.ReportDuplicate {
		t.Fatalf("reporte repetido = %v, se esperaba ReportDuplicate", res)
	}
	if f = leerRevision(t, db, id); !f.LastReportedAt.Equal(segundo.ProcessedAt) {
		t.Errorf("un duplicado movió last_reported_at a %v", f.LastReportedAt)
	}
}

// Por debajo del umbral el reporte se cuenta y se anota la fecha, pero la cuenta
// no entra en revisión: under_review_since sigue nulo.
func TestIntegracionApplyReportBajoElUmbralNoMarcaLaRevision(t *testing.T) {
	db := baseConEsquemaAislado(t)
	_, reputacion := repositorioDeRevision(t, db)
	id := usuarioNuevo(t, db)

	if res := reportar(t, reputacion, id, 3); res != domain.ReportCounted {
		t.Fatalf("resultado = %v, se esperaba ReportCounted", res)
	}

	f := leerRevision(t, db, id)
	if f.UnderReviewSince != nil || f.AccountStatus != "ACTIVE" {
		t.Errorf("usuario = %+v, no debería estar en revisión", f)
	}
	if f.LastReportedAt == nil {
		t.Error("last_reported_at debería anotarse aunque no llegue al umbral")
	}
}

func TestIntegracionListCasesOrdenaDelMasViejoAlMasNuevoYSoloListaLosEnRevision(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo, _ := repositorioDeRevision(t, db)

	base := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	nuevo := usuarioNuevo(t, db)
	viejo := usuarioNuevo(t, db)
	medio := usuarioNuevo(t, db)
	activo := usuarioNuevo(t, db)
	sinFecha := usuarioNuevo(t, db)

	nuevoDesde, viejoDesde, medioDesde := base.Add(72*time.Hour), base, base.Add(24*time.Hour)
	enRevision(t, db, nuevo, 1, 0, &nuevoDesde)
	enRevision(t, db, viejo, 4, -30, &viejoDesde)
	enRevision(t, db, medio, 2, -10, &medioDesde)
	// Estaba en revisión antes de US-17: sin under_review_since, se ordena por la
	// creación de la cuenta (la más antigua de todas).
	enRevision(t, db, sinFecha, 1, 0, nil)
	creadoEn(t, db, sinFecha, base.Add(-240*time.Hour))
	creadoEn(t, db, viejo, base.Add(-480*time.Hour))
	creadoEn(t, db, medio, base.Add(-480*time.Hour))
	creadoEn(t, db, nuevo, base.Add(-480*time.Hour))
	if err := db.Exec(`UPDATE users SET last_reported_at = ? WHERE id = ?`, base.Add(100*time.Hour), viejo).Error; err != nil {
		t.Fatalf("no se pudo fijar last_reported_at: %v", err)
	}

	page, err := repo.ListCases(t.Context(), domain.AccountStatusUnderReview, 50, "")
	if err != nil {
		t.Fatalf("ListCases falló: %v", err)
	}

	got := make([]uuid.UUID, 0, len(page.Items))
	for _, it := range page.Items {
		got = append(got, it.UserID)
	}
	want := []uuid.UUID{sinFecha, viejo, medio, nuevo}
	if len(got) != len(want) {
		t.Fatalf("casos = %v, se esperaban %v (el usuario ACTIVE no debe aparecer: %s)", got, want, activo)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("orden = %v, se esperaba %v", got, want)
		}
	}
	if page.NextCursor != "" {
		t.Errorf("NextCursor = %q, se esperaba vacío en la última página", page.NextCursor)
	}

	c := page.Items[1]
	if c.AccountStatus != domain.AccountStatusUnderReview || c.ReportCount != 4 || c.ReputationScore != -30 {
		t.Errorf("caso = %+v", c)
	}
	if c.UnderReviewSince == nil || !c.UnderReviewSince.Equal(viejoDesde) || c.UnderReviewSince.Location() != time.UTC {
		t.Errorf("under_review_since = %v, se esperaba %v en UTC", c.UnderReviewSince, viejoDesde)
	}
	if c.LastReportedAt == nil || !c.LastReportedAt.Equal(base.Add(100*time.Hour)) {
		t.Errorf("last_reported_at = %v", c.LastReportedAt)
	}
	if page.Items[0].UnderReviewSince != nil || page.Items[0].LastReportedAt != nil {
		t.Errorf("el caso sin fechas las devolvió: %+v", page.Items[0])
	}
}

// Paginar de a dos recorre todos los casos exactamente una vez, en orden, también
// cuando varios comparten la misma fecha: el id desempata.
func TestIntegracionListCasesPaginaSinRepetirNiSaltearCasos(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo, _ := repositorioDeRevision(t, db)

	desde := time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)
	const total = 7
	ids := make(map[uuid.UUID]bool, total)
	for i := range total {
		id := usuarioNuevo(t, db)
		// Los tres primeros comparten fecha exacta.
		cuando := desde.Add(time.Duration(max(i-2, 0)) * time.Hour)
		enRevision(t, db, id, 1, 0, &cuando)
		ids[id] = true
	}

	var vistos []domain.ReviewCase
	cursor := ""
	for paginas := 0; ; paginas++ {
		if paginas > total {
			t.Fatal("la paginación no termina")
		}
		page, err := repo.ListCases(t.Context(), domain.AccountStatusUnderReview, 2, cursor)
		if err != nil {
			t.Fatalf("página %d: %v", paginas, err)
		}
		if len(page.Items) > 2 {
			t.Fatalf("la página %d tiene %d items, el límite era 2", paginas, len(page.Items))
		}
		vistos = append(vistos, page.Items...)
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}

	if len(vistos) != total {
		t.Fatalf("se recorrieron %d casos, se esperaban %d", len(vistos), total)
	}
	repetidos := map[uuid.UUID]bool{}
	for i, c := range vistos {
		if !ids[c.UserID] || repetidos[c.UserID] {
			t.Fatalf("caso %s inesperado o repetido", c.UserID)
		}
		repetidos[c.UserID] = true
		if i > 0 && vistos[i-1].UnderReviewSince.After(*c.UnderReviewSince) {
			t.Errorf("el caso %d está desordenado: %v después de %v", i, c.UnderReviewSince, vistos[i-1].UnderReviewSince)
		}
	}
}

// Una página exacta (tantos casos como el límite) no inventa una página siguiente.
func TestIntegracionListCasesConUnaPaginaExactaNoDevuelveCursor(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo, _ := repositorioDeRevision(t, db)
	for range 2 {
		id := usuarioNuevo(t, db)
		desde := time.Now().UTC()
		enRevision(t, db, id, 1, 0, &desde)
	}

	page, err := repo.ListCases(t.Context(), domain.AccountStatusUnderReview, 2, "")
	if err != nil {
		t.Fatalf("ListCases falló: %v", err)
	}
	if len(page.Items) != 2 || page.NextCursor != "" {
		t.Errorf("items = %d, cursor = %q; se esperaban 2 y vacío", len(page.Items), page.NextCursor)
	}
}

func TestIntegracionListCasesSinCasosDevuelveUnaListaVacia(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo, _ := repositorioDeRevision(t, db)
	usuarioNuevo(t, db)

	page, err := repo.ListCases(t.Context(), domain.AccountStatusUnderReview, 50, "")
	if err != nil {
		t.Fatalf("ListCases falló: %v", err)
	}
	if page.Items == nil || len(page.Items) != 0 || page.NextCursor != "" {
		t.Errorf("página = %+v, se esperaba una lista vacía no nula", page)
	}
}

func TestIntegracionListCasesRechazaUnCursorInvalidoYUnLimiteInvalido(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo, _ := repositorioDeRevision(t, db)

	if _, err := repo.ListCases(t.Context(), domain.AccountStatusUnderReview, 10, "basura"); !errors.Is(err, domain.ErrInvalidCursor) {
		t.Errorf("error = %v, se esperaba ErrInvalidCursor", err)
	}
	if _, err := repo.ListCases(t.Context(), domain.AccountStatusUnderReview, 0, ""); err == nil {
		t.Error("se esperaba un error con límite 0")
	}
}

// El desbloqueo, en una transacción: la cuenta vuelve a ACTIVE con report_count 0 y
// sin under_review_since, la reputación no cambia, queda la decisión y el evento
// user.status.changed (ACTIVE, MANUAL_UNBLOCK) pendiente en el outbox.
func TestIntegracionUnblockLevantaLaRevisionYRegistraDecisionYEvento(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo, _ := repositorioDeRevision(t, db)
	id := usuarioNuevo(t, db)
	desde := time.Now().UTC().Add(-time.Hour)
	enRevision(t, db, id, 3, -25, &desde)
	otro := usuarioNuevo(t, db)
	enRevision(t, db, otro, 2, 0, &desde)

	decision, evt := desbloqueo(t, id, "Revisada la evidencia: sin fraude", "ana.perez")
	if err := repo.Unblock(t.Context(), decision, evt); err != nil {
		t.Fatalf("Unblock falló: %v", err)
	}

	f := leerRevision(t, db, id)
	if f.AccountStatus != "ACTIVE" || f.ReportCount != 0 || f.UnderReviewSince != nil {
		t.Errorf("usuario = %+v, se esperaba ACTIVE, report_count 0 y sin under_review_since", f)
	}
	if f.ReputationScore != -25 {
		t.Errorf("reputation_score = %d, no debe cambiar (-25)", f.ReputationScore)
	}
	if o := leerRevision(t, db, otro); o.AccountStatus != "UNDER_REVIEW" || o.ReportCount != 2 {
		t.Errorf("el desbloqueo tocó a otro usuario: %+v", o)
	}

	var d reviewDecisionModel
	if err := db.Where("id = ?", decision.ID).Take(&d).Error; err != nil {
		t.Fatalf("no se encontró la decisión: %v", err)
	}
	if d.UserID != id || d.Decision != "UNBLOCK" || d.Reason != "Revisada la evidencia: sin fraude" || d.Operator != "ana.perez" {
		t.Errorf("decisión = %+v", d)
	}
	if !d.DecidedAt.Truncate(time.Microsecond).Equal(decision.DecidedAt.Truncate(time.Microsecond)) {
		t.Errorf("decided_at = %v, se esperaba %v", d.DecidedAt, decision.DecidedAt)
	}

	filas := leerOutbox(t, db)
	if len(filas) != 1 || filas[0].ID != evt.ID || filas[0].Type != "user.status.changed" || filas[0].Status != "pending" {
		t.Fatalf("outbox = %+v, se esperaba un user.status.changed pendiente", filas)
	}
	var payload map[string]string
	if err := json.Unmarshal(filas[0].Payload, &payload); err != nil {
		t.Fatalf("payload ilegible: %v", err)
	}
	if payload["user_id"] != id.String() || payload["account_status"] != "ACTIVE" || payload["reason"] != "MANUAL_UNBLOCK" {
		t.Errorf("payload = %v", payload)
	}
	if strings.Contains(string(filas[0].Payload), "ana.perez") || strings.Contains(string(filas[0].Payload), "evidencia") {
		t.Errorf("el payload del evento lleva el motivo o el operador: %s", filas[0].Payload)
	}
}

func TestIntegracionUnblockDeUnUsuarioInexistenteDevuelveNotFoundSinEscribirNada(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo, _ := repositorioDeRevision(t, db)

	decision, evt := desbloqueo(t, uuid.New(), "un motivo suficiente", "ana")
	if err := repo.Unblock(t.Context(), decision, evt); !errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("error = %v, se esperaba ErrUserNotFound", err)
	}

	if n := contarDecisiones(t, db); n != 0 {
		t.Errorf("review_decisions tiene %d filas, se esperaba 0", n)
	}
	if filas := leerOutbox(t, db); len(filas) != 0 {
		t.Errorf("outbox = %+v, se esperaba vacío", filas)
	}
}

func TestIntegracionUnblockDeUnUsuarioActivoDevuelveNotUnderReviewSinEscribirNada(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo, _ := repositorioDeRevision(t, db)
	id := usuarioNuevo(t, db)
	if err := db.Exec(`UPDATE users SET report_count = 2 WHERE id = ?`, id).Error; err != nil {
		t.Fatalf("no se pudo fijar report_count: %v", err)
	}

	decision, evt := desbloqueo(t, id, "un motivo suficiente", "ana")
	if err := repo.Unblock(t.Context(), decision, evt); !errors.Is(err, domain.ErrNotUnderReview) {
		t.Fatalf("error = %v, se esperaba ErrNotUnderReview", err)
	}

	if f := leerRevision(t, db, id); f.AccountStatus != "ACTIVE" || f.ReportCount != 2 {
		t.Errorf("usuario = %+v, no debería haber cambiado", f)
	}
	if n := contarDecisiones(t, db); n != 0 {
		t.Errorf("review_decisions tiene %d filas, se esperaba 0", n)
	}
	if filas := leerOutbox(t, db); len(filas) != 0 {
		t.Errorf("outbox = %+v, se esperaba vacío", filas)
	}
}

// Si el outbox falla, no queda nada hecho: la cuenta sigue en revisión y no hay
// decisión. Alert nunca se queda bloqueando a un usuario que ya figura ACTIVE, ni
// al revés.
func TestIntegracionUnblockSeDeshaceEntero(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo, _ := repositorioDeRevision(t, db)
	id := usuarioNuevo(t, db)
	desde := time.Now().UTC()
	enRevision(t, db, id, 3, -5, &desde)

	decision, evt := desbloqueo(t, id, "un motivo suficiente", "ana")
	// Un evento con el mismo id ya en el outbox hace fallar el INSERT del final.
	if err := db.Create(toOutboxModel(&evt)).Error; err != nil {
		t.Fatalf("no se pudo sembrar el outbox: %v", err)
	}

	err := repo.Unblock(t.Context(), decision, evt)
	if err == nil {
		t.Fatal("se esperaba un error por el outbox")
	}
	if errors.Is(err, domain.ErrUserNotFound) || errors.Is(err, domain.ErrNotUnderReview) {
		t.Fatalf("error = %v, no debería ser un error de negocio", err)
	}

	if f := leerRevision(t, db, id); f.AccountStatus != "UNDER_REVIEW" || f.ReportCount != 3 || f.UnderReviewSince == nil {
		t.Errorf("usuario = %+v, la transacción debía deshacerse", f)
	}
	if n := contarDecisiones(t, db); n != 0 {
		t.Errorf("review_decisions tiene %d filas, se esperaba 0", n)
	}
}

func TestIntegracionUnblockExigeElEventoDeCambioDeEstado(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo, _ := repositorioDeRevision(t, db)
	id := usuarioNuevo(t, db)
	desde := time.Now().UTC()
	enRevision(t, db, id, 1, 0, &desde)

	decision, _ := desbloqueo(t, id, "un motivo suficiente", "ana")
	if err := repo.Unblock(t.Context(), decision, domain.OutboxEvent{}); err == nil {
		t.Fatal("se esperaba un error sin el user.status.changed")
	}
	if f := leerRevision(t, db, id); f.AccountStatus != "UNDER_REVIEW" {
		t.Errorf("usuario = %+v, no debería haber cambiado", f)
	}
}

// Dos desbloqueos concurrentes de la misma cuenta: uno gana y el resto recibe
// ErrNotUnderReview. Queda una sola decisión y un solo evento.
func TestIntegracionUnblockConcurrenteDeLaMismaCuentaSoloUnoGana(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo, _ := repositorioDeRevision(t, db)
	id := usuarioNuevo(t, db)
	desde := time.Now().UTC()
	enRevision(t, db, id, 2, 0, &desde)

	const intentos = 8
	resultados := make([]error, intentos)
	var wg sync.WaitGroup
	for i := range intentos {
		wg.Add(1)
		go func() {
			defer wg.Done()
			decision, evt := desbloqueo(t, id, "un motivo suficiente", "ana")
			resultados[i] = repo.Unblock(t.Context(), decision, evt)
		}()
	}
	wg.Wait()

	var ganadores, rechazados int
	for _, err := range resultados {
		switch {
		case err == nil:
			ganadores++
		case errors.Is(err, domain.ErrNotUnderReview):
			rechazados++
		default:
			t.Errorf("error inesperado: %v", err)
		}
	}
	if ganadores != 1 || rechazados != intentos-1 {
		t.Errorf("ganadores = %d, rechazados = %d; se esperaban 1 y %d", ganadores, rechazados, intentos-1)
	}
	if n := contarDecisiones(t, db); n != 1 {
		t.Errorf("review_decisions tiene %d filas, se esperaba 1", n)
	}
	if filas := leerOutbox(t, db); len(filas) != 1 {
		t.Errorf("outbox tiene %d filas, se esperaba 1", len(filas))
	}
}

// Al desbloquear, report_count vuelve a 0: el próximo reporte abre un caso nuevo
// (con umbral 1) en lugar de sumarse a los viejos, y publica de nuevo.
func TestIntegracionElReporteSiguienteAlDesbloqueoAbreUnCasoNuevo(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo, reputacion := repositorioDeRevision(t, db)
	id := usuarioNuevo(t, db)

	viejo := eventoDeReporte()
	viejo.ProcessedAt = time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	if res := reportarEvento(t, reputacion, viejo, id, 1); res != domain.ReportEscalated {
		t.Fatalf("primer reporte = %v, se esperaba ReportEscalated", res)
	}
	decision, evt := desbloqueo(t, id, "un motivo suficiente", "ana")
	if err := repo.Unblock(t.Context(), decision, evt); err != nil {
		t.Fatalf("Unblock falló: %v", err)
	}

	nuevo := eventoDeReporte()
	nuevo.ProcessedAt = time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	if res := reportarEvento(t, reputacion, nuevo, id, 1); res != domain.ReportEscalated {
		t.Fatalf("reporte tras el desbloqueo = %v, se esperaba ReportEscalated", res)
	}

	f := leerRevision(t, db, id)
	if f.AccountStatus != "UNDER_REVIEW" || f.ReportCount != 1 {
		t.Errorf("usuario = %+v, se esperaba UNDER_REVIEW con report_count 1", f)
	}
	if f.UnderReviewSince == nil || !f.UnderReviewSince.Equal(nuevo.ProcessedAt) {
		t.Errorf("under_review_since = %v, se esperaba %v (caso nuevo)", f.UnderReviewSince, nuevo.ProcessedAt)
	}
	// Dos escaladas y un desbloqueo: tres user.status.changed.
	if filas := leerOutbox(t, db); len(filas) != 3 {
		t.Errorf("outbox tiene %d filas, se esperaban 3", len(filas))
	}
}

func TestIntegracionListDecisionsDevuelveElHistorialDeLaCuentaDelMasNuevoAlMasViejo(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo, _ := repositorioDeRevision(t, db)
	id, otro := usuarioNuevo(t, db), usuarioNuevo(t, db)

	base := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	for i, motivo := range []string{"primer desbloqueo", "segundo desbloqueo", "tercer desbloqueo"} {
		d := domain.ReviewDecision{
			ID: uuid.New(), UserID: id, Decision: "UNBLOCK", Reason: motivo + " del caso", Operator: "ana",
			DecidedAt: base.Add(time.Duration(i) * 24 * time.Hour),
		}
		if err := db.Create(toReviewDecisionModel(d)).Error; err != nil {
			t.Fatalf("no se pudo sembrar la decisión: %v", err)
		}
	}
	ajena := domain.ReviewDecision{ID: uuid.New(), UserID: otro, Decision: "UNBLOCK", Reason: "decisión de otra cuenta", Operator: "bruno", DecidedAt: base}
	if err := db.Create(toReviewDecisionModel(ajena)).Error; err != nil {
		t.Fatalf("no se pudo sembrar la decisión ajena: %v", err)
	}

	got, err := repo.ListDecisions(t.Context(), id)
	if err != nil {
		t.Fatalf("ListDecisions falló: %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("decisiones = %d, se esperaban 3", len(got))
	}
	for i, motivo := range []string{"tercer desbloqueo del caso", "segundo desbloqueo del caso", "primer desbloqueo del caso"} {
		if got[i].Reason != motivo || got[i].UserID != id || got[i].Operator != "ana" || got[i].Decision != "UNBLOCK" {
			t.Errorf("decisión %d = %+v, se esperaba %q", i, got[i], motivo)
		}
	}
	if got[0].DecidedAt.Location() != time.UTC {
		t.Errorf("decided_at no está en UTC: %v", got[0].DecidedAt.Location())
	}

	vacio, err := repo.ListDecisions(t.Context(), uuid.New())
	if err != nil || vacio == nil || len(vacio) != 0 {
		t.Errorf("sin historial = (%v, %v), se esperaba una lista vacía no nula", vacio, err)
	}
}

// El motivo más largo que admite el contrato (500 caracteres multibyte) entra en
// la columna, y el operador de 100 también.
func TestIntegracionUnblockGuardaElMotivoYElOperadorEnSuLargoMaximo(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo, _ := repositorioDeRevision(t, db)
	id := usuarioNuevo(t, db)
	desde := time.Now().UTC()
	enRevision(t, db, id, 1, 0, &desde)

	motivo, operador := strings.Repeat("ñ", 500), strings.Repeat("ó", 100)
	decision, evt := desbloqueo(t, id, motivo, operador)
	if err := repo.Unblock(t.Context(), decision, evt); err != nil {
		t.Fatalf("Unblock falló con los largos máximos: %v", err)
	}

	got, err := repo.ListDecisions(t.Context(), id)
	if err != nil || len(got) != 1 || got[0].Reason != motivo || got[0].Operator != operador {
		t.Fatalf("historial = (%d decisiones, %v); el motivo o el operador no se guardaron enteros", len(got), err)
	}
}

// La base rechaza una decisión que se pase del largo del contrato, aunque el
// servicio ya la validó: defensa en profundidad.
func TestIntegracionLaBaseRechazaUnMotivoDeMasDe500Caracteres(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repositorioDeRevision(t, db)
	id := usuarioNuevo(t, db)

	d := domain.ReviewDecision{ID: uuid.New(), UserID: id, Decision: "UNBLOCK", Reason: strings.Repeat("a", 501), Operator: "ana", DecidedAt: time.Now()}
	if err := db.Create(toReviewDecisionModel(d)).Error; err == nil {
		t.Error("se esperaba que la base rechazara un motivo de 501 caracteres")
	}
}

// La baja de la cuenta se lleva su historial de decisiones (clave foránea con
// ON DELETE CASCADE), y la clave foránea impide decisiones de una cuenta que no
// existe.
func TestIntegracionLaBajaDeLaCuentaBorraSuHistorialDeDecisiones(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repositorioDeRevision(t, db)
	id, otro := usuarioNuevo(t, db), usuarioNuevo(t, db)

	for _, u := range []uuid.UUID{id, otro} {
		d := domain.ReviewDecision{ID: uuid.New(), UserID: u, Decision: "UNBLOCK", Reason: "un motivo suficiente", Operator: "ana", DecidedAt: time.Now()}
		if err := db.Create(toReviewDecisionModel(d)).Error; err != nil {
			t.Fatalf("no se pudo sembrar la decisión: %v", err)
		}
	}

	if err := db.Exec(`DELETE FROM users WHERE id = ?`, id).Error; err != nil {
		t.Fatalf("no se pudo borrar el usuario: %v", err)
	}

	if n := contarDecisiones(t, db); n != 1 {
		t.Errorf("review_decisions tiene %d filas, se esperaba 1 (la de la otra cuenta)", n)
	}

	huerfana := domain.ReviewDecision{ID: uuid.New(), UserID: uuid.New(), Decision: "UNBLOCK", Reason: "un motivo suficiente", Operator: "ana", DecidedAt: time.Now()}
	if err := db.Create(toReviewDecisionModel(huerfana)).Error; err == nil {
		t.Error("la clave foránea debería rechazar una decisión de una cuenta inexistente")
	}
}

// Con la base sin responder (plazo vencido), las tres operaciones devuelven
// ErrDatabaseUnavailable, que la capa HTTP traduce a 503 con Retry-After, y no
// dejan nada hecho.
func TestIntegracionRevisionConLaBaseNoDisponibleDevuelveErrDatabaseUnavailable(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo, _ := repositorioDeRevision(t, db)
	id := usuarioNuevo(t, db)
	desde := time.Now().UTC()
	enRevision(t, db, id, 2, 0, &desde)

	vencido, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()

	if _, err := repo.ListCases(vencido, domain.AccountStatusUnderReview, 10, ""); !errors.Is(err, domain.ErrDatabaseUnavailable) {
		t.Errorf("ListCases: error = %v, se esperaba ErrDatabaseUnavailable", err)
	}
	decision, evt := desbloqueo(t, id, "un motivo suficiente", "ana")
	if err := repo.Unblock(vencido, decision, evt); !errors.Is(err, domain.ErrDatabaseUnavailable) {
		t.Errorf("Unblock: error = %v, se esperaba ErrDatabaseUnavailable", err)
	}
	if _, err := repo.ListDecisions(vencido, id); !errors.Is(err, domain.ErrDatabaseUnavailable) {
		t.Errorf("ListDecisions: error = %v, se esperaba ErrDatabaseUnavailable", err)
	}

	if f := leerRevision(t, db, id); f.AccountStatus != "UNDER_REVIEW" || f.ReportCount != 2 {
		t.Errorf("usuario = %+v, no debería haber cambiado", f)
	}
}

// Si la migración de review_decisions no puede correr, el servicio no arranca:
// NewReviewRepository devuelve el error en vez de seguir con la tabla a medias.
func TestIntegracionNewReviewRepositoryFallaSiLaBaseNoResponde(t *testing.T) {
	if _, err := NewReviewRepository(t.Context(), nil); err == nil {
		t.Error("se esperaba un error sin conexión")
	}

	db := baseConEsquemaAislado(t)
	repositorioDeReportes(t, db)
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("no se pudo obtener la conexión: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("no se pudo cerrar la conexión: %v", err)
	}

	if _, err := NewReviewRepository(t.Context(), db); err == nil {
		t.Error("se esperaba un error de migración con la conexión cerrada")
	}
}
