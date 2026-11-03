//go:build integration

// Pruebas de integración contra un PostgreSQL real de la baja de cuenta y el
// hold de retención (US-11): el esquema legal_hold, AccountDeletionRepository,
// la herencia de sanciones en UserRepository.Create y el barrido de
// LegalHoldRepository. Mismas reglas que outbox_migration_test.go: requieren
// TEST_DATABASE_URL, fallan si falta y trabajan en un esquema propio que se
// borra al terminar.
//
// Una excepción: legal_hold es un esquema fijo del contrato, no se puede
// aislar por prueba con search_path. Cada prueba usa identificadores únicos y
// borra sus propios holds al terminar. DestroyExpired borra todos los holds
// vencidos de la base, así que estas pruebas no admiten una base con holds
// reales (es una base descartable) ni correr en paralelo.
package postgres

import (
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

// repos agrupa los repositorios que toca la baja, ya migrados.
type repos struct {
	db        *gorm.DB
	users     *UserRepository
	deletions *AccountDeletionRepository
	holds     *LegalHoldRepository
}

func nuevosRepos(t *testing.T) repos {
	t.Helper()

	db := baseConEsquemaAislado(t)
	ctx := t.Context()

	users, err := NewUserRepository(ctx, db)
	if err != nil {
		t.Fatalf("NewUserRepository: %v", err)
	}
	if _, err := NewSessionRepository(ctx, db); err != nil {
		t.Fatalf("NewSessionRepository: %v", err)
	}
	if _, err := NewOutboxRepository(ctx, db); err != nil {
		t.Fatalf("NewOutboxRepository: %v", err)
	}
	deletions, err := NewAccountDeletionRepository(ctx, db)
	if err != nil {
		t.Fatalf("NewAccountDeletionRepository: %v", err)
	}
	holds, err := NewLegalHoldRepository(ctx, db)
	if err != nil {
		t.Fatalf("NewLegalHoldRepository: %v", err)
	}
	return repos{db: db, users: users, deletions: deletions, holds: holds}
}

// limpiarHolds borra los holds de la prueba de la tabla compartida legal_hold.
func limpiarHolds(t *testing.T, db *gorm.DB, userIDs ...uuid.UUID) {
	t.Helper()

	t.Cleanup(func() {
		for _, id := range userIDs {
			_ = db.Exec(`DELETE FROM legal_hold.user_holds WHERE user_id = ?`, id).Error
		}
	})
}

func usuarioConEstado(t *testing.T, db *gorm.DB, status domain.AccountStatus, score, reports int) *domain.User {
	t.Helper()

	u, err := domain.NewUser(uuid.NewString()+"@example.com", "hash-argon2", uuid.NewString(), "dni-cifrado-at-rest", time.Now())
	if err != nil {
		t.Fatalf("no se pudo armar el usuario: %v", err)
	}
	u.AccountStatus, u.ReputationScore, u.ReportCount = status, score, reports
	if err := db.Create(toModel(u)).Error; err != nil {
		t.Fatalf("no se pudo insertar el usuario: %v", err)
	}
	return u
}

func conSesiones(t *testing.T, db *gorm.DB, userID uuid.UUID, cantidad int) {
	t.Helper()

	for i := 0; i < cantidad; i++ {
		s, err := domain.NewSession(userID, uuid.NewString(), time.Now().Add(time.Hour), time.Now())
		if err != nil {
			t.Fatalf("no se pudo armar la sesión: %v", err)
		}
		if err := db.Create(toSessionModel(s)).Error; err != nil {
			t.Fatalf("no se pudo insertar la sesión: %v", err)
		}
	}
}

// unaBaja arma la baja de userID con los dos eventos del contrato.
func unaBaja(t *testing.T, userID uuid.UUID, destroyEn time.Duration) domain.AccountDeletion {
	t.Helper()

	baja := time.Now().UTC().Truncate(time.Microsecond)
	revoked, err := domain.NewOutboxEvent("user.sessions.revoked", map[string]string{
		"user_id": userID.String(), "reason": string(domain.SessionsRevokedReasonAccountDeleted),
	})
	if err != nil {
		t.Fatalf("no se pudo armar el evento: %v", err)
	}
	revoked.CreatedAt = baja
	deleted, err := domain.NewOutboxEvent(domain.EventTypeUserDeleted, map[string]string{
		"user_id": userID.String(), "deleted_at": baja.Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatalf("no se pudo armar el evento: %v", err)
	}
	deleted.CreatedAt = baja.Add(time.Millisecond)

	return domain.AccountDeletion{
		UserID:    userID,
		DNISealed: "sellado-base64-" + userID.String(),
		DeletedAt: baja,
		DestroyAt: baja.Add(destroyEn),
		Events:    []domain.OutboxEvent{revoked, deleted},
	}
}

type filaHold struct {
	UserID          uuid.UUID
	DNISealed       string
	DeletedAt       time.Time
	DestroyAt       time.Time
	DNIHMAC         *string `gorm:"column:dni_hmac"`
	AccountStatus   *string
	ReputationScore *int
	ReportCount     *int
}

func leerHold(t *testing.T, db *gorm.DB, userID uuid.UUID) (filaHold, bool) {
	t.Helper()

	var filas []filaHold
	if err := db.Raw(`SELECT user_id, dni_sealed, deleted_at, destroy_at, dni_hmac, account_status, reputation_score, report_count
		FROM legal_hold.user_holds WHERE user_id = ?`, userID).Scan(&filas).Error; err != nil {
		t.Fatalf("no se pudo leer el hold: %v", err)
	}
	if len(filas) == 0 {
		return filaHold{}, false
	}
	return filas[0], true
}

func contar(t *testing.T, db *gorm.DB, consulta string, args ...any) int64 {
	t.Helper()

	var n int64
	if err := db.Raw(consulta, args...).Scan(&n).Error; err != nil {
		t.Fatalf("no se pudo contar (%s): %v", consulta, err)
	}
	return n
}

func existeUsuario(t *testing.T, db *gorm.DB, id uuid.UUID) bool {
	t.Helper()
	return contar(t, db, `SELECT count(*) FROM users WHERE id = ?`, id) == 1
}

// ── Migración ────────────────────────────────────────────────────────────────

type columnaHold struct {
	ColumnName string
	DataType   string
	IsNullable string
}

// El esquema y la tabla son los del contrato: columnas, tipos y nulabilidad.
func TestIntegracionMigracionDeLegalHoldCumpleElContrato(t *testing.T) {
	r := nuevosRepos(t)

	var cols []columnaHold
	if err := r.db.Raw(`SELECT column_name, data_type, is_nullable FROM information_schema.columns
		WHERE table_schema = 'legal_hold' AND table_name = 'user_holds'`).Scan(&cols).Error; err != nil {
		t.Fatalf("no se pudo leer information_schema: %v", err)
	}

	want := map[string]columnaHold{
		"user_id":          {DataType: "uuid", IsNullable: "NO"},
		"dni_sealed":       {DataType: "text", IsNullable: "NO"},
		"deleted_at":       {DataType: "timestamp with time zone", IsNullable: "NO"},
		"destroy_at":       {DataType: "timestamp with time zone", IsNullable: "NO"},
		"dni_hmac":         {DataType: "character varying", IsNullable: "YES"},
		"account_status":   {DataType: "character varying", IsNullable: "YES"},
		"reputation_score": {DataType: "integer", IsNullable: "YES"},
		"report_count":     {DataType: "integer", IsNullable: "YES"},
	}
	got := map[string]columnaHold{}
	for _, c := range cols {
		got[c.ColumnName] = c
	}
	if len(got) != len(want) {
		t.Errorf("la tabla tiene %d columnas, se esperaban %d: %v", len(got), len(want), got)
	}
	for nombre, w := range want {
		g, ok := got[nombre]
		if !ok {
			t.Errorf("falta la columna %s", nombre)
			continue
		}
		if g.DataType != w.DataType || g.IsNullable != w.IsNullable {
			t.Errorf("%s: tipo=%s nulable=%s, se esperaba tipo=%s nulable=%s", nombre, g.DataType, g.IsNullable, w.DataType, w.IsNullable)
		}
	}

	var largo int
	if err := r.db.Raw(`SELECT character_maximum_length FROM information_schema.columns
		WHERE table_schema = 'legal_hold' AND table_name = 'user_holds' AND column_name = 'dni_hmac'`).Scan(&largo).Error; err != nil || largo != 64 {
		t.Errorf("dni_hmac debe ser varchar(64): largo=%d err=%v", largo, err)
	}

	if n := contar(t, r.db, `SELECT count(*) FROM pg_constraint c
		JOIN pg_class t ON t.oid = c.conrelid JOIN pg_namespace n ON n.oid = t.relnamespace
		WHERE n.nspname = 'legal_hold' AND t.relname = 'user_holds' AND c.contype = 'p'`); n != 1 {
		t.Errorf("user_id debe ser la clave primaria (restricciones primarias: %d)", n)
	}

	for _, idx := range []string{"idx_user_holds_destroy_at", "idx_user_holds_dni_hmac"} {
		if n := contar(t, r.db, `SELECT count(*) FROM pg_indexes WHERE schemaname = 'legal_hold' AND tablename = 'user_holds' AND indexname = ?`, idx); n != 1 {
			t.Errorf("falta el índice %s", idx)
		}
	}
}

// La migración corre en cada arranque: repetirla no falla ni toca los holds.
func TestIntegracionMigracionDeLegalHoldEsIdempotente(t *testing.T) {
	r := nuevosRepos(t)
	u := usuarioConEstado(t, r.db, domain.AccountStatusUnderReview, -10, 2)
	limpiarHolds(t, r.db, u.ID)
	if err := r.deletions.DeleteAccount(t.Context(), unaBaja(t, u.ID, time.Hour)); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	for i := 0; i < 3; i++ {
		if err := ensureLegalHoldSchema(t.Context(), r.db); err != nil {
			t.Fatalf("la migración repetida %d falló: %v", i+1, err)
		}
	}
	if _, ok := leerHold(t, r.db, u.ID); !ok {
		t.Error("la migración repetida borró un hold")
	}
}

// Con la tabla ya creada la migración no ejecuta ningún DDL: en producción la
// crea el DBA con el rol propio del esquema, y el servicio solo necesita
// permisos de DML. Se prueba con un índice que falta: si la migración corriera
// sus CREATE INDEX IF NOT EXISTS, lo volvería a crear.
func TestIntegracionMigracionDeLegalHoldNoEjecutaDDLSiLaTablaExiste(t *testing.T) {
	r := nuevosRepos(t)
	const indice = "idx_user_holds_destroy_at"
	if err := r.db.Exec("DROP INDEX legal_hold." + indice).Error; err != nil {
		t.Fatalf("no se pudo quitar el índice: %v", err)
	}
	t.Cleanup(func() {
		_ = r.db.Exec("CREATE INDEX IF NOT EXISTS " + indice + " ON legal_hold.user_holds (destroy_at)").Error
	})

	if err := ensureLegalHoldSchema(t.Context(), r.db); err != nil {
		t.Fatalf("la migración falló con la tabla ya creada: %v", err)
	}

	if n := contar(t, r.db, `SELECT count(*) FROM pg_indexes WHERE schemaname = 'legal_hold' AND indexname = ?`, indice); n != 0 {
		t.Error("la migración ejecutó DDL aunque la tabla ya existía")
	}
}

// Varias réplicas arrancando a la vez no chocan en el catálogo.
func TestIntegracionMigracionDeLegalHoldEsSeguraEnConcurrencia(t *testing.T) {
	r := nuevosRepos(t)

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- ensureLegalHoldSchema(t.Context(), r.db)
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Errorf("migración concurrente: %v", err)
		}
	}
}

// ── Baja ─────────────────────────────────────────────────────────────────────

func TestIntegracionBajaCorrecta(t *testing.T) {
	r := nuevosRepos(t)
	u := usuarioConEstado(t, r.db, domain.AccountStatusActive, 0, 0)
	otro := usuarioConEstado(t, r.db, domain.AccountStatusActive, 0, 0)
	conSesiones(t, r.db, u.ID, 3)
	conSesiones(t, r.db, otro.ID, 2)
	limpiarHolds(t, r.db, u.ID)
	baja := unaBaja(t, u.ID, 1095*24*time.Hour)

	if err := r.deletions.DeleteAccount(t.Context(), baja); err != nil {
		t.Fatalf("DeleteAccount falló: %v", err)
	}

	if existeUsuario(t, r.db, u.ID) {
		t.Error("la fila de users sigue existiendo")
	}
	if n := contar(t, r.db, `SELECT count(*) FROM sessions WHERE user_id = ?`, u.ID); n != 0 {
		t.Errorf("quedaron %d sesiones del usuario", n)
	}

	// No toca a nadie más.
	if !existeUsuario(t, r.db, otro.ID) || contar(t, r.db, `SELECT count(*) FROM sessions WHERE user_id = ?`, otro.ID) != 2 {
		t.Error("la baja tocó a otro usuario")
	}

	hold, ok := leerHold(t, r.db, u.ID)
	if !ok {
		t.Fatal("no se creó el hold")
	}
	if hold.DNISealed != baja.DNISealed {
		t.Errorf("dni_sealed = %q, se esperaba %q", hold.DNISealed, baja.DNISealed)
	}
	if !hold.DeletedAt.Equal(baja.DeletedAt) || !hold.DestroyAt.Equal(baja.DestroyAt) {
		t.Errorf("fechas = %v / %v, se esperaban %v / %v", hold.DeletedAt, hold.DestroyAt, baja.DeletedAt, baja.DestroyAt)
	}
	if hold.DNIHMAC != nil || hold.AccountStatus != nil || hold.ReputationScore != nil || hold.ReportCount != nil {
		t.Errorf("una cuenta limpia no deja sanción en el hold: %+v", hold)
	}
}

// Los dos eventos quedan encolados, pendientes, en la misma transacción.
func TestIntegracionBajaEncolaLosDosEventos(t *testing.T) {
	r := nuevosRepos(t)
	u := usuarioConEstado(t, r.db, domain.AccountStatusActive, 0, 0)
	limpiarHolds(t, r.db, u.ID)
	baja := unaBaja(t, u.ID, time.Hour)

	if err := r.deletions.DeleteAccount(t.Context(), baja); err != nil {
		t.Fatalf("DeleteAccount falló: %v", err)
	}

	filas := leerOutbox(t, r.db)
	if len(filas) != 2 {
		t.Fatalf("outbox tiene %d eventos, se esperaban 2", len(filas))
	}
	if filas[0].Type != "user.sessions.revoked" || filas[1].Type != "user.deleted" {
		t.Errorf("tipos = %q y %q", filas[0].Type, filas[1].Type)
	}
	for i, f := range filas {
		if f.ID != baja.Events[i].ID || f.Status != "pending" {
			t.Errorf("evento %d: id=%v estado=%q, se esperaba %v pendiente", i, f.ID, f.Status, baja.Events[i].ID)
		}
		var payload map[string]string
		if err := json.Unmarshal(f.Payload, &payload); err != nil || payload["user_id"] != u.ID.String() {
			t.Errorf("evento %d: payload = %s (err %v)", i, f.Payload, err)
		}
	}
}

// "Penalizada" son las tres señales del contrato; cada una guarda la sanción
// completa con el mismo Blind Index que users.dni_hashed.
func TestIntegracionBajaDeCuentaPenalizadaGuardaLaSancion(t *testing.T) {
	casos := map[string]struct {
		status  domain.AccountStatus
		score   int
		reports int
	}{
		"en revisión":       {domain.AccountStatusUnderReview, 0, 1},
		"solo reportes":     {domain.AccountStatusActive, 0, 2},
		"solo reputación":   {domain.AccountStatusActive, -10, 0},
		"revisión con todo": {domain.AccountStatusUnderReview, -40, 4},
	}

	for nombre, caso := range casos {
		t.Run(nombre, func(t *testing.T) {
			r := nuevosRepos(t)
			u := usuarioConEstado(t, r.db, caso.status, caso.score, caso.reports)
			limpiarHolds(t, r.db, u.ID)

			if err := r.deletions.DeleteAccount(t.Context(), unaBaja(t, u.ID, time.Hour)); err != nil {
				t.Fatalf("DeleteAccount falló: %v", err)
			}

			hold, ok := leerHold(t, r.db, u.ID)
			if !ok {
				t.Fatal("no se creó el hold")
			}
			if hold.DNIHMAC == nil || *hold.DNIHMAC != u.DNIHashed {
				t.Errorf("dni_hmac = %v, se esperaba el Blind Index del DNI %q", hold.DNIHMAC, u.DNIHashed)
			}
			if hold.AccountStatus == nil || *hold.AccountStatus != string(caso.status) {
				t.Errorf("account_status = %v, se esperaba %q", hold.AccountStatus, caso.status)
			}
			if hold.ReputationScore == nil || *hold.ReputationScore != caso.score {
				t.Errorf("reputation_score = %v, se esperaba %d", hold.ReputationScore, caso.score)
			}
			if hold.ReportCount == nil || *hold.ReportCount != caso.reports {
				t.Errorf("report_count = %v, se esperaba %d", hold.ReportCount, caso.reports)
			}
		})
	}
}

// Atomicidad: si falla el outbox, no se borra nada. El evento repetido (misma
// clave primaria que uno ya encolado) hace fallar el último paso de la
// transacción, cuando el hold, las sesiones y el usuario ya se tocaron.
func TestIntegracionBajaSiFallaElOutboxNoSeBorraNada(t *testing.T) {
	r := nuevosRepos(t)
	u := usuarioConEstado(t, r.db, domain.AccountStatusUnderReview, -10, 2)
	conSesiones(t, r.db, u.ID, 2)
	limpiarHolds(t, r.db, u.ID)
	baja := unaBaja(t, u.ID, time.Hour)

	// El segundo evento de la baja choca con una fila que ya está en el outbox.
	previo := domain.OutboxEvent{ID: baja.Events[1].ID, Type: "user.deleted", Payload: []byte(`{}`), CreatedAt: time.Now().UTC()}
	if err := r.db.Create(toOutboxModel(&previo)).Error; err != nil {
		t.Fatalf("no se pudo sembrar el evento que choca: %v", err)
	}

	err := r.deletions.DeleteAccount(t.Context(), baja)

	if err == nil {
		t.Fatal("se esperaba un error al fallar el outbox")
	}
	if !existeUsuario(t, r.db, u.ID) {
		t.Error("se borró al usuario aunque falló el outbox")
	}
	if n := contar(t, r.db, `SELECT count(*) FROM sessions WHERE user_id = ?`, u.ID); n != 2 {
		t.Errorf("sesiones = %d, se esperaban las 2 originales", n)
	}
	if _, ok := leerHold(t, r.db, u.ID); ok {
		t.Error("quedó un hold aunque falló el outbox")
	}
	// Solo queda la fila sembrada: el primer evento de la baja también se deshizo.
	if filas := leerOutbox(t, r.db); len(filas) != 1 {
		t.Errorf("outbox tiene %d eventos, se esperaba solo el sembrado", len(filas))
	}
}

// Atomicidad desde el otro extremo: si falla el hold (ya existe uno para ese
// usuario), no se borra al usuario ni se encola nada.
func TestIntegracionBajaSiFallaElHoldNoSeBorraNada(t *testing.T) {
	r := nuevosRepos(t)
	u := usuarioConEstado(t, r.db, domain.AccountStatusActive, 0, 0)
	conSesiones(t, r.db, u.ID, 1)
	limpiarHolds(t, r.db, u.ID)
	if err := r.db.Exec(`INSERT INTO legal_hold.user_holds (user_id, dni_sealed, deleted_at, destroy_at)
		VALUES (?, 'previo', now(), now() + interval '1 day')`, u.ID).Error; err != nil {
		t.Fatalf("no se pudo sembrar el hold: %v", err)
	}

	if err := r.deletions.DeleteAccount(t.Context(), unaBaja(t, u.ID, time.Hour)); err == nil {
		t.Fatal("se esperaba un error por el hold repetido")
	}

	if !existeUsuario(t, r.db, u.ID) || contar(t, r.db, `SELECT count(*) FROM sessions WHERE user_id = ?`, u.ID) != 1 {
		t.Error("se borró algo aunque falló el hold")
	}
	if filas := leerOutbox(t, r.db); len(filas) != 0 {
		t.Errorf("se encolaron %d eventos aunque falló el hold", len(filas))
	}
	if hold, _ := leerHold(t, r.db, u.ID); hold.DNISealed != "previo" {
		t.Errorf("el hold previo se modificó: %+v", hold)
	}
}

func TestIntegracionBajaDeUnUsuarioInexistente(t *testing.T) {
	r := nuevosRepos(t)
	fantasma := uuid.New()
	limpiarHolds(t, r.db, fantasma)

	err := r.deletions.DeleteAccount(t.Context(), unaBaja(t, fantasma, time.Hour))

	if !errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("error = %v, se esperaba ErrUserNotFound", err)
	}
	if _, ok := leerHold(t, r.db, fantasma); ok {
		t.Error("se creó un hold para un usuario que no existe")
	}
	if filas := leerOutbox(t, r.db); len(filas) != 0 {
		t.Errorf("se encolaron %d eventos para un usuario que no existe", len(filas))
	}
}

// Dos bajas simultáneas del mismo usuario: una gana y la otra ve al usuario
// inexistente. Un solo hold, y los eventos una sola vez.
func TestIntegracionDosBajasConcurrentesDelMismoUsuario(t *testing.T) {
	r := nuevosRepos(t)
	u := usuarioConEstado(t, r.db, domain.AccountStatusActive, 0, 0)
	limpiarHolds(t, r.db, u.ID)

	var wg sync.WaitGroup
	resultados := make(chan error, 2)
	for i := 0; i < 2; i++ {
		baja := unaBaja(t, u.ID, time.Hour)
		wg.Add(1)
		go func() {
			defer wg.Done()
			resultados <- r.deletions.DeleteAccount(t.Context(), baja)
		}()
	}
	wg.Wait()
	close(resultados)

	var exitos, inexistentes int
	for err := range resultados {
		switch {
		case err == nil:
			exitos++
		case errors.Is(err, domain.ErrUserNotFound):
			inexistentes++
		default:
			t.Errorf("error inesperado: %v", err)
		}
	}
	if exitos != 1 || inexistentes != 1 {
		t.Errorf("éxitos=%d inexistentes=%d, se esperaba 1 y 1", exitos, inexistentes)
	}
	if n := contar(t, r.db, `SELECT count(*) FROM legal_hold.user_holds WHERE user_id = ?`, u.ID); n != 1 {
		t.Errorf("holds = %d, se esperaba 1", n)
	}
	if filas := leerOutbox(t, r.db); len(filas) != 2 {
		t.Errorf("outbox tiene %d eventos, se esperaban 2", len(filas))
	}
}

// La sanción del hold sale de la fila que se borra, leída dentro de la
// transacción, y no de una copia que el servicio haya leído antes: lo que se
// penalizó hasta la baja queda en el hold.
func TestIntegracionBajaGuardaLaSancionVigenteDeLaFila(t *testing.T) {
	r := nuevosRepos(t)
	u := usuarioConEstado(t, r.db, domain.AccountStatusActive, 0, 0)
	limpiarHolds(t, r.db, u.ID)

	// Un reporte confirmado antes de la baja tiene que verse en el hold: el
	// hold lee la fila con SELECT ... FOR UPDATE, no una copia vieja del servicio.
	if err := r.db.Exec(`UPDATE users SET report_count = 3, reputation_score = -20 WHERE id = ?`, u.ID).Error; err != nil {
		t.Fatalf("no se pudo penalizar al usuario: %v", err)
	}

	if err := r.deletions.DeleteAccount(t.Context(), unaBaja(t, u.ID, time.Hour)); err != nil {
		t.Fatalf("DeleteAccount falló: %v", err)
	}

	hold, ok := leerHold(t, r.db, u.ID)
	if !ok || hold.ReportCount == nil || *hold.ReportCount != 3 || hold.ReputationScore == nil || *hold.ReputationScore != -20 {
		t.Errorf("el hold no refleja la sanción vigente al momento de la baja: %+v", hold)
	}
}

// ── Herencia en el alta ──────────────────────────────────────────────────────

// sembrarHold deja un hold con sanción para un DNI, como lo dejaría una baja.
func sembrarHold(t *testing.T, db *gorm.DB, dniHMAC string, status domain.AccountStatus, score, reports int, destroyEn time.Duration) uuid.UUID {
	t.Helper()

	id := uuid.New()
	limpiarHolds(t, db, id)
	err := db.Exec(`INSERT INTO legal_hold.user_holds
		(user_id, dni_sealed, deleted_at, destroy_at, dni_hmac, account_status, reputation_score, report_count)
		VALUES (?, 'sellado', now(), now() + (? * interval '1 second'), ?, ?, ?, ?)`,
		id, destroyEn.Seconds(), dniHMAC, string(status), score, reports).Error
	if err != nil {
		t.Fatalf("no se pudo sembrar el hold: %v", err)
	}
	return id
}

func usuarioParaAlta(t *testing.T, dniHMAC string) *domain.User {
	t.Helper()

	u, err := domain.NewUser(uuid.NewString()+"@example.com", "hash-argon2", dniHMAC, "dni-cifrado", time.Now())
	if err != nil {
		t.Fatalf("no se pudo armar el usuario: %v", err)
	}
	return u
}

func eventoHeredado(t *testing.T, userID uuid.UUID) domain.OutboxEvent {
	t.Helper()

	evt, err := domain.NewUserStatusChangedOutboxEvent(userID, domain.AccountStatusUnderReview, domain.UserStatusReasonInheritedOnSignup)
	if err != nil {
		t.Fatalf("no se pudo armar el evento: %v", err)
	}
	evt.CreatedAt = time.Now().UTC()
	return evt
}

func TestIntegracionAltaConHoldEnRevisionHeredaLaSancion(t *testing.T) {
	r := nuevosRepos(t)
	dni := uuid.NewString()
	holdID := sembrarHold(t, r.db, dni, domain.AccountStatusUnderReview, -30, 2, time.Hour)
	u := usuarioParaAlta(t, dni)
	evt := eventoHeredado(t, u.ID)

	if err := r.users.Create(t.Context(), u, evt); err != nil {
		t.Fatalf("Create falló: %v", err)
	}

	// El usuario que devuelve Create y el que quedó en la base coinciden.
	if u.AccountStatus != domain.AccountStatusUnderReview || u.ReputationScore != -30 || u.ReportCount != 2 {
		t.Errorf("el usuario devuelto = %q/%d/%d", u.AccountStatus, u.ReputationScore, u.ReportCount)
	}
	f := leerReputacion(t, r.db, u.ID)
	if f.AccountStatus != "UNDER_REVIEW" || f.ReputationScore != -30 || f.ReportCount != 2 {
		t.Errorf("la cuenta nueva quedó con %+v", f)
	}

	// La sanción se borra del hold, y también el dni_hmac que la vinculaba.
	hold, ok := leerHold(t, r.db, holdID)
	if !ok {
		t.Fatal("el hold no debe borrarse: sigue su plazo de retención")
	}
	if hold.DNIHMAC != nil || hold.AccountStatus != nil || hold.ReputationScore != nil || hold.ReportCount != nil {
		t.Errorf("la sanción debe anularse en el hold: %+v", hold)
	}
	if hold.DNISealed != "sellado" {
		t.Errorf("el DNI sellado no se toca: %q", hold.DNISealed)
	}

	// Queda en revisión, así que sale user.status.changed con el motivo.
	filas := leerOutbox(t, r.db)
	if len(filas) != 1 || filas[0].Type != domain.EventTypeUserStatusChanged || filas[0].ID != evt.ID {
		t.Fatalf("outbox = %+v, se esperaba el user.status.changed heredado", filas)
	}
	var payload map[string]string
	if err := json.Unmarshal(filas[0].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["user_id"] != u.ID.String() || payload["account_status"] != "UNDER_REVIEW" || payload["reason"] != "INHERITED_ON_SIGNUP" {
		t.Errorf("payload = %v", payload)
	}
}

// Con sanción pero sin revisión (solo reputación o reportes) hereda los números
// y no hay transición de estado que anunciar.
func TestIntegracionAltaConHoldActivoHeredaSinPublicar(t *testing.T) {
	r := nuevosRepos(t)
	dni := uuid.NewString()
	sembrarHold(t, r.db, dni, domain.AccountStatusActive, -10, 1, time.Hour)
	u := usuarioParaAlta(t, dni)

	if err := r.users.Create(t.Context(), u, eventoHeredado(t, u.ID)); err != nil {
		t.Fatalf("Create falló: %v", err)
	}

	f := leerReputacion(t, r.db, u.ID)
	if f.AccountStatus != "ACTIVE" || f.ReputationScore != -10 || f.ReportCount != 1 {
		t.Errorf("la cuenta nueva quedó con %+v", f)
	}
	if filas := leerOutbox(t, r.db); len(filas) != 0 {
		t.Errorf("no hubo transición a revisión: no debe encolarse nada, hay %d eventos", len(filas))
	}
}

// Sin hold con sanción para ese DNI el alta nace limpia y no encola nada.
func TestIntegracionAltaSinHoldNaceLimpia(t *testing.T) {
	r := nuevosRepos(t)
	u := usuarioParaAlta(t, uuid.NewString())

	if err := r.users.Create(t.Context(), u, eventoHeredado(t, u.ID)); err != nil {
		t.Fatalf("Create falló: %v", err)
	}

	f := leerReputacion(t, r.db, u.ID)
	if f.AccountStatus != "ACTIVE" || f.ReputationScore != 0 || f.ReportCount != 0 {
		t.Errorf("la cuenta nueva quedó con %+v, se esperaba limpia", f)
	}
	if filas := leerOutbox(t, r.db); len(filas) != 0 {
		t.Errorf("se encolaron %d eventos en un alta limpia", len(filas))
	}
}

// Un hold de una cuenta que no estaba penalizada no deja nada que heredar.
func TestIntegracionAltaConHoldSinSancionNaceLimpia(t *testing.T) {
	r := nuevosRepos(t)
	u := usuarioConEstado(t, r.db, domain.AccountStatusActive, 0, 0)
	limpiarHolds(t, r.db, u.ID)
	if err := r.deletions.DeleteAccount(t.Context(), unaBaja(t, u.ID, time.Hour)); err != nil {
		t.Fatalf("DeleteAccount falló: %v", err)
	}
	// Los eventos de la baja no son parte de lo que se prueba acá.
	if err := r.db.Exec(`DELETE FROM outbox_events`).Error; err != nil {
		t.Fatal(err)
	}

	nuevo := usuarioParaAlta(t, u.DNIHashed)
	if err := r.users.Create(t.Context(), nuevo, eventoHeredado(t, nuevo.ID)); err != nil {
		t.Fatalf("Create falló: %v", err)
	}

	f := leerReputacion(t, r.db, nuevo.ID)
	if f.AccountStatus != "ACTIVE" || f.ReputationScore != 0 || f.ReportCount != 0 {
		t.Errorf("el registro nuevo debía arrancar limpio, quedó con %+v", f)
	}
	if filas := leerOutbox(t, r.db); len(filas) != 0 {
		t.Errorf("se encolaron %d eventos en un alta limpia", len(filas))
	}
}

// Un hold vencido no se hereda: el plazo de retención ya pasó.
func TestIntegracionAltaConHoldVencidoNoHereda(t *testing.T) {
	r := nuevosRepos(t)
	dni := uuid.NewString()
	holdID := sembrarHold(t, r.db, dni, domain.AccountStatusUnderReview, -30, 2, -time.Hour)
	u := usuarioParaAlta(t, dni)

	if err := r.users.Create(t.Context(), u, eventoHeredado(t, u.ID)); err != nil {
		t.Fatalf("Create falló: %v", err)
	}

	f := leerReputacion(t, r.db, u.ID)
	if f.AccountStatus != "ACTIVE" || f.ReputationScore != 0 || f.ReportCount != 0 {
		t.Errorf("la cuenta nueva quedó con %+v, se esperaba limpia", f)
	}
	hold, _ := leerHold(t, r.db, holdID)
	if hold.DNIHMAC == nil || hold.AccountStatus == nil {
		t.Errorf("un hold vencido no se toca en el alta, lo destruye el barrido: %+v", hold)
	}
}

// La sanción no se hereda dos veces: tras el primer alta, otra cuenta con el
// mismo DNI nace limpia.
func TestIntegracionLaSancionNoSeHeredaDosVeces(t *testing.T) {
	r := nuevosRepos(t)
	dni := uuid.NewString()
	sembrarHold(t, r.db, dni, domain.AccountStatusUnderReview, -30, 2, time.Hour)

	primera := usuarioParaAlta(t, dni)
	if err := r.users.Create(t.Context(), primera, eventoHeredado(t, primera.ID)); err != nil {
		t.Fatalf("primer alta: %v", err)
	}
	if primera.AccountStatus != domain.AccountStatusUnderReview {
		t.Fatalf("la primera cuenta debía heredar la revisión, quedó %q", primera.AccountStatus)
	}

	// La cuenta desaparece sin dejar un hold nuevo (la limpieza de otra prueba,
	// o un borrado manual), y el mismo DNI se registra otra vez.
	if err := r.db.Exec(`DELETE FROM users WHERE id = ?`, primera.ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := r.db.Exec(`DELETE FROM outbox_events`).Error; err != nil {
		t.Fatal(err)
	}

	segunda := usuarioParaAlta(t, dni)
	if err := r.users.Create(t.Context(), segunda, eventoHeredado(t, segunda.ID)); err != nil {
		t.Fatalf("segunda alta: %v", err)
	}

	f := leerReputacion(t, r.db, segunda.ID)
	if f.AccountStatus != "ACTIVE" || f.ReputationScore != 0 || f.ReportCount != 0 {
		t.Errorf("la sanción se heredó dos veces: la segunda cuenta quedó con %+v", f)
	}
	if filas := leerOutbox(t, r.db); len(filas) != 0 {
		t.Errorf("la segunda alta no debe publicar nada, hay %d eventos", len(filas))
	}
}

// Un alta que falla no consume la sanción: el reclamo se deshace con el resto de
// la transacción, y el reintento hereda.
func TestIntegracionUnAltaQueFallaNoConsumeElHold(t *testing.T) {
	r := nuevosRepos(t)
	dni := uuid.NewString()
	holdID := sembrarHold(t, r.db, dni, domain.AccountStatusUnderReview, -30, 2, time.Hour)

	existente := usuarioConEstado(t, r.db, domain.AccountStatusActive, 0, 0)

	fallida := usuarioParaAlta(t, dni)
	fallida.Email = existente.Email // choca con el índice único de email
	err := r.users.Create(t.Context(), fallida, eventoHeredado(t, fallida.ID))
	if !errors.Is(err, domain.ErrDuplicateUser) {
		t.Fatalf("error = %v, se esperaba ErrDuplicateUser", err)
	}

	hold, _ := leerHold(t, r.db, holdID)
	if hold.DNIHMAC == nil || hold.AccountStatus == nil || *hold.AccountStatus != "UNDER_REVIEW" {
		t.Fatalf("el alta fallida consumió la sanción del hold: %+v", hold)
	}
	if fallida.AccountStatus != domain.AccountStatusActive {
		t.Errorf("el usuario del alta fallida no debe quedar modificado: %q", fallida.AccountStatus)
	}

	reintento := usuarioParaAlta(t, dni)
	if err := r.users.Create(t.Context(), reintento, eventoHeredado(t, reintento.ID)); err != nil {
		t.Fatalf("el reintento falló: %v", err)
	}
	if reintento.AccountStatus != domain.AccountStatusUnderReview {
		t.Errorf("el reintento debía heredar la revisión, quedó %q", reintento.AccountStatus)
	}
}

// Si la sanción deja la cuenta en revisión y falta el evento, el alta entera se
// deshace: nunca una cuenta en revisión que Alert no se entera.
func TestIntegracionAltaSinEventoParaLaRevisionHeredadaSeDeshace(t *testing.T) {
	r := nuevosRepos(t)
	dni := uuid.NewString()
	holdID := sembrarHold(t, r.db, dni, domain.AccountStatusUnderReview, -30, 2, time.Hour)
	u := usuarioParaAlta(t, dni)

	if err := r.users.Create(t.Context(), u, domain.OutboxEvent{}); err == nil {
		t.Fatal("se esperaba un error sin el evento de la revisión heredada")
	}

	if existeUsuario(t, r.db, u.ID) {
		t.Error("se creó la cuenta aunque no pudo anunciarse su revisión")
	}
	if hold, _ := leerHold(t, r.db, holdID); hold.AccountStatus == nil {
		t.Error("se consumió la sanción aunque el alta se deshizo")
	}
}

// Atomicidad de la herencia con el outbox: si falla el evento, ni el usuario ni
// el reclamo del hold quedan.
func TestIntegracionAltaSiFallaElOutboxNoQuedaNada(t *testing.T) {
	r := nuevosRepos(t)
	dni := uuid.NewString()
	holdID := sembrarHold(t, r.db, dni, domain.AccountStatusUnderReview, -30, 2, time.Hour)
	u := usuarioParaAlta(t, dni)
	evt := eventoHeredado(t, u.ID)
	previo := domain.OutboxEvent{ID: evt.ID, Type: "user.status.changed", Payload: []byte(`{}`), CreatedAt: time.Now().UTC()}
	if err := r.db.Create(toOutboxModel(&previo)).Error; err != nil {
		t.Fatalf("no se pudo sembrar el evento que choca: %v", err)
	}

	if err := r.users.Create(t.Context(), u, evt); err == nil {
		t.Fatal("se esperaba un error al fallar el outbox")
	}

	if existeUsuario(t, r.db, u.ID) {
		t.Error("se creó la cuenta aunque falló el outbox")
	}
	if hold, _ := leerHold(t, r.db, holdID); hold.AccountStatus == nil || hold.DNIHMAC == nil {
		t.Errorf("se consumió la sanción aunque falló el outbox: %+v", hold)
	}
}

// Dos altas simultáneas con el mismo DNI: gana una, que hereda; la otra choca
// con el índice único. La sanción se consume una sola vez y el evento sale una
// sola vez.
func TestIntegracionDosAltasConcurrentesConElMismoDNIHeredanUnaVez(t *testing.T) {
	r := nuevosRepos(t)
	dni := uuid.NewString()
	sembrarHold(t, r.db, dni, domain.AccountStatusUnderReview, -30, 2, time.Hour)

	var wg sync.WaitGroup
	resultados := make(chan error, 2)
	usuarios := []*domain.User{usuarioParaAlta(t, dni), usuarioParaAlta(t, dni)}
	for _, u := range usuarios {
		evt := eventoHeredado(t, u.ID)
		wg.Add(1)
		go func() {
			defer wg.Done()
			resultados <- r.users.Create(t.Context(), u, evt)
		}()
	}
	wg.Wait()
	close(resultados)

	var exitos, duplicados int
	for err := range resultados {
		switch {
		case err == nil:
			exitos++
		case errors.Is(err, domain.ErrDuplicateUser):
			duplicados++
		default:
			t.Errorf("error inesperado: %v", err)
		}
	}
	if exitos != 1 || duplicados != 1 {
		t.Fatalf("éxitos=%d duplicados=%d, se esperaba 1 y 1", exitos, duplicados)
	}
	if n := contar(t, r.db, `SELECT count(*) FROM users WHERE dni_hashed = ?`, dni); n != 1 {
		t.Errorf("cuentas con ese DNI = %d, se esperaba 1", n)
	}
	if n := contar(t, r.db, `SELECT count(*) FROM users WHERE dni_hashed = ? AND account_status = 'UNDER_REVIEW'`, dni); n != 1 {
		t.Errorf("la cuenta que ganó debía heredar la revisión")
	}
	if filas := leerOutbox(t, r.db); len(filas) != 1 {
		t.Errorf("outbox tiene %d eventos, se esperaba 1", len(filas))
	}
}

// El camino completo: baja de una cuenta penalizada y registro posterior con el
// mismo DNI.
func TestIntegracionBajaYRegistroPosteriorDeLaMismaPersona(t *testing.T) {
	r := nuevosRepos(t)
	u := usuarioConEstado(t, r.db, domain.AccountStatusUnderReview, -20, 3)
	limpiarHolds(t, r.db, u.ID)
	if err := r.deletions.DeleteAccount(t.Context(), unaBaja(t, u.ID, time.Hour)); err != nil {
		t.Fatalf("DeleteAccount falló: %v", err)
	}
	if err := r.db.Exec(`DELETE FROM outbox_events`).Error; err != nil {
		t.Fatal(err)
	}

	nuevo := usuarioParaAlta(t, u.DNIHashed)
	if err := r.users.Create(t.Context(), nuevo, eventoHeredado(t, nuevo.ID)); err != nil {
		t.Fatalf("el registro posterior falló: %v", err)
	}

	f := leerReputacion(t, r.db, nuevo.ID)
	if f.AccountStatus != "UNDER_REVIEW" || f.ReputationScore != -20 || f.ReportCount != 3 {
		t.Errorf("el registro posterior debía heredar la sanción, quedó con %+v", f)
	}
	if nuevo.ID == u.ID {
		t.Error("la cuenta nueva reutilizó el id de la anterior")
	}
	if filas := leerOutbox(t, r.db); len(filas) != 1 || filas[0].Type != domain.EventTypeUserStatusChanged {
		t.Errorf("outbox = %+v, se esperaba el user.status.changed heredado", filas)
	}
}

// ── Lectura y barrido ────────────────────────────────────────────────────────

func TestIntegracionFindByID(t *testing.T) {
	r := nuevosRepos(t)
	u := usuarioConEstado(t, r.db, domain.AccountStatusUnderReview, -5, 1)

	got, err := r.users.FindByID(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("FindByID falló: %v", err)
	}
	if got.ID != u.ID || got.Email != u.Email || got.PasswordHash != u.PasswordHash ||
		got.DNIEncrypted != u.DNIEncrypted || got.AccountStatus != u.AccountStatus ||
		got.ReputationScore != -5 || got.ReportCount != 1 {
		t.Errorf("usuario = %+v, se esperaba %+v", got, u)
	}

	if _, err := r.users.FindByID(t.Context(), uuid.New()); !errors.Is(err, domain.ErrUserNotFound) {
		t.Errorf("error = %v, se esperaba ErrUserNotFound", err)
	}
}

func sembrarVencidos(t *testing.T, db *gorm.DB, cantidad int, vencidoHace time.Duration) []uuid.UUID {
	t.Helper()

	ids := make([]uuid.UUID, 0, cantidad)
	for i := 0; i < cantidad; i++ {
		id := uuid.New()
		ids = append(ids, id)
		err := db.Exec(`INSERT INTO legal_hold.user_holds (user_id, dni_sealed, deleted_at, destroy_at)
			VALUES (?, 'sellado', now() - interval '4 years', now() - (? * interval '1 second'))`, id, vencidoHace.Seconds()).Error
		if err != nil {
			t.Fatalf("no se pudo sembrar el hold: %v", err)
		}
	}
	limpiarHolds(t, db, ids...)
	return ids
}

// Destruye solo lo vencido (destroy_at <= now) y deja lo vigente.
func TestIntegracionDestroyExpiredBorraSoloLosVencidos(t *testing.T) {
	r := nuevosRepos(t)
	vencidos := sembrarVencidos(t, r.db, 3, time.Hour)
	vigentes := sembrarVencidos(t, r.db, 2, -time.Hour) // vencen dentro de una hora

	n, err := r.holds.DestroyExpired(t.Context(), time.Now(), 100)
	if err != nil {
		t.Fatalf("DestroyExpired falló: %v", err)
	}

	if n != 3 {
		t.Errorf("destruidos = %d, se esperaban 3", n)
	}
	for _, id := range vencidos {
		if _, ok := leerHold(t, r.db, id); ok {
			t.Errorf("el hold vencido %v sigue existiendo", id)
		}
	}
	for _, id := range vigentes {
		if _, ok := leerHold(t, r.db, id); !ok {
			t.Errorf("el hold vigente %v se destruyó", id)
		}
	}
}

// El corte es inclusivo: destroy_at == now ya se destruye (destroy_at <= now).
func TestIntegracionDestroyExpiredEsInclusivoEnElLimite(t *testing.T) {
	r := nuevosRepos(t)
	id := uuid.New()
	limpiarHolds(t, r.db, id)
	corte := time.Now().UTC().Truncate(time.Microsecond)
	if err := r.db.Exec(`INSERT INTO legal_hold.user_holds (user_id, dni_sealed, deleted_at, destroy_at) VALUES (?, 'sellado', ?, ?)`,
		id, corte.AddDate(-3, 0, 0), corte).Error; err != nil {
		t.Fatal(err)
	}

	n, err := r.holds.DestroyExpired(t.Context(), corte, 10)
	if err != nil || n != 1 {
		t.Fatalf("destruidos=%d err=%v, se esperaba 1 y nil", n, err)
	}
	if _, ok := leerHold(t, r.db, id); ok {
		t.Error("el hold en el límite exacto no se destruyó")
	}

	// Un microsegundo antes del corte, todavía no.
	id2 := uuid.New()
	limpiarHolds(t, r.db, id2)
	if err := r.db.Exec(`INSERT INTO legal_hold.user_holds (user_id, dni_sealed, deleted_at, destroy_at) VALUES (?, 'sellado', ?, ?)`,
		id2, corte.AddDate(-3, 0, 0), corte.Add(time.Microsecond)).Error; err != nil {
		t.Fatal(err)
	}
	if n, err := r.holds.DestroyExpired(t.Context(), corte, 10); err != nil || n != 0 {
		t.Errorf("destruidos=%d err=%v, se esperaba 0 y nil", n, err)
	}
}

// El límite acota cada sentencia: se destruye de a lotes.
func TestIntegracionDestroyExpiredRespetaElLimite(t *testing.T) {
	r := nuevosRepos(t)
	ids := sembrarVencidos(t, r.db, 5, time.Hour)

	n, err := r.holds.DestroyExpired(t.Context(), time.Now(), 2)
	if err != nil || n != 2 {
		t.Fatalf("destruidos=%d err=%v, se esperaba 2 y nil", n, err)
	}
	quedan := 0
	for _, id := range ids {
		if _, ok := leerHold(t, r.db, id); ok {
			quedan++
		}
	}
	if quedan != 3 {
		t.Errorf("quedan %d holds, se esperaban 3", quedan)
	}
}

// Los holds más viejos se destruyen primero.
func TestIntegracionDestroyExpiredDestruyeLosMasViejosPrimero(t *testing.T) {
	r := nuevosRepos(t)
	viejo := sembrarVencidos(t, r.db, 1, 48*time.Hour)[0]
	reciente := sembrarVencidos(t, r.db, 1, time.Hour)[0]

	if n, err := r.holds.DestroyExpired(t.Context(), time.Now(), 1); err != nil || n != 1 {
		t.Fatalf("destruidos=%d err=%v", n, err)
	}

	if _, ok := leerHold(t, r.db, viejo); ok {
		t.Error("el hold más viejo debía destruirse primero")
	}
	if _, ok := leerHold(t, r.db, reciente); !ok {
		t.Error("el hold más reciente no debía destruirse todavía")
	}
}

// Varias réplicas barriendo a la vez reparten el trabajo: cada hold se destruye
// una sola vez y nadie se bloquea esperando a otro.
func TestIntegracionDestroyExpiredEsSeguroConVariasReplicas(t *testing.T) {
	r := nuevosRepos(t)
	sembrarVencidos(t, r.db, 40, time.Hour)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var total int64
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				n, err := r.holds.DestroyExpired(t.Context(), time.Now(), 5)
				if err != nil {
					t.Errorf("DestroyExpired falló: %v", err)
					return
				}
				mu.Lock()
				total += n
				mu.Unlock()
				if n < 5 {
					return
				}
			}
		}()
	}
	wg.Wait()

	if total != 40 {
		t.Errorf("entre todas destruyeron %d holds, se esperaban 40", total)
	}
}

func TestIntegracionDestroyExpiredRechazaUnLimiteInvalido(t *testing.T) {
	r := nuevosRepos(t)

	for _, limite := range []int{0, -1} {
		if _, err := r.holds.DestroyExpired(t.Context(), time.Now(), limite); err == nil {
			t.Errorf("con límite %d se esperaba un error", limite)
		}
	}
}

// El hold nunca guarda el DNI en claro: solo el sellado y, si estaba
// penalizada, el Blind Index.
func TestIntegracionElHoldNoGuardaElDNIEnClaro(t *testing.T) {
	r := nuevosRepos(t)
	u := usuarioConEstado(t, r.db, domain.AccountStatusUnderReview, -1, 1)
	limpiarHolds(t, r.db, u.ID)

	if err := r.deletions.DeleteAccount(t.Context(), unaBaja(t, u.ID, time.Hour)); err != nil {
		t.Fatalf("DeleteAccount falló: %v", err)
	}

	var fila string
	if err := r.db.Raw(`SELECT h::text FROM legal_hold.user_holds h WHERE user_id = ?`, u.ID).Scan(&fila).Error; err != nil {
		t.Fatal(err)
	}
	for _, prohibido := range []string{u.Email, u.PasswordHash, u.DNIEncrypted} {
		if strings.Contains(fila, prohibido) {
			t.Errorf("el hold contiene %q: %s", prohibido, fila)
		}
	}
}
