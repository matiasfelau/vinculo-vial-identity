//go:build integration

// Pruebas de integración contra un PostgreSQL real de la baja de cuenta y la
// herencia de sanciones (US-11): la tabla sanction_carryovers,
// AccountDeletionRepository, la herencia en UserRepository.Create, el barrido de
// SanctionCarryoverRepository y la migración desde el esquema de retención
// anterior. Mismas reglas que outbox_migration_test.go: requieren
// TEST_DATABASE_URL, fallan si falta y trabajan en un esquema propio que se
// borra al terminar.
//
// Una excepción: el esquema de retención anterior es un esquema fijo, no se
// puede aislar por prueba con search_path. Solo lo crean las pruebas de
// migración, que lo borran al terminar, así que no admiten una base con datos
// reales (es una base descartable) ni correr en paralelo.
package postgres

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	pgdriver "gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// repos agrupa los repositorios que toca la baja, ya migrados.
type repos struct {
	db         *gorm.DB
	users      *UserRepository
	deletions  *AccountDeletionRepository
	carryovers *SanctionCarryoverRepository
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
	carryovers, err := NewSanctionCarryoverRepository(ctx, db)
	if err != nil {
		t.Fatalf("NewSanctionCarryoverRepository: %v", err)
	}
	return repos{db: db, users: users, deletions: deletions, carryovers: carryovers}
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
		s, err := domain.NewSession(userID, uuid.NewString(), time.Now().Add(time.Hour), time.Now(), time.Now())
		if err != nil {
			t.Fatalf("no se pudo armar la sesión: %v", err)
		}
		if err := db.Create(toSessionModel(s)).Error; err != nil {
			t.Fatalf("no se pudo insertar la sesión: %v", err)
		}
	}
}

// unaBaja arma la baja de userID con los dos eventos del contrato; la herencia de
// su sanción vence dentro de herenciaEn.
func unaBaja(t *testing.T, userID uuid.UUID, herenciaEn time.Duration) domain.AccountDeletion {
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
		UserID:             userID,
		DeletedAt:          baja,
		CarryoverExpiresAt: baja.Add(herenciaEn),
		Events:             []domain.OutboxEvent{revoked, deleted},
	}
}

func leerSancion(t *testing.T, db *gorm.DB, dniHMAC string) (domain.SanctionCarryover, bool) {
	t.Helper()

	var filas []sanctionCarryoverModel
	if err := db.Raw(`SELECT dni_hmac, account_status, reputation_score, report_count, created_at, expires_at
		FROM sanction_carryovers WHERE dni_hmac = ?`, dniHMAC).Scan(&filas).Error; err != nil {
		t.Fatalf("no se pudo leer la sanción: %v", err)
	}
	if len(filas) == 0 {
		return domain.SanctionCarryover{}, false
	}
	return filas[0].toDomain(), true
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

func sancionesGuardadas(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	return contar(t, db, `SELECT count(*) FROM sanction_carryovers`)
}

// ── Migración ────────────────────────────────────────────────────────────────

type columnaTabla struct {
	ColumnName string
	DataType   string
	IsNullable string
}

// La tabla es la del contrato: columnas, tipos y nulabilidad.
func TestIntegracionMigracionDeSanctionCarryoversCumpleElContrato(t *testing.T) {
	r := nuevosRepos(t)

	var cols []columnaTabla
	if err := r.db.Raw(`SELECT column_name, data_type, is_nullable FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'sanction_carryovers'`).Scan(&cols).Error; err != nil {
		t.Fatalf("no se pudo leer information_schema: %v", err)
	}

	want := map[string]columnaTabla{
		"dni_hmac":         {DataType: "character varying", IsNullable: "NO"},
		"account_status":   {DataType: "character varying", IsNullable: "NO"},
		"reputation_score": {DataType: "integer", IsNullable: "NO"},
		"report_count":     {DataType: "integer", IsNullable: "NO"},
		"created_at":       {DataType: "timestamp with time zone", IsNullable: "NO"},
		"expires_at":       {DataType: "timestamp with time zone", IsNullable: "NO"},
	}
	got := map[string]columnaTabla{}
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
	if _, ok := got["user_id"]; ok {
		t.Error("la tabla no debe llevar user_id: la sanción se vincula con el DNI y nada más")
	}

	var largo int
	if err := r.db.Raw(`SELECT character_maximum_length FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'sanction_carryovers' AND column_name = 'dni_hmac'`).Scan(&largo).Error; err != nil || largo != 64 {
		t.Errorf("dni_hmac debe ser varchar(64): largo=%d err=%v", largo, err)
	}

	if n := contar(t, r.db, `SELECT count(*) FROM pg_constraint c
		JOIN pg_class t ON t.oid = c.conrelid JOIN pg_namespace n ON n.oid = t.relnamespace
		JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY (c.conkey)
		WHERE n.nspname = current_schema() AND t.relname = 'sanction_carryovers' AND c.contype = 'p' AND a.attname = 'dni_hmac'`); n != 1 {
		t.Errorf("dni_hmac debe ser la clave primaria (coincidencias: %d)", n)
	}

	if n := contar(t, r.db, `SELECT count(*) FROM pg_indexes WHERE schemaname = current_schema()
		AND tablename = 'sanction_carryovers' AND indexname = 'idx_sanction_carryovers_expires_at'`); n != 1 {
		t.Error("falta el índice de expires_at")
	}
}

// La migración corre en cada arranque: repetirla no falla ni toca las sanciones.
func TestIntegracionMigracionDeSanctionCarryoversEsIdempotente(t *testing.T) {
	r := nuevosRepos(t)
	u := usuarioConEstado(t, r.db, domain.AccountStatusUnderReview, -10, 2)
	if err := r.deletions.DeleteAccount(t.Context(), unaBaja(t, u.ID, time.Hour)); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	for i := 0; i < 3; i++ {
		if err := ensureSanctionCarryovers(t.Context(), r.db); err != nil {
			t.Fatalf("la migración repetida %d falló: %v", i+1, err)
		}
	}
	if _, ok := leerSancion(t, r.db, u.DNIHashed); !ok {
		t.Error("la migración repetida borró una sanción")
	}
}

// Varias réplicas arrancando a la vez no chocan en el catálogo.
func TestIntegracionMigracionDeSanctionCarryoversEsSeguraEnConcurrencia(t *testing.T) {
	db := baseConEsquemaAislado(t)

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- ensureSanctionCarryovers(t.Context(), db)
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

// Con la tabla ya creada por el DBA, el servicio arranca con un rol que solo
// tiene permisos de DML: la migración no necesita DDL. Es lo que documenta el
// README para los entornos donde el rol de la aplicación no puede crear objetos.
func TestIntegracionLaMigracionNoNecesitaDDLSiLaTablaYaExiste(t *testing.T) {
	r := nuevosRepos(t)
	var esquema string
	if err := r.db.Raw(`SELECT current_schema()`).Scan(&esquema).Error; err != nil {
		t.Fatal(err)
	}
	rol := "svc_sin_ddl_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	const clave = "clave-de-prueba"
	for _, sentencia := range []string{
		`CREATE ROLE ` + rol + ` LOGIN PASSWORD '` + clave + `'`,
		`GRANT USAGE ON SCHEMA ` + esquema + ` TO ` + rol,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON sanction_carryovers TO ` + rol,
	} {
		if err := r.db.Exec(sentencia).Error; err != nil {
			t.Fatalf("no se pudo preparar el rol (%s): %v", sentencia, err)
		}
	}
	t.Cleanup(func() {
		_ = r.db.Exec(`DROP OWNED BY ` + rol).Error
		_ = r.db.Exec(`DROP ROLE IF EXISTS ` + rol).Error
	})

	u, err := url.Parse(os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatalf("TEST_DATABASE_URL inválida: %v", err)
	}
	u.User = url.UserPassword(rol, clave)
	q := u.Query()
	q.Set("search_path", esquema)
	u.RawQuery = q.Encode()
	svcDB, err := gorm.Open(pgdriver.Open(u.String()), &gorm.Config{})
	if err != nil {
		t.Fatalf("no se pudo conectar con el rol del servicio: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := svcDB.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})

	repo, err := NewSanctionCarryoverRepository(t.Context(), svcDB)
	if err != nil {
		t.Fatalf("el servicio no arrancó con un rol sin DDL y la tabla ya creada: %v", err)
	}
	sembrarSancion(t, r.db, uuid.NewString(), domain.AccountStatusUnderReview, -1, 1, -time.Hour)
	if n, err := repo.DeleteExpired(t.Context(), time.Now(), 10); err != nil || n != 1 {
		t.Errorf("borradas=%d err=%v, se esperaba 1 y nil con permisos de DML", n, err)
	}
}

// ── Migración desde el esquema de retención anterior ─────────────────────────

// esquemaAnterior es el DDL con que la Rama B de US-11 creó el registro de
// retención que reemplazó el Audit Service.
const esquemaAnterior = `
CREATE SCHEMA legal_hold;
CREATE TABLE legal_hold.user_holds (
	user_id          uuid PRIMARY KEY,
	dni_sealed       text        NOT NULL,
	deleted_at       timestamptz NOT NULL,
	destroy_at       timestamptz NOT NULL,
	dni_hmac         varchar(64),
	account_status   varchar(32),
	reputation_score integer,
	report_count     integer
);`

// conEsquemaAnterior crea el esquema anterior en la base de prueba y lo borra al
// terminar, haya migrado o no.
func conEsquemaAnterior(t *testing.T, db *gorm.DB) {
	t.Helper()

	if err := db.Exec(esquemaAnterior).Error; err != nil {
		t.Fatalf("no se pudo crear el esquema anterior: %v", err)
	}
	t.Cleanup(func() { _ = db.Exec(`DROP SCHEMA IF EXISTS legal_hold CASCADE`).Error })
}

// holdAnterior inserta un hold del esquema anterior. dniHMAC vacío es un hold sin
// sanción (cuenta limpia, o sanción ya heredada).
func holdAnterior(t *testing.T, db *gorm.DB, dniHMAC string, status string, score, reports int, destroyEn time.Duration) (deleted, destroy time.Time) {
	t.Helper()

	deleted = time.Now().UTC().Truncate(time.Microsecond).AddDate(-1, 0, 0)
	destroy = time.Now().UTC().Truncate(time.Microsecond).Add(destroyEn)
	var hmac, st *string
	var sc, rc *int
	if dniHMAC != "" {
		hmac, st, sc, rc = &dniHMAC, &status, &score, &reports
	}
	if err := db.Exec(`INSERT INTO legal_hold.user_holds
		(user_id, dni_sealed, deleted_at, destroy_at, dni_hmac, account_status, reputation_score, report_count)
		VALUES (?, 'sellado', ?, ?, ?, ?, ?, ?)`, uuid.New(), deleted, destroy, hmac, st, sc, rc).Error; err != nil {
		t.Fatalf("no se pudo sembrar el hold anterior: %v", err)
	}
	return deleted, destroy
}

func existeEsquemaAnterior(t *testing.T, db *gorm.DB) bool {
	t.Helper()
	return contar(t, db, `SELECT count(*) FROM pg_namespace WHERE nspname = 'legal_hold'`) == 1
}

// Con el esquema anterior, la migración lleva a sanction_carryovers solo las
// sanciones vigentes (con dni_hmac y destroy_at futuro), con el mismo
// vencimiento, y después borra el esquema.
func TestIntegracionMigracionLlevaLasSancionesVigentesDelEsquemaAnterior(t *testing.T) {
	db := baseConEsquemaAislado(t)
	conEsquemaAnterior(t, db)
	vigente, otraVigente, vencida := uuid.NewString(), uuid.NewString(), uuid.NewString()
	deleted, destroy := holdAnterior(t, db, vigente, "UNDER_REVIEW", -30, 2, 24*time.Hour)
	holdAnterior(t, db, otraVigente, "ACTIVE", -5, 0, 48*time.Hour)
	holdAnterior(t, db, vencida, "UNDER_REVIEW", -30, 2, -time.Hour)
	holdAnterior(t, db, "", "", 0, 0, 24*time.Hour)

	if err := ensureSanctionCarryovers(t.Context(), db); err != nil {
		t.Fatalf("la migración falló: %v", err)
	}

	got, ok := leerSancion(t, db, vigente)
	if !ok {
		t.Fatal("no se migró la sanción vigente")
	}
	if got.AccountStatus != domain.AccountStatusUnderReview || got.ReputationScore != -30 || got.ReportCount != 2 {
		t.Errorf("sanción migrada = %+v", got)
	}
	if !got.ExpiresAt.Equal(destroy) {
		t.Errorf("expires_at = %v, se esperaba el destroy_at del hold %v: el plazo que ya corría no cambia", got.ExpiresAt, destroy)
	}
	if !got.CreatedAt.Equal(deleted) {
		t.Errorf("created_at = %v, se esperaba el deleted_at del hold %v", got.CreatedAt, deleted)
	}
	if _, ok := leerSancion(t, db, otraVigente); !ok {
		t.Error("no se migró la segunda sanción vigente")
	}
	if _, ok := leerSancion(t, db, vencida); ok {
		t.Error("se migró una sanción vencida")
	}
	if n := sancionesGuardadas(t, db); n != 2 {
		t.Errorf("sanction_carryovers tiene %d filas, se esperaban 2 (las vigentes con sanción)", n)
	}
	if existeEsquemaAnterior(t, db) {
		t.Error("el esquema anterior sigue existiendo")
	}
}

// La sanción migrada se hereda en el alta, como cualquier otra.
func TestIntegracionLaSancionMigradaSeHereda(t *testing.T) {
	r := nuevosRepos(t)
	conEsquemaAnterior(t, r.db)
	dni := uuid.NewString()
	holdAnterior(t, r.db, dni, "UNDER_REVIEW", -30, 2, 24*time.Hour)
	if err := ensureSanctionCarryovers(t.Context(), r.db); err != nil {
		t.Fatalf("la migración falló: %v", err)
	}

	u := usuarioParaAlta(t, dni)
	if err := r.users.Create(t.Context(), u, eventoHeredado(t, u.ID)); err != nil {
		t.Fatalf("Create falló: %v", err)
	}

	if u.AccountStatus != domain.AccountStatusUnderReview || u.ReputationScore != -30 || u.ReportCount != 2 {
		t.Errorf("la cuenta nueva quedó con %q/%d/%d", u.AccountStatus, u.ReputationScore, u.ReportCount)
	}
}

// Sin el esquema anterior no hace nada: ni lo crea ni toca lo que hay.
func TestIntegracionMigracionSinEsquemaAnteriorNoHaceNada(t *testing.T) {
	r := nuevosRepos(t)
	sembrarSancion(t, r.db, uuid.NewString(), domain.AccountStatusUnderReview, -1, 1, time.Hour)

	if err := ensureSanctionCarryovers(t.Context(), r.db); err != nil {
		t.Fatalf("la migración falló sin el esquema anterior: %v", err)
	}

	if existeEsquemaAnterior(t, r.db) {
		t.Error("la migración creó el esquema anterior")
	}
	if n := sancionesGuardadas(t, r.db); n != 1 {
		t.Errorf("sanction_carryovers tiene %d filas, se esperaba 1", n)
	}
}

// La migración repetida con el esquema ya retirado no hace nada más: la segunda
// corrida no duplica ni pierde sanciones.
func TestIntegracionMigracionDelEsquemaAnteriorEsIdempotente(t *testing.T) {
	db := baseConEsquemaAislado(t)
	conEsquemaAnterior(t, db)
	dni := uuid.NewString()
	holdAnterior(t, db, dni, "UNDER_REVIEW", -30, 2, 24*time.Hour)

	for i := 0; i < 3; i++ {
		if err := ensureSanctionCarryovers(t.Context(), db); err != nil {
			t.Fatalf("la migración %d falló: %v", i+1, err)
		}
	}

	if n := sancionesGuardadas(t, db); n != 1 {
		t.Errorf("sanction_carryovers tiene %d filas, se esperaba 1", n)
	}
	if existeEsquemaAnterior(t, db) {
		t.Error("el esquema anterior sigue existiendo")
	}
}

// Si ya hay una sanción para ese DNI en sanction_carryovers, la migración no la
// pisa.
func TestIntegracionMigracionNoPisaUnaSancionExistente(t *testing.T) {
	db := baseConEsquemaAislado(t)
	if err := ensureSanctionCarryovers(t.Context(), db); err != nil {
		t.Fatalf("la migración inicial falló: %v", err)
	}
	dni := uuid.NewString()
	sembrarSancion(t, db, dni, domain.AccountStatusActive, -1, 1, time.Hour)
	conEsquemaAnterior(t, db)
	holdAnterior(t, db, dni, "UNDER_REVIEW", -99, 9, 24*time.Hour)

	if err := ensureSanctionCarryovers(t.Context(), db); err != nil {
		t.Fatalf("la migración falló: %v", err)
	}

	got, _ := leerSancion(t, db, dni)
	if got.ReputationScore != -1 || got.ReportCount != 1 {
		t.Errorf("la migración pisó la sanción existente: %+v", got)
	}
	if existeEsquemaAnterior(t, db) {
		t.Error("el esquema anterior sigue existiendo")
	}
}

// Sin sanciones vigentes que llevar, igual retira el esquema.
func TestIntegracionMigracionRetiraElEsquemaAnteriorSinSancionesVigentes(t *testing.T) {
	db := baseConEsquemaAislado(t)
	conEsquemaAnterior(t, db)
	holdAnterior(t, db, "", "", 0, 0, 24*time.Hour)
	holdAnterior(t, db, uuid.NewString(), "UNDER_REVIEW", -1, 1, -time.Hour)

	if err := ensureSanctionCarryovers(t.Context(), db); err != nil {
		t.Fatalf("la migración falló: %v", err)
	}

	if n := sancionesGuardadas(t, db); n != 0 {
		t.Errorf("sanction_carryovers tiene %d filas, se esperaba ninguna", n)
	}
	if existeEsquemaAnterior(t, db) {
		t.Error("el esquema anterior sigue existiendo")
	}
}

// Un esquema anterior sin tabla (a medio crear) igual se retira.
func TestIntegracionMigracionRetiraUnEsquemaAnteriorSinTabla(t *testing.T) {
	db := baseConEsquemaAislado(t)
	if err := db.Exec(`CREATE SCHEMA legal_hold`).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Exec(`DROP SCHEMA IF EXISTS legal_hold CASCADE`).Error })

	if err := ensureSanctionCarryovers(t.Context(), db); err != nil {
		t.Fatalf("la migración falló: %v", err)
	}

	if existeEsquemaAnterior(t, db) {
		t.Error("el esquema anterior sigue existiendo")
	}
}

// La copia y el borrado del esquema son atómicos: si la copia falla, el esquema
// anterior queda intacto con sus datos, y el siguiente arranque reintenta. Un
// dni_hmac de más de 64 caracteres no cabe en la tabla nueva.
func TestIntegracionMigracionFallidaNoPierdeElEsquemaAnterior(t *testing.T) {
	db := baseConEsquemaAislado(t)
	conEsquemaAnterior(t, db)
	if err := db.Exec(`ALTER TABLE legal_hold.user_holds ALTER COLUMN dni_hmac TYPE varchar(200)`).Error; err != nil {
		t.Fatal(err)
	}
	holdAnterior(t, db, strings.Repeat("x", 100), "UNDER_REVIEW", -1, 1, 24*time.Hour)

	if err := ensureSanctionCarryovers(t.Context(), db); err == nil {
		t.Fatal("se esperaba un error al no poder copiar la sanción")
	}

	if !existeEsquemaAnterior(t, db) {
		t.Fatal("la migración fallida borró el esquema anterior")
	}
	if n := contar(t, db, `SELECT count(*) FROM legal_hold.user_holds`); n != 1 {
		t.Errorf("el esquema anterior tiene %d holds, se esperaba 1 intacto", n)
	}
}

// Varias réplicas arrancando a la vez sobre una base con el esquema anterior: una
// migra y las demás encuentran el trabajo hecho, sin error ni duplicados.
func TestIntegracionMigracionDelEsquemaAnteriorEsSeguraEnConcurrencia(t *testing.T) {
	db := baseConEsquemaAislado(t)
	conEsquemaAnterior(t, db)
	holdAnterior(t, db, uuid.NewString(), "UNDER_REVIEW", -1, 1, 24*time.Hour)

	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- ensureSanctionCarryovers(t.Context(), db)
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Errorf("migración concurrente: %v", err)
		}
	}
	if n := sancionesGuardadas(t, db); n != 1 {
		t.Errorf("sanction_carryovers tiene %d filas, se esperaba 1", n)
	}
	if existeEsquemaAnterior(t, db) {
		t.Error("el esquema anterior sigue existiendo")
	}
}

// ── Baja ─────────────────────────────────────────────────────────────────────

func TestIntegracionBajaCorrecta(t *testing.T) {
	r := nuevosRepos(t)
	u := usuarioConEstado(t, r.db, domain.AccountStatusActive, 0, 0)
	otro := usuarioConEstado(t, r.db, domain.AccountStatusActive, 0, 0)
	conSesiones(t, r.db, u.ID, 3)
	conSesiones(t, r.db, otro.ID, 2)
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

	// Una cuenta sin penalizaciones no deja nada: ni sanción ni ningún otro rastro.
	if n := sancionesGuardadas(t, r.db); n != 0 {
		t.Errorf("una cuenta limpia dejó %d sanciones", n)
	}
}

// Los dos eventos quedan encolados, pendientes, en la misma transacción.
func TestIntegracionBajaEncolaLosDosEventos(t *testing.T) {
	r := nuevosRepos(t)
	u := usuarioConEstado(t, r.db, domain.AccountStatusActive, 0, 0)
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

// "Penalizada" son las tres señales del contrato; cada una deja la sanción
// completa con el mismo Blind Index que users.dni_hashed y el vencimiento de la
// baja.
func TestIntegracionBajaDeCuentaPenalizadaDejaLaSancion(t *testing.T) {
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
			baja := unaBaja(t, u.ID, 1095*24*time.Hour)

			if err := r.deletions.DeleteAccount(t.Context(), baja); err != nil {
				t.Fatalf("DeleteAccount falló: %v", err)
			}

			got, ok := leerSancion(t, r.db, u.DNIHashed)
			if !ok {
				t.Fatal("no se guardó la sanción")
			}
			if got.AccountStatus != caso.status || got.ReputationScore != caso.score || got.ReportCount != caso.reports {
				t.Errorf("sanción = %+v, se esperaba %q/%d/%d", got, caso.status, caso.score, caso.reports)
			}
			if !got.CreatedAt.Equal(baja.DeletedAt) {
				t.Errorf("created_at = %v, se esperaba la fecha de la baja %v", got.CreatedAt, baja.DeletedAt)
			}
			if !got.ExpiresAt.Equal(baja.CarryoverExpiresAt) {
				t.Errorf("expires_at = %v, se esperaba %v", got.ExpiresAt, baja.CarryoverExpiresAt)
			}
		})
	}
}

// Atomicidad: si falla el outbox, no se borra nada. El evento repetido (misma
// clave primaria que uno ya encolado) hace fallar el último paso de la
// transacción, cuando la sanción, las sesiones y el usuario ya se tocaron.
func TestIntegracionBajaSiFallaElOutboxNoSeBorraNada(t *testing.T) {
	r := nuevosRepos(t)
	u := usuarioConEstado(t, r.db, domain.AccountStatusUnderReview, -10, 2)
	conSesiones(t, r.db, u.ID, 2)
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
	if _, ok := leerSancion(t, r.db, u.DNIHashed); ok {
		t.Error("quedó una sanción aunque falló el outbox")
	}
	// Solo queda la fila sembrada: el primer evento de la baja también se deshizo.
	if filas := leerOutbox(t, r.db); len(filas) != 1 {
		t.Errorf("outbox tiene %d eventos, se esperaba solo el sembrado", len(filas))
	}
}

// Atomicidad desde el otro extremo: si falla el guardado de la sanción, no se
// borra al usuario ni se encola nada. Una restricción que la tabla rechaza hace
// fallar el primer paso de la transacción.
func TestIntegracionBajaSiFallaLaSancionNoSeBorraNada(t *testing.T) {
	r := nuevosRepos(t)
	u := usuarioConEstado(t, r.db, domain.AccountStatusUnderReview, -10, 2)
	conSesiones(t, r.db, u.ID, 1)
	if err := r.db.Exec(`ALTER TABLE sanction_carryovers ADD CONSTRAINT rechaza_todo CHECK (false)`).Error; err != nil {
		t.Fatalf("no se pudo agregar la restricción: %v", err)
	}

	if err := r.deletions.DeleteAccount(t.Context(), unaBaja(t, u.ID, time.Hour)); err == nil {
		t.Fatal("se esperaba un error al no poder guardar la sanción")
	}

	if !existeUsuario(t, r.db, u.ID) || contar(t, r.db, `SELECT count(*) FROM sessions WHERE user_id = ?`, u.ID) != 1 {
		t.Error("se borró algo aunque falló el guardado de la sanción")
	}
	if filas := leerOutbox(t, r.db); len(filas) != 0 {
		t.Errorf("se encolaron %d eventos aunque falló el guardado de la sanción", len(filas))
	}
}

func TestIntegracionBajaDeUnUsuarioInexistente(t *testing.T) {
	r := nuevosRepos(t)
	fantasma := uuid.New()

	err := r.deletions.DeleteAccount(t.Context(), unaBaja(t, fantasma, time.Hour))

	if !errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("error = %v, se esperaba ErrUserNotFound", err)
	}
	if n := sancionesGuardadas(t, r.db); n != 0 {
		t.Errorf("se guardaron %d sanciones para un usuario que no existe", n)
	}
	if filas := leerOutbox(t, r.db); len(filas) != 0 {
		t.Errorf("se encolaron %d eventos para un usuario que no existe", len(filas))
	}
}

// Dos bajas simultáneas del mismo usuario: una gana y la otra ve al usuario
// inexistente. Una sola sanción, y los eventos una sola vez.
func TestIntegracionDosBajasConcurrentesDelMismoUsuario(t *testing.T) {
	r := nuevosRepos(t)
	u := usuarioConEstado(t, r.db, domain.AccountStatusUnderReview, -10, 2)

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
	if n := sancionesGuardadas(t, r.db); n != 1 {
		t.Errorf("sanciones = %d, se esperaba 1", n)
	}
	if filas := leerOutbox(t, r.db); len(filas) != 2 {
		t.Errorf("outbox tiene %d eventos, se esperaban 2", len(filas))
	}
}

// La sanción sale de la fila que se borra, leída dentro de la transacción, y no
// de una copia que el servicio haya leído antes: lo que se penalizó hasta la
// baja queda guardado.
func TestIntegracionBajaGuardaLaSancionVigenteDeLaFila(t *testing.T) {
	r := nuevosRepos(t)
	u := usuarioConEstado(t, r.db, domain.AccountStatusActive, 0, 0)

	// Un reporte confirmado antes de la baja tiene que verse en la sanción: se
	// lee la fila con SELECT ... FOR UPDATE, no una copia vieja del servicio.
	if err := r.db.Exec(`UPDATE users SET report_count = 3, reputation_score = -20 WHERE id = ?`, u.ID).Error; err != nil {
		t.Fatalf("no se pudo penalizar al usuario: %v", err)
	}

	if err := r.deletions.DeleteAccount(t.Context(), unaBaja(t, u.ID, time.Hour)); err != nil {
		t.Fatalf("DeleteAccount falló: %v", err)
	}

	got, ok := leerSancion(t, r.db, u.DNIHashed)
	if !ok || got.ReportCount != 3 || got.ReputationScore != -20 {
		t.Errorf("la sanción no refleja el estado vigente al momento de la baja: %+v (existe=%v)", got, ok)
	}
}

// Una fila vencida que el barrido todavía no borró, de una cuenta anterior con
// el mismo DNI, se pisa con la sanción nueva: la tabla no puede tener dos filas
// por DNI ni rechazar la baja.
func TestIntegracionBajaPisaUnaSancionVencidaDelMismoDNI(t *testing.T) {
	r := nuevosRepos(t)
	u := usuarioConEstado(t, r.db, domain.AccountStatusUnderReview, -50, 5)
	sembrarSancion(t, r.db, u.DNIHashed, domain.AccountStatusActive, -1, 1, -time.Hour)
	baja := unaBaja(t, u.ID, 24*time.Hour)

	if err := r.deletions.DeleteAccount(t.Context(), baja); err != nil {
		t.Fatalf("DeleteAccount falló: %v", err)
	}

	if n := sancionesGuardadas(t, r.db); n != 1 {
		t.Fatalf("sanciones = %d, se esperaba 1", n)
	}
	got, _ := leerSancion(t, r.db, u.DNIHashed)
	if got.AccountStatus != domain.AccountStatusUnderReview || got.ReputationScore != -50 || got.ReportCount != 5 {
		t.Errorf("la sanción nueva no pisó a la vencida: %+v", got)
	}
	if !got.ExpiresAt.Equal(baja.CarryoverExpiresAt) {
		t.Errorf("expires_at = %v, se esperaba %v", got.ExpiresAt, baja.CarryoverExpiresAt)
	}
}

// La sanción guardada no lleva ningún dato del usuario más que el Blind Index:
// ni email, ni contraseña, ni DNI cifrado, ni su id.
func TestIntegracionLaSancionNoGuardaDatosDelUsuario(t *testing.T) {
	r := nuevosRepos(t)
	u := usuarioConEstado(t, r.db, domain.AccountStatusUnderReview, -1, 1)

	if err := r.deletions.DeleteAccount(t.Context(), unaBaja(t, u.ID, time.Hour)); err != nil {
		t.Fatalf("DeleteAccount falló: %v", err)
	}

	var fila string
	if err := r.db.Raw(`SELECT c::text FROM sanction_carryovers c WHERE dni_hmac = ?`, u.DNIHashed).Scan(&fila).Error; err != nil {
		t.Fatal(err)
	}
	for _, prohibido := range []string{u.Email, u.PasswordHash, u.DNIEncrypted, u.ID.String()} {
		if strings.Contains(fila, prohibido) {
			t.Errorf("la sanción contiene %q: %s", prohibido, fila)
		}
	}
}

// ── Herencia en el alta ──────────────────────────────────────────────────────

// sembrarSancion deja una sanción para un DNI, como la dejaría una baja; expiraEn
// negativo la deja vencida.
func sembrarSancion(t *testing.T, db *gorm.DB, dniHMAC string, status domain.AccountStatus, score, reports int, expiraEn time.Duration) {
	t.Helper()

	err := db.Exec(`INSERT INTO sanction_carryovers
		(dni_hmac, account_status, reputation_score, report_count, created_at, expires_at)
		VALUES (?, ?, ?, ?, now() - interval '1 day', now() + (? * interval '1 second'))`,
		dniHMAC, string(status), score, reports, expiraEn.Seconds()).Error
	if err != nil {
		t.Fatalf("no se pudo sembrar la sanción: %v", err)
	}
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

func TestIntegracionAltaConSancionEnRevisionHeredaLaSancion(t *testing.T) {
	r := nuevosRepos(t)
	dni := uuid.NewString()
	sembrarSancion(t, r.db, dni, domain.AccountStatusUnderReview, -30, 2, time.Hour)
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

	// La sanción se borra: se hereda una sola vez.
	if _, ok := leerSancion(t, r.db, dni); ok {
		t.Error("la sanción heredada sigue en sanction_carryovers")
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
func TestIntegracionAltaConSancionActivaHeredaSinPublicar(t *testing.T) {
	r := nuevosRepos(t)
	dni := uuid.NewString()
	sembrarSancion(t, r.db, dni, domain.AccountStatusActive, -10, 1, time.Hour)
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
	if _, ok := leerSancion(t, r.db, dni); ok {
		t.Error("la sanción heredada sigue en sanction_carryovers")
	}
}

// Sin sanción para ese DNI el alta nace limpia y no encola nada.
func TestIntegracionAltaSinSancionNaceLimpia(t *testing.T) {
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

// Una cuenta que no estaba penalizada no deja nada que heredar: el registro
// posterior con el mismo DNI arranca limpio.
func TestIntegracionAltaTrasUnaBajaSinPenalizacionesNaceLimpia(t *testing.T) {
	r := nuevosRepos(t)
	u := usuarioConEstado(t, r.db, domain.AccountStatusActive, 0, 0)
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

// Una sanción vencida no se hereda: el plazo ya pasó. La fila queda para el
// barrido.
func TestIntegracionAltaConSancionVencidaNoHereda(t *testing.T) {
	r := nuevosRepos(t)
	dni := uuid.NewString()
	sembrarSancion(t, r.db, dni, domain.AccountStatusUnderReview, -30, 2, -time.Hour)
	u := usuarioParaAlta(t, dni)

	if err := r.users.Create(t.Context(), u, eventoHeredado(t, u.ID)); err != nil {
		t.Fatalf("Create falló: %v", err)
	}

	f := leerReputacion(t, r.db, u.ID)
	if f.AccountStatus != "ACTIVE" || f.ReputationScore != 0 || f.ReportCount != 0 {
		t.Errorf("la cuenta nueva quedó con %+v, se esperaba limpia", f)
	}
	if _, ok := leerSancion(t, r.db, dni); !ok {
		t.Error("una sanción vencida no se toca en el alta, la borra el barrido")
	}
	if filas := leerOutbox(t, r.db); len(filas) != 0 {
		t.Errorf("se encolaron %d eventos sin herencia", len(filas))
	}
}

// La sanción no se hereda dos veces: tras el primer alta, otra cuenta con el
// mismo DNI nace limpia.
func TestIntegracionLaSancionNoSeHeredaDosVeces(t *testing.T) {
	r := nuevosRepos(t)
	dni := uuid.NewString()
	sembrarSancion(t, r.db, dni, domain.AccountStatusUnderReview, -30, 2, time.Hour)

	primera := usuarioParaAlta(t, dni)
	if err := r.users.Create(t.Context(), primera, eventoHeredado(t, primera.ID)); err != nil {
		t.Fatalf("primer alta: %v", err)
	}
	if primera.AccountStatus != domain.AccountStatusUnderReview {
		t.Fatalf("la primera cuenta debía heredar la revisión, quedó %q", primera.AccountStatus)
	}

	// La cuenta desaparece sin dejar una sanción nueva (un borrado manual), y el
	// mismo DNI se registra otra vez.
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
func TestIntegracionUnAltaQueFallaNoConsumeLaSancion(t *testing.T) {
	r := nuevosRepos(t)
	dni := uuid.NewString()
	sembrarSancion(t, r.db, dni, domain.AccountStatusUnderReview, -30, 2, time.Hour)

	existente := usuarioConEstado(t, r.db, domain.AccountStatusActive, 0, 0)

	fallida := usuarioParaAlta(t, dni)
	fallida.Email = existente.Email // choca con el índice único de email
	err := r.users.Create(t.Context(), fallida, eventoHeredado(t, fallida.ID))
	if !errors.Is(err, domain.ErrDuplicateUser) {
		t.Fatalf("error = %v, se esperaba ErrDuplicateUser", err)
	}

	got, ok := leerSancion(t, r.db, dni)
	if !ok || got.AccountStatus != domain.AccountStatusUnderReview {
		t.Fatalf("el alta fallida consumió la sanción: %+v (existe=%v)", got, ok)
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
	sembrarSancion(t, r.db, dni, domain.AccountStatusUnderReview, -30, 2, time.Hour)
	u := usuarioParaAlta(t, dni)

	if err := r.users.Create(t.Context(), u, domain.OutboxEvent{}); err == nil {
		t.Fatal("se esperaba un error sin el evento de la revisión heredada")
	}

	if existeUsuario(t, r.db, u.ID) {
		t.Error("se creó la cuenta aunque no pudo anunciarse su revisión")
	}
	if _, ok := leerSancion(t, r.db, dni); !ok {
		t.Error("se consumió la sanción aunque el alta se deshizo")
	}
}

// Atomicidad de la herencia con el outbox: si falla el evento, ni el usuario ni
// el reclamo de la sanción quedan.
func TestIntegracionAltaSiFallaElOutboxNoQuedaNada(t *testing.T) {
	r := nuevosRepos(t)
	dni := uuid.NewString()
	sembrarSancion(t, r.db, dni, domain.AccountStatusUnderReview, -30, 2, time.Hour)
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
	if _, ok := leerSancion(t, r.db, dni); !ok {
		t.Error("se consumió la sanción aunque falló el outbox")
	}
}

// Dos altas simultáneas con el mismo DNI: gana una, que hereda; la otra choca
// con el índice único. La sanción se consume una sola vez y el evento sale una
// sola vez.
func TestIntegracionDosAltasConcurrentesConElMismoDNIHeredanUnaVez(t *testing.T) {
	r := nuevosRepos(t)
	dni := uuid.NewString()
	sembrarSancion(t, r.db, dni, domain.AccountStatusUnderReview, -30, 2, time.Hour)

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
	if n := sancionesGuardadas(t, r.db); n != 0 {
		t.Errorf("la sanción heredada sigue guardada (%d filas)", n)
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

// sembrarVencidas deja cantidad sanciones vencidas hace vencidaHace (negativo: las
// deja vigentes) y devuelve sus Blind Index.
func sembrarVencidas(t *testing.T, db *gorm.DB, cantidad int, vencidaHace time.Duration) []string {
	t.Helper()

	dnis := make([]string, 0, cantidad)
	for i := 0; i < cantidad; i++ {
		dni := uuid.NewString()
		dnis = append(dnis, dni)
		sembrarSancion(t, db, dni, domain.AccountStatusUnderReview, -1, 1, -vencidaHace)
	}
	return dnis
}

// Borra solo lo vencido (expires_at <= now) y deja lo vigente.
func TestIntegracionDeleteExpiredBorraSoloLasVencidas(t *testing.T) {
	r := nuevosRepos(t)
	vencidas := sembrarVencidas(t, r.db, 3, time.Hour)
	vigentes := sembrarVencidas(t, r.db, 2, -time.Hour) // vencen dentro de una hora

	n, err := r.carryovers.DeleteExpired(t.Context(), time.Now(), 100)
	if err != nil {
		t.Fatalf("DeleteExpired falló: %v", err)
	}

	if n != 3 {
		t.Errorf("borradas = %d, se esperaban 3", n)
	}
	for _, dni := range vencidas {
		if _, ok := leerSancion(t, r.db, dni); ok {
			t.Errorf("la sanción vencida %v sigue existiendo", dni)
		}
	}
	for _, dni := range vigentes {
		if _, ok := leerSancion(t, r.db, dni); !ok {
			t.Errorf("la sanción vigente %v se borró", dni)
		}
	}
}

// El corte es inclusivo: expires_at == now ya se borra (expires_at <= now).
func TestIntegracionDeleteExpiredEsInclusivoEnElLimite(t *testing.T) {
	r := nuevosRepos(t)
	corte := time.Now().UTC().Truncate(time.Microsecond)
	insertar := func(dni string, expira time.Time) {
		t.Helper()
		if err := r.db.Exec(`INSERT INTO sanction_carryovers (dni_hmac, account_status, reputation_score, report_count, created_at, expires_at)
			VALUES (?, 'UNDER_REVIEW', -1, 1, ?, ?)`, dni, corte.AddDate(-3, 0, 0), expira).Error; err != nil {
			t.Fatal(err)
		}
	}
	justo, despues := uuid.NewString(), uuid.NewString()
	insertar(justo, corte)

	n, err := r.carryovers.DeleteExpired(t.Context(), corte, 10)
	if err != nil || n != 1 {
		t.Fatalf("borradas=%d err=%v, se esperaba 1 y nil", n, err)
	}
	if _, ok := leerSancion(t, r.db, justo); ok {
		t.Error("la sanción en el límite exacto no se borró")
	}

	// Un microsegundo después del corte, todavía no.
	insertar(despues, corte.Add(time.Microsecond))
	if n, err := r.carryovers.DeleteExpired(t.Context(), corte, 10); err != nil || n != 0 {
		t.Errorf("borradas=%d err=%v, se esperaba 0 y nil", n, err)
	}
}

// El límite acota cada sentencia: se borra de a lotes.
func TestIntegracionDeleteExpiredRespetaElLimite(t *testing.T) {
	r := nuevosRepos(t)
	dnis := sembrarVencidas(t, r.db, 5, time.Hour)

	n, err := r.carryovers.DeleteExpired(t.Context(), time.Now(), 2)
	if err != nil || n != 2 {
		t.Fatalf("borradas=%d err=%v, se esperaba 2 y nil", n, err)
	}
	quedan := 0
	for _, dni := range dnis {
		if _, ok := leerSancion(t, r.db, dni); ok {
			quedan++
		}
	}
	if quedan != 3 {
		t.Errorf("quedan %d sanciones, se esperaban 3", quedan)
	}
}

// Las más viejas se borran primero.
func TestIntegracionDeleteExpiredBorraLasMasViejasPrimero(t *testing.T) {
	r := nuevosRepos(t)
	vieja := sembrarVencidas(t, r.db, 1, 48*time.Hour)[0]
	reciente := sembrarVencidas(t, r.db, 1, time.Hour)[0]

	if n, err := r.carryovers.DeleteExpired(t.Context(), time.Now(), 1); err != nil || n != 1 {
		t.Fatalf("borradas=%d err=%v", n, err)
	}

	if _, ok := leerSancion(t, r.db, vieja); ok {
		t.Error("la sanción más vieja debía borrarse primero")
	}
	if _, ok := leerSancion(t, r.db, reciente); !ok {
		t.Error("la sanción más reciente no debía borrarse todavía")
	}
}

// Varias réplicas barriendo a la vez reparten el trabajo: cada sanción se borra
// una sola vez y nadie se bloquea esperando a otro.
func TestIntegracionDeleteExpiredEsSeguroConVariasReplicas(t *testing.T) {
	r := nuevosRepos(t)
	sembrarVencidas(t, r.db, 40, time.Hour)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var total int64
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				n, err := r.carryovers.DeleteExpired(t.Context(), time.Now(), 5)
				if err != nil {
					t.Errorf("DeleteExpired falló: %v", err)
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
		t.Errorf("entre todas borraron %d sanciones, se esperaban 40", total)
	}
}

func TestIntegracionDeleteExpiredRechazaUnLimiteInvalido(t *testing.T) {
	r := nuevosRepos(t)

	for _, limite := range []int{0, -1} {
		if _, err := r.carryovers.DeleteExpired(t.Context(), time.Now(), limite); err == nil {
			t.Errorf("con límite %d se esperaba un error", limite)
		}
	}
}
