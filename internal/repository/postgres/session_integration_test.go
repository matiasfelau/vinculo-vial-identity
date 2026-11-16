//go:build integration

// Pruebas de integración contra un PostgreSQL real de la vida máxima de la
// sesión (US-12): sessions.started_at, su backfill desde created_at y la
// rotación que lo conserva. Mismas reglas que outbox_migration_test.go:
// requieren TEST_DATABASE_URL y trabajan en un esquema propio que se borra al
// terminar.
package postgres

import (
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

// sessionColumnIsNullable informa si sessions.started_at admite nulos en el
// esquema de la conexión.
func sessionColumnIsNullable(t *testing.T, db *gorm.DB) bool {
	t.Helper()

	var nullable string
	err := db.Raw(`SELECT is_nullable FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'sessions' AND column_name = 'started_at'`).
		Scan(&nullable).Error
	if err != nil {
		t.Fatalf("no se pudo consultar el catálogo: %v", err)
	}
	if nullable == "" {
		t.Fatal("sessions.started_at no existe")
	}
	return nullable == "YES"
}

// La rotación conserva el started_at de la sesión que reemplaza, aunque la
// sesión nueva nazca mucho después: es el ancla de la vida máxima.
func TestIntegracionLaRotacionConservaElStartedAt(t *testing.T) {
	db := baseConEsquemaAislado(t)
	ctx := t.Context()

	if _, err := NewUserRepository(ctx, db); err != nil {
		t.Fatalf("NewUserRepository: %v", err)
	}
	sessions, err := NewSessionRepository(ctx, db)
	if err != nil {
		t.Fatalf("NewSessionRepository: %v", err)
	}
	u := usuarioConEstado(t, db, domain.AccountStatusActive, 0, 0)

	login := time.Now().UTC().Add(-60 * 24 * time.Hour).Truncate(time.Microsecond)
	original, err := domain.NewSession(u.ID, uuid.NewString(), login.Add(30*24*time.Hour), login, login)
	if err != nil {
		t.Fatalf("no se pudo armar la sesión: %v", err)
	}
	if err := sessions.Create(ctx, original); err != nil {
		t.Fatalf("Create: %v", err)
	}

	ahora := time.Now().UTC()
	rotada, err := domain.NewSession(u.ID, uuid.NewString(), ahora.Add(30*24*time.Hour), original.StartedAt, ahora)
	if err != nil {
		t.Fatalf("no se pudo armar la sesión rotada: %v", err)
	}
	if err := sessions.RotateSession(ctx, original.ID, rotada); err != nil {
		t.Fatalf("RotateSession: %v", err)
	}

	got, err := sessions.FindByHash(ctx, rotada.RefreshTokenHash)
	if err != nil {
		t.Fatalf("FindByHash: %v", err)
	}
	if !got.StartedAt.Equal(login) {
		t.Errorf("started_at tras rotar = %v, se esperaba el del login (%v)", got.StartedAt, login)
	}
	if got.CreatedAt.Sub(got.StartedAt) < 59*24*time.Hour {
		t.Errorf("created_at (%v) debería ser posterior a started_at (%v)", got.CreatedAt, got.StartedAt)
	}
}

// Un started_at viaja ida y vuelta por la base sin perder el instante.
func TestIntegracionCreateYFindByHashConservanElStartedAt(t *testing.T) {
	db := baseConEsquemaAislado(t)
	ctx := t.Context()

	if _, err := NewUserRepository(ctx, db); err != nil {
		t.Fatalf("NewUserRepository: %v", err)
	}
	sessions, err := NewSessionRepository(ctx, db)
	if err != nil {
		t.Fatalf("NewSessionRepository: %v", err)
	}
	u := usuarioConEstado(t, db, domain.AccountStatusActive, 0, 0)

	ahora := time.Now().UTC().Truncate(time.Microsecond)
	s, err := domain.NewSession(u.ID, uuid.NewString(), ahora.Add(time.Hour), ahora, ahora)
	if err != nil {
		t.Fatalf("no se pudo armar la sesión: %v", err)
	}
	if err := sessions.Create(ctx, s); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := sessions.FindByHash(ctx, s.RefreshTokenHash)
	if err != nil {
		t.Fatalf("FindByHash: %v", err)
	}
	if !got.StartedAt.Equal(ahora) {
		t.Errorf("started_at = %v, se esperaba %v", got.StartedAt, ahora)
	}
}

// Una base con sesiones de la versión anterior (sin la columna) se migra: las
// filas existentes toman created_at como started_at y la columna queda NOT
// NULL.
func TestIntegracionLaMigracionRellenaStartedAtConCreatedAt(t *testing.T) {
	db := baseConEsquemaAislado(t)
	ctx := t.Context()

	if _, err := NewUserRepository(ctx, db); err != nil {
		t.Fatalf("NewUserRepository: %v", err)
	}
	u := usuarioConEstado(t, db, domain.AccountStatusActive, 0, 0)

	// Esquema anterior: la tabla sessions tal como estaba antes de US-12.
	err := db.Exec(`CREATE TABLE sessions (
		id uuid PRIMARY KEY,
		user_id uuid NOT NULL,
		refresh_token_hash varchar(64) NOT NULL,
		is_revoked boolean NOT NULL DEFAULT false,
		expires_at timestamptz NOT NULL,
		created_at timestamptz NOT NULL)`).Error
	if err != nil {
		t.Fatalf("no se pudo crear el esquema anterior: %v", err)
	}
	creada := time.Now().UTC().Add(-10 * 24 * time.Hour).Truncate(time.Microsecond)
	ids := []uuid.UUID{uuid.New(), uuid.New()}
	for _, id := range ids {
		err := db.Exec(`INSERT INTO sessions (id, user_id, refresh_token_hash, is_revoked, expires_at, created_at)
			VALUES (?, ?, ?, false, ?, ?)`, id, u.ID, id.String(), creada.Add(30*24*time.Hour), creada).Error
		if err != nil {
			t.Fatalf("no se pudo insertar la sesión anterior: %v", err)
		}
	}

	sessions, err := NewSessionRepository(ctx, db)
	if err != nil {
		t.Fatalf("NewSessionRepository sobre el esquema anterior: %v", err)
	}

	if sessionColumnIsNullable(t, db) {
		t.Error("started_at debería quedar NOT NULL")
	}
	for _, id := range ids {
		got, err := sessions.FindByHash(ctx, id.String())
		if err != nil {
			t.Fatalf("FindByHash: %v", err)
		}
		if !got.StartedAt.Equal(creada) {
			t.Errorf("started_at = %v, se esperaba created_at (%v)", got.StartedAt, creada)
		}
	}
}

// Migrar dos veces no cambia nada: ni pisa un started_at ya fijado ni falla.
func TestIntegracionLaMigracionDeSessionsEsIdempotente(t *testing.T) {
	db := baseConEsquemaAislado(t)
	ctx := t.Context()

	if _, err := NewUserRepository(ctx, db); err != nil {
		t.Fatalf("NewUserRepository: %v", err)
	}
	sessions, err := NewSessionRepository(ctx, db)
	if err != nil {
		t.Fatalf("NewSessionRepository: %v", err)
	}
	u := usuarioConEstado(t, db, domain.AccountStatusActive, 0, 0)

	login := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Microsecond)
	ahora := time.Now().UTC()
	s, err := domain.NewSession(u.ID, uuid.NewString(), ahora.Add(time.Hour), login, ahora)
	if err != nil {
		t.Fatalf("no se pudo armar la sesión: %v", err)
	}
	if err := sessions.Create(ctx, s); err != nil {
		t.Fatalf("Create: %v", err)
	}

	for i := 0; i < 2; i++ {
		if _, err := NewSessionRepository(ctx, db); err != nil {
			t.Fatalf("NewSessionRepository (arranque %d): %v", i+2, err)
		}
	}

	got, err := sessions.FindByHash(ctx, s.RefreshTokenHash)
	if err != nil {
		t.Fatalf("FindByHash: %v", err)
	}
	if !got.StartedAt.Equal(login) {
		t.Errorf("started_at = %v, se esperaba %v: la migración no debe pisarlo", got.StartedAt, login)
	}
	if sessionColumnIsNullable(t, db) {
		t.Error("started_at debería seguir NOT NULL")
	}
}

// Varias réplicas arrancando a la vez sobre el esquema anterior no chocan: el
// advisory lock serializa la migración.
func TestIntegracionLaMigracionDeSessionsEsConcurrente(t *testing.T) {
	db := baseConEsquemaAislado(t)
	ctx := t.Context()

	if _, err := NewUserRepository(ctx, db); err != nil {
		t.Fatalf("NewUserRepository: %v", err)
	}
	u := usuarioConEstado(t, db, domain.AccountStatusActive, 0, 0)

	err := db.Exec(`CREATE TABLE sessions (
		id uuid PRIMARY KEY,
		user_id uuid NOT NULL,
		refresh_token_hash varchar(64) NOT NULL,
		is_revoked boolean NOT NULL DEFAULT false,
		expires_at timestamptz NOT NULL,
		created_at timestamptz NOT NULL)`).Error
	if err != nil {
		t.Fatalf("no se pudo crear el esquema anterior: %v", err)
	}
	id := uuid.New()
	creada := time.Now().UTC().Add(-time.Hour)
	if err := db.Exec(`INSERT INTO sessions (id, user_id, refresh_token_hash, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?)`, id, u.ID, id.String(), creada.Add(time.Hour), creada).Error; err != nil {
		t.Fatalf("no se pudo insertar la sesión anterior: %v", err)
	}

	const replicas = 6
	errs := make(chan error, replicas)
	var wg sync.WaitGroup
	for i := 0; i < replicas; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := NewSessionRepository(ctx, db)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Errorf("NewSessionRepository concurrente: %v", err)
		}
	}
	if sessionColumnIsNullable(t, db) {
		t.Error("started_at debería quedar NOT NULL")
	}
}

// Con la migración ya aplicada (por ejemplo, a mano por un DBA), el arranque
// no ejecuta DDL sobre sessions: un rol sin privilegios de dueño arranca y
// puede crear y rotar sesiones con solo permisos de DML.
func TestIntegracionLaMigracionDeSessionsNoNecesitaDDLSiYaEstaAplicada(t *testing.T) {
	db := baseConEsquemaAislado(t)
	ctx := t.Context()

	if _, err := NewUserRepository(ctx, db); err != nil {
		t.Fatalf("NewUserRepository: %v", err)
	}
	if _, err := NewSessionRepository(ctx, db); err != nil {
		t.Fatalf("NewSessionRepository: %v", err)
	}
	u := usuarioConEstado(t, db, domain.AccountStatusActive, 0, 0)

	var esquema string
	if err := db.Raw(`SELECT current_schema()`).Scan(&esquema).Error; err != nil {
		t.Fatal(err)
	}
	rol := "svc_sin_ddl_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	const clave = "clave-de-prueba"
	for _, sentencia := range []string{
		`CREATE ROLE ` + rol + ` LOGIN PASSWORD '` + clave + `'`,
		`GRANT USAGE ON SCHEMA ` + esquema + ` TO ` + rol,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON sessions, users TO ` + rol,
	} {
		if err := db.Exec(sentencia).Error; err != nil {
			t.Fatalf("no se pudo preparar el rol (%s): %v", sentencia, err)
		}
	}
	t.Cleanup(func() {
		_ = db.Exec(`DROP OWNED BY ` + rol).Error
		_ = db.Exec(`DROP ROLE IF EXISTS ` + rol).Error
	})

	parsed, err := url.Parse(os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatalf("TEST_DATABASE_URL inválida: %v", err)
	}
	parsed.User = url.UserPassword(rol, clave)
	q := parsed.Query()
	q.Set("search_path", esquema)
	parsed.RawQuery = q.Encode()
	svcDB, err := gorm.Open(pgdriver.Open(parsed.String()), &gorm.Config{})
	if err != nil {
		t.Fatalf("no se pudo conectar con el rol del servicio: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := svcDB.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})

	sessions, err := NewSessionRepository(ctx, svcDB)
	if err != nil {
		t.Fatalf("el servicio no arrancó con un rol sin DDL y la migración ya aplicada: %v", err)
	}
	ahora := time.Now().UTC()
	s, err := domain.NewSession(u.ID, uuid.NewString(), ahora.Add(time.Hour), ahora, ahora)
	if err != nil {
		t.Fatalf("no se pudo armar la sesión: %v", err)
	}
	if err := sessions.Create(ctx, s); err != nil {
		t.Errorf("Create con permisos de DML: %v", err)
	}
}
