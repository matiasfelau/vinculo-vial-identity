//go:build integration

// Pruebas de integración contra un PostgreSQL real de la migración de las
// columnas de reputación y de ReputationRepository (US-08). Mismas reglas que
// outbox_migration_test.go: requieren TEST_DATABASE_URL, fallan si falta y
// trabajan en un esquema propio que se borra al terminar.
package postgres

import (
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

const consumidorDePrueba = "identity.alert-rejected.q"

// ddlUsersPreUS08 es la tabla users tal como la dejó AutoMigrate antes de
// US-08: sin reputation_score ni report_count.
const ddlUsersPreUS08 = `
CREATE TABLE users (
	id uuid PRIMARY KEY,
	email varchar(254) NOT NULL,
	password varchar(255) NOT NULL,
	dni_hashed varchar(64) NOT NULL,
	dni_encrypted text NOT NULL,
	account_status varchar(32) NOT NULL DEFAULT 'ACTIVE',
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX uix_users_email ON users (email);
CREATE UNIQUE INDEX uix_users_dni_hashed ON users (dni_hashed);
`

type columnaUsers struct {
	IsNullable    string
	ColumnDefault *string
	DataType      string
}

func columnaDeUsers(t *testing.T, db *gorm.DB, nombre string) columnaUsers {
	t.Helper()

	var c columnaUsers
	err := db.Raw(`SELECT is_nullable, column_default, data_type FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = ?`, nombre).Scan(&c).Error
	if err != nil || c.IsNullable == "" {
		t.Fatalf("no se pudo leer la columna users.%s (err=%v)", nombre, err)
	}
	return c
}

func insertarUsuarioPreUS08(t *testing.T, db *gorm.DB, email, estado string) uuid.UUID {
	t.Helper()

	id := uuid.New()
	err := db.Exec(`INSERT INTO users (id, email, password, dni_hashed, dni_encrypted, account_status, created_at, updated_at)
		VALUES (?, ?, 'hash', ?, 'cifrado', ?, now(), now())`, id, email, uuid.NewString(), estado).Error
	if err != nil {
		t.Fatalf("no se pudo insertar el usuario preexistente: %v", err)
	}
	return id
}

type filaReputacion struct {
	ReputationScore int
	ReportCount     int
	AccountStatus   string
	Email           string
}

func leerReputacion(t *testing.T, db *gorm.DB, id uuid.UUID) filaReputacion {
	t.Helper()

	var f filaReputacion
	if err := db.Raw(`SELECT reputation_score, report_count, account_status, email FROM users WHERE id = ?`, id).Scan(&f).Error; err != nil {
		t.Fatalf("no se pudo leer el usuario: %v", err)
	}
	return f
}

func contarEventos(t *testing.T, db *gorm.DB) int64 {
	t.Helper()

	var n int64
	if err := db.Raw(`SELECT count(*) FROM processed_events`).Scan(&n).Error; err != nil {
		t.Fatalf("no se pudo contar processed_events: %v", err)
	}
	return n
}

func usuarioNuevo(t *testing.T, db *gorm.DB) uuid.UUID {
	t.Helper()

	u, err := domain.NewUser(uuid.NewString()+"@example.com", "hash", uuid.NewString(), "cifrado", time.Now())
	if err != nil {
		t.Fatalf("no se pudo armar el usuario: %v", err)
	}
	if err := db.Create(toModel(u)).Error; err != nil {
		t.Fatalf("no se pudo insertar el usuario: %v", err)
	}
	return u.ID
}

func eventoDePrueba(consumidor string) domain.ProcessedEvent {
	return domain.ProcessedEvent{
		EventID:     uuid.New(),
		Consumer:    consumidor,
		EventType:   "alert.rejected",
		ProcessedAt: time.Now().UTC(),
	}
}

// AutoMigrate sobre una tabla users con filas: las columnas nuevas se agregan
// NOT NULL con default 0, y los usuarios que ya existían quedan en el valor
// inicial sin backfill ni otro dato alterado.
func TestIntegracionMigracionDeUsersConFilasPreexistentes(t *testing.T) {
	db := baseConEsquemaAislado(t)
	if err := db.Exec(ddlUsersPreUS08).Error; err != nil {
		t.Fatalf("no se pudo crear la tabla users previa a US-08: %v", err)
	}
	uno := insertarUsuarioPreUS08(t, db, "uno@example.com", "ACTIVE")
	dos := insertarUsuarioPreUS08(t, db, "dos@example.com", "ACTIVE")

	repo, err := NewUserRepository(t.Context(), db)
	if err != nil {
		t.Fatalf("la migración sobre filas existentes falló: %v", err)
	}

	for nombre, id := range map[string]uuid.UUID{"uno": uno, "dos": dos} {
		f := leerReputacion(t, db, id)
		if f.ReputationScore != 0 || f.ReportCount != 0 {
			t.Errorf("usuario %s: reputation_score=%d report_count=%d, se esperaba 0 y 0", nombre, f.ReputationScore, f.ReportCount)
		}
		if f.AccountStatus != "ACTIVE" || f.Email != nombre+"@example.com" {
			t.Errorf("usuario %s: la migración alteró datos existentes: %+v", nombre, f)
		}
	}

	for _, nombre := range []string{"reputation_score", "report_count"} {
		c := columnaDeUsers(t, db, nombre)
		if c.IsNullable != "NO" {
			t.Errorf("users.%s admite NULL", nombre)
		}
		if c.ColumnDefault == nil || *c.ColumnDefault != "0" {
			t.Errorf("users.%s: default = %v, se esperaba 0", nombre, c.ColumnDefault)
		}
		if c.DataType != "integer" {
			t.Errorf("users.%s: tipo = %q, se esperaba integer", nombre, c.DataType)
		}
	}

	// Un alta posterior a la migración nace con los valores iniciales.
	nuevo, err := domain.NewUser("nuevo@example.com", "hash", "dni", "cifrado", time.Now())
	if err != nil {
		t.Fatalf("no se pudo armar el usuario: %v", err)
	}
	if err := repo.Create(t.Context(), nuevo, domain.OutboxEvent{}, nil); err != nil {
		t.Fatalf("el alta posterior a la migración falló: %v", err)
	}
	if f := leerReputacion(t, db, nuevo.ID); f.ReputationScore != 0 || f.ReportCount != 0 {
		t.Errorf("el usuario nuevo nació con %+v, se esperaba 0 y 0", f)
	}
}

// La migración corre en cada arranque: repetirla no cambia nada, ni los
// valores que el servicio ya fue modificando.
func TestIntegracionMigracionDeUsersEsIdempotente(t *testing.T) {
	db := baseConEsquemaAislado(t)
	if err := db.Exec(ddlUsersPreUS08).Error; err != nil {
		t.Fatalf("no se pudo crear la tabla users previa a US-08: %v", err)
	}
	id := insertarUsuarioPreUS08(t, db, "uno@example.com", "ACTIVE")

	for range 2 {
		if _, err := NewUserRepository(t.Context(), db); err != nil {
			t.Fatalf("la migración falló: %v", err)
		}
	}
	if err := db.Exec(`UPDATE users SET reputation_score = -20, report_count = 3 WHERE id = ?`, id).Error; err != nil {
		t.Fatalf("no se pudo modificar el usuario: %v", err)
	}
	if _, err := NewUserRepository(t.Context(), db); err != nil {
		t.Fatalf("la migración repetida falló: %v", err)
	}

	if f := leerReputacion(t, db, id); f.ReputationScore != -20 || f.ReportCount != 3 {
		t.Errorf("la migración repetida pisó los valores: %+v", f)
	}
}

// processed_events se crea con una clave única por (event_id, consumer): la
// restricción de la base es la que hace idempotente al consumidor.
func TestIntegracionProcessedEventsTieneClaveUnicaPorEventoYConsumidor(t *testing.T) {
	db := baseConEsquemaAislado(t)
	if _, err := NewUserRepository(t.Context(), db); err != nil {
		t.Fatalf("migración de users: %v", err)
	}
	for range 2 {
		if _, err := NewReputationRepository(t.Context(), db); err != nil {
			t.Fatalf("migración de processed_events: %v", err)
		}
	}

	var columnas []string
	err := db.Raw(`SELECT a.attname FROM pg_index i
		JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey)
		WHERE i.indrelid = 'processed_events'::regclass AND i.indisprimary
		ORDER BY a.attname`).Scan(&columnas).Error
	if err != nil {
		t.Fatalf("no se pudo leer la clave primaria: %v", err)
	}
	if len(columnas) != 2 || columnas[0] != "consumer" || columnas[1] != "event_id" {
		t.Errorf("clave primaria = %v, se esperaba (consumer, event_id)", columnas)
	}

	evento := eventoDePrueba(consumidorDePrueba)
	if err := db.Create(toProcessedEventModel(evento)).Error; err != nil {
		t.Fatalf("primer insert: %v", err)
	}
	if err := db.Create(toProcessedEventModel(evento)).Error; err == nil {
		t.Error("el mismo (event_id, consumer) debería violar la clave única")
	}
	otro := evento
	otro.Consumer = "identity.alert-reported.q"
	if err := db.Create(toProcessedEventModel(otro)).Error; err != nil {
		t.Errorf("el mismo evento para otro consumidor no es un duplicado: %v", err)
	}
}

func repositorioDeReputacion(t *testing.T, db *gorm.DB) *ReputationRepository {
	t.Helper()

	if _, err := NewUserRepository(t.Context(), db); err != nil {
		t.Fatalf("migración de users: %v", err)
	}
	repo, err := NewReputationRepository(t.Context(), db)
	if err != nil {
		t.Fatalf("migración de processed_events: %v", err)
	}
	return repo
}

func TestIntegracionApplyRejectionRestaLaPenalizacion(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo := repositorioDeReputacion(t, db)
	id := usuarioNuevo(t, db)

	res, err := repo.ApplyRejection(t.Context(), eventoDePrueba(consumidorDePrueba), id, 10)
	if err != nil || res != domain.RejectionApplied {
		t.Fatalf("resultado = (%v, %v), se esperaba RejectionApplied", res, err)
	}
	if f := leerReputacion(t, db, id); f.ReputationScore != -10 {
		t.Errorf("reputation_score = %d, se esperaba -10", f.ReputationScore)
	}
	if n := contarEventos(t, db); n != 1 {
		t.Errorf("processed_events = %d filas, se esperaba 1", n)
	}

	// Un segundo rechazo distinto acumula.
	if _, err := repo.ApplyRejection(t.Context(), eventoDePrueba(consumidorDePrueba), id, 10); err != nil {
		t.Fatalf("segundo rechazo: %v", err)
	}
	if f := leerReputacion(t, db, id); f.ReputationScore != -20 {
		t.Errorf("reputation_score = %d, se esperaba -20", f.ReputationScore)
	}
}

func TestIntegracionApplyRejectionDeUnEventoRepetidoRestaUnaSolaVez(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo := repositorioDeReputacion(t, db)
	id := usuarioNuevo(t, db)
	evento := eventoDePrueba(consumidorDePrueba)

	primero, err := repo.ApplyRejection(t.Context(), evento, id, 10)
	if err != nil || primero != domain.RejectionApplied {
		t.Fatalf("primera entrega = (%v, %v)", primero, err)
	}
	segundo, err := repo.ApplyRejection(t.Context(), evento, id, 10)
	if err != nil || segundo != domain.RejectionDuplicate {
		t.Fatalf("segunda entrega = (%v, %v), se esperaba RejectionDuplicate", segundo, err)
	}

	if f := leerReputacion(t, db, id); f.ReputationScore != -10 {
		t.Errorf("reputation_score = %d, se esperaba -10: la reentrega no debe volver a restar", f.ReputationScore)
	}
}

// Entregas concurrentes del mismo evento (dos réplicas, o una reentrega que
// alcanza a la original): la clave única serializa y solo una resta.
func TestIntegracionApplyRejectionConcurrenteRestaUnaSolaVez(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo := repositorioDeReputacion(t, db)
	id := usuarioNuevo(t, db)
	evento := eventoDePrueba(consumidorDePrueba)

	const entregas = 8
	resultados := make([]domain.RejectionResult, entregas)
	errores := make([]error, entregas)
	var wg sync.WaitGroup
	for i := range entregas {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resultados[i], errores[i] = repo.ApplyRejection(t.Context(), evento, id, 10)
		}()
	}
	wg.Wait()

	aplicados := 0
	for i := range entregas {
		if errores[i] != nil {
			t.Fatalf("entrega %d: %v", i, errores[i])
		}
		if resultados[i] == domain.RejectionApplied {
			aplicados++
		}
	}
	if aplicados != 1 {
		t.Errorf("entregas aplicadas = %d, se esperaba 1", aplicados)
	}
	if f := leerReputacion(t, db, id); f.ReputationScore != -10 {
		t.Errorf("reputation_score = %d, se esperaba -10", f.ReputationScore)
	}
}

// La clave es (event_id, consumidor): el mismo evento visto por otro
// consumidor es un efecto distinto, no un duplicado.
func TestIntegracionApplyRejectionDeduplicaPorConsumidor(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo := repositorioDeReputacion(t, db)
	id := usuarioNuevo(t, db)

	evento := eventoDePrueba(consumidorDePrueba)
	otro := evento
	otro.Consumer = "identity.alert-reported.q"

	for _, e := range []domain.ProcessedEvent{evento, otro} {
		res, err := repo.ApplyRejection(t.Context(), e, id, 10)
		if err != nil || res != domain.RejectionApplied {
			t.Fatalf("consumidor %s = (%v, %v), se esperaba RejectionApplied", e.Consumer, res, err)
		}
	}
	if f := leerReputacion(t, db, id); f.ReputationScore != -20 {
		t.Errorf("reputation_score = %d, se esperaba -20", f.ReputationScore)
	}
}

// Sin penalización (rechazo sin fraude) el evento igual queda registrado y el
// usuario no cambia.
func TestIntegracionApplyRejectionSinPenalizacionSoloRegistraElEvento(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo := repositorioDeReputacion(t, db)
	id := usuarioNuevo(t, db)

	res, err := repo.ApplyRejection(t.Context(), eventoDePrueba(consumidorDePrueba), id, 0)
	if err != nil || res != domain.RejectionApplied {
		t.Fatalf("resultado = (%v, %v)", res, err)
	}
	if f := leerReputacion(t, db, id); f.ReputationScore != 0 {
		t.Errorf("reputation_score = %d, se esperaba 0", f.ReputationScore)
	}
	if n := contarEventos(t, db); n != 1 {
		t.Errorf("processed_events = %d filas, se esperaba 1", n)
	}
}

// Un usuario inexistente no es un error: se registra el evento y se informa.
func TestIntegracionApplyRejectionDeUnUsuarioInexistente(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo := repositorioDeReputacion(t, db)

	res, err := repo.ApplyRejection(t.Context(), eventoDePrueba(consumidorDePrueba), uuid.New(), 10)
	if err != nil || res != domain.RejectionUserNotFound {
		t.Fatalf("resultado = (%v, %v), se esperaba RejectionUserNotFound", res, err)
	}
}

// Si falla la resta, la marca de deduplicación se deshace con ella: el
// reintento tiene que poder procesar el evento entero. Un trigger que rechaza
// todo UPDATE sobre users fuerza el fallo.
func TestIntegracionApplyRejectionEsAtomico(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo := repositorioDeReputacion(t, db)
	id := usuarioNuevo(t, db)

	err := db.Exec(`
		CREATE FUNCTION rechazar_update() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'update rechazado por la prueba'; END $$;
		CREATE TRIGGER users_sin_update BEFORE UPDATE ON users
			FOR EACH ROW EXECUTE FUNCTION rechazar_update();`).Error
	if err != nil {
		t.Fatalf("no se pudo armar el trigger: %v", err)
	}

	evento := eventoDePrueba(consumidorDePrueba)
	if _, err := repo.ApplyRejection(t.Context(), evento, id, 10); err == nil {
		t.Fatal("se esperaba un error al fallar la resta")
	}
	if n := contarEventos(t, db); n != 0 {
		t.Fatalf("processed_events = %d filas: la marca debió deshacerse con la transacción", n)
	}

	if err := db.Exec(`DROP TRIGGER users_sin_update ON users`).Error; err != nil {
		t.Fatalf("no se pudo quitar el trigger: %v", err)
	}
	res, err := repo.ApplyRejection(t.Context(), evento, id, 10)
	if err != nil || res != domain.RejectionApplied {
		t.Fatalf("el reintento = (%v, %v), se esperaba RejectionApplied", res, err)
	}
	if f := leerReputacion(t, db, id); f.ReputationScore != -10 {
		t.Errorf("reputation_score = %d, se esperaba -10", f.ReputationScore)
	}
}
