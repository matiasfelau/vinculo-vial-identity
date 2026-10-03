// Prueba de integración contra PostgreSQL real de la migración de
// outbox_events. Se omite si DATABASE_URL no está definida (igual que en
// vinculo-vial-vehicle); el workflow de CI la define con un servicio Postgres.
//
// Cada prueba trabaja en un esquema propio, que se borra al terminar: no toca
// las tablas de `public` de la base a la que apunta DATABASE_URL.
package postgres

import (
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	pgdriver "gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// ddlOutboxTipado es la tabla tal como la dejó #41: user_id y reason NOT NULL.
const ddlOutboxTipado = `
CREATE TABLE outbox_events (
	id uuid PRIMARY KEY,
	user_id uuid NOT NULL,
	reason varchar(64) NOT NULL,
	status varchar(16) NOT NULL DEFAULT 'pending',
	attempts bigint NOT NULL DEFAULT 0,
	last_error text,
	created_at timestamptz NOT NULL,
	sent_at timestamptz
);
CREATE INDEX idx_outbox_events_status_created_at ON outbox_events (status, created_at);
`

func baseConEsquemaAislado(t *testing.T) *gorm.DB {
	t.Helper()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL no configurada: se omite la prueba de integración con PostgreSQL")
	}

	admin, err := gorm.Open(pgdriver.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("no se pudo conectar a PostgreSQL: %v", err)
	}
	schema := "outbox_it_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatalf("no se pudo crear el esquema de prueba: %v", err)
	}

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("DATABASE_URL inválida: %v", err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()

	db, err := gorm.Open(pgdriver.Open(u.String()), &gorm.Config{})
	if err != nil {
		t.Fatalf("no se pudo conectar al esquema de prueba: %v", err)
	}

	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
		_ = admin.Exec("DROP SCHEMA " + schema + " CASCADE").Error
		if sqlDB, err := admin.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

func columnasLegacyRestantes(t *testing.T, db *gorm.DB) int {
	t.Helper()
	var n int
	if err := db.Raw(`SELECT count(*) FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'outbox_events'
		AND column_name IN ('user_id', 'reason')`).Scan(&n).Error; err != nil {
		t.Fatalf("no se pudo consultar information_schema: %v", err)
	}
	return n
}

func nuevoEventoDeRevocacion(t *testing.T) domain.OutboxEvent {
	t.Helper()
	evt, err := domain.NewOutboxEvent("user.sessions.revoked", map[string]string{
		"user_id": uuid.NewString(),
		"reason":  string(domain.SessionsRevokedReasonReuseDetected),
	})
	if err != nil {
		t.Fatalf("no se pudo armar el evento: %v", err)
	}
	evt.CreatedAt = time.Now().UTC()
	return evt
}

// Una base que corrió #41 tiene filas con user_id/reason. La migración las
// convierte al formato nuevo en vez de dejarlas sin contenido, borra las
// columnas viejas y deja la tabla en condiciones de aceptar INSERT nuevos.
func TestMigracionDelOutboxTipadoConservaLasFilasYBorraLasColumnas(t *testing.T) {
	db := baseConEsquemaAislado(t)
	if err := db.Exec(ddlOutboxTipado).Error; err != nil {
		t.Fatalf("no se pudo crear la tabla tipada: %v", err)
	}

	pendiente, enviado := uuid.New(), uuid.New()
	usuario := uuid.New()
	if err := db.Exec(`INSERT INTO outbox_events (id, user_id, reason, status, created_at, sent_at) VALUES
		(?, ?, 'REUSE_DETECTED', 'pending', now(), NULL),
		(?, ?, 'REUSE_DETECTED', 'sent', now(), now())`, pendiente, usuario, enviado, uuid.New()).Error; err != nil {
		t.Fatalf("no se pudieron insertar las filas tipadas: %v", err)
	}

	repo, err := NewOutboxRepository(t.Context(), db)
	if err != nil {
		t.Fatalf("la migración falló: %v", err)
	}

	if n := columnasLegacyRestantes(t, db); n != 0 {
		t.Errorf("quedaron %d columnas viejas (user_id/reason)", n)
	}

	eventos, err := repo.FetchPending(t.Context(), 10)
	if err != nil {
		t.Fatalf("FetchPending falló: %v", err)
	}
	if len(eventos) != 1 || eventos[0].ID != pendiente {
		t.Fatalf("pendientes = %+v, se esperaba solo el evento %v", eventos, pendiente)
	}
	if eventos[0].Type != "user.sessions.revoked" {
		t.Errorf("type = %q, se esperaba user.sessions.revoked", eventos[0].Type)
	}
	var payload struct {
		UserID string `json:"user_id"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(eventos[0].Payload, &payload); err != nil {
		t.Fatalf("el payload convertido no es JSON válido: %v", err)
	}
	if payload.UserID != usuario.String() || payload.Reason != "REUSE_DETECTED" {
		t.Errorf("payload = %+v, se esperaba el user_id y reason de la fila original", payload)
	}

	nuevo := nuevoEventoDeRevocacion(t)
	if err := db.Create(toOutboxModel(&nuevo)).Error; err != nil {
		t.Errorf("un INSERT nuevo falló tras la migración: %v", err)
	}
}

// Caso que reportó la revisión de #42: una base donde AutoMigrate ya agregó
// type/payload (la tabla estaba vacía) pero user_id/reason siguen NOT NULL, y
// por lo tanto todo INSERT nuevo fallaba.
func TestMigracionDelOutboxConAmbosEsquemasPermiteInsertar(t *testing.T) {
	db := baseConEsquemaAislado(t)
	if err := db.Exec(ddlOutboxTipado).Error; err != nil {
		t.Fatalf("no se pudo crear la tabla tipada: %v", err)
	}
	if err := db.Exec(`ALTER TABLE outbox_events
		ADD COLUMN type varchar(64) NOT NULL, ADD COLUMN payload jsonb NOT NULL`).Error; err != nil {
		t.Fatalf("no se pudo armar el esquema híbrido: %v", err)
	}

	nuevo := nuevoEventoDeRevocacion(t)
	if err := db.Create(toOutboxModel(&nuevo)).Error; err == nil {
		t.Fatal("precondición: el INSERT debería fallar con las columnas viejas NOT NULL")
	}

	if _, err := NewOutboxRepository(t.Context(), db); err != nil {
		t.Fatalf("la migración falló: %v", err)
	}
	if n := columnasLegacyRestantes(t, db); n != 0 {
		t.Errorf("quedaron %d columnas viejas (user_id/reason)", n)
	}
	if err := db.Create(toOutboxModel(&nuevo)).Error; err != nil {
		t.Errorf("el INSERT debería funcionar tras la migración: %v", err)
	}
}

// La migración corre en cada arranque: sobre una base sin tabla, o ya
// migrada, no debe fallar ni cambiar nada.
func TestMigracionDelOutboxEsIdempotente(t *testing.T) {
	db := baseConEsquemaAislado(t)

	for i := 0; i < 3; i++ {
		if _, err := NewOutboxRepository(t.Context(), db); err != nil {
			t.Fatalf("arranque %d: %v", i+1, err)
		}
	}

	nuevo := nuevoEventoDeRevocacion(t)
	if err := db.Create(toOutboxModel(&nuevo)).Error; err != nil {
		t.Errorf("INSERT sobre la tabla recién creada: %v", err)
	}
}
