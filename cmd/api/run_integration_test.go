//go:build integration

// Pruebas de integración del arranque completo del servicio (run) contra un
// PostgreSQL real. Requieren TEST_DATABASE_URL, fallan si falta (como las de
// internal/repository/postgres) y trabajan en un esquema propio que se borra al
// terminar, así que no pisan ni dependen del esquema public.
package main

import (
	"context"
	"database/sql"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	delivery "github.com/matiasfelau/vinculo-vial-identity/internal/delivery/http"
	"github.com/matiasfelau/vinculo-vial-identity/pkg/config"
)

// esquemaAislado crea un esquema vacío, lo expone al servicio con PGOPTIONS (que
// pgx lee del entorno) y devuelve las variables POSTGRES_* que apuntan a la base
// de TEST_DATABASE_URL. Lo borra al terminar.
func esquemaAislado(t *testing.T) (override map[string]string, schema string, admin *sql.DB) {
	t.Helper()

	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("TEST_DATABASE_URL no está definida: las pruebas de integración requieren un PostgreSQL real")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("TEST_DATABASE_URL inválida: %v", err)
	}

	admin, err = sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("no se pudo conectar a PostgreSQL: %v", err)
	}
	schema = "cmdapi_it_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	if _, err := admin.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatalf("no se pudo crear el esquema de prueba: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec("DROP SCHEMA " + schema + " CASCADE")
		_ = admin.Close()
	})

	pass, _ := u.User.Password()
	override = map[string]string{
		"POSTGRES_HOST":     u.Hostname(),
		"POSTGRES_PORT":     u.Port(),
		"POSTGRES_USER":     u.User.Username(),
		"POSTGRES_PASSWORD": pass,
		"POSTGRES_DB":       strings.TrimPrefix(u.Path, "/"),
		"POSTGRES_SSLMODE":  "disable",
	}
	if m := u.Query().Get("sslmode"); m != "" {
		override["POSTGRES_SSLMODE"] = m
	}
	return override, schema, admin
}

// arrancar lanza run en una goroutine y devuelve cómo apagarlo y el canal con su
// resultado.
func arrancar(t *testing.T, cfg *config.Config) (apagar func(), resultado <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan error, 1)
	go func() { out <- run(ctx, cfg) }()
	t.Cleanup(cancel)
	return cancel, out
}

func pedir(t *testing.T, metodo, url string, cabeceras map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(metodo, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range cabeceras {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", metodo, url, err)
	}
	defer resp.Body.Close()
	cuerpo, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(cuerpo)
}

func esperarListo(t *testing.T, base string, resultado <-chan error) {
	t.Helper()
	limite := time.Now().Add(20 * time.Second)
	for {
		select {
		case err := <-resultado:
			t.Fatalf("run terminó antes de quedar listo: %v", err)
		default:
		}
		resp, err := http.Get(base + "/ready")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		if time.Now().After(limite) {
			t.Fatalf("el servicio no quedó listo a tiempo (último error: %v)", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func esperarApagado(t *testing.T, apagar func(), resultado <-chan error) {
	t.Helper()
	apagar()
	select {
	case err := <-resultado:
		if err != nil {
			t.Errorf("un apagado ordenado no debería devolver error: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("run no volvió tras cancelar el contexto")
	}
}

func tablasDelEsquema(t *testing.T, db *sql.DB, schema string) map[string]bool {
	t.Helper()
	rows, err := db.Query("SELECT table_name FROM information_schema.tables WHERE table_schema = $1", schema)
	if err != nil {
		t.Fatalf("no se pudieron listar las tablas: %v", err)
	}
	defer rows.Close()
	tablas := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		tablas[n] = true
	}
	return tablas
}

// El servicio arranca de punta a punta con configuración de prueba: migra todas
// las tablas, sirve los tres routers cada uno con su autenticación, y se apaga en
// orden. Arrancarlo una segunda vez sobre la misma base (un reinicio) tiene que
// funcionar: las migraciones son idempotentes.
func TestIntegracionRunArrancaSirveLosTresRoutersYSeApagaEnOrden(t *testing.T) {
	pg, schema, admin := esquemaAislado(t)
	t.Setenv("PGOPTIONS", "-c search_path="+schema)
	cfg := entornoValido(t, pg)

	apagar, resultado := arrancar(t, cfg)
	publico := "http://127.0.0.1" + cfg.HTTP.Addr()
	interno := "http://127.0.0.1" + cfg.Internal.Addr()
	administracion := "http://127.0.0.1" + cfg.Admin.Addr()
	esperarListo(t, publico, resultado)

	// Público: la salud de las dependencias informa el publisher inerte, el worker
	// del outbox y el breaker de RENAPER.
	if status, cuerpo := pedir(t, http.MethodGet, publico+"/health/deps", nil); status != http.StatusOK || !strings.Contains(cuerpo, "renaper_breaker") {
		t.Errorf("GET /health/deps = %d %q, se esperaba 200 con el breaker de RENAPER", status, cuerpo)
	}

	// Interno: toda ruta exige el token de servicio, comparado en servidor.
	if status, _ := pedir(t, http.MethodGet, interno+"/internal/healthz", nil); status != http.StatusUnauthorized && status != http.StatusForbidden {
		t.Errorf("GET /internal/healthz sin token = %d, se esperaba 401 o 403", status)
	}
	if status, _ := pedir(t, http.MethodGet, interno+"/internal/healthz", map[string]string{delivery.HeaderInternalServiceToken: tokenInternoDePrueba}); status != http.StatusOK {
		t.Errorf("GET /internal/healthz con token = %d, se esperaba 200", status)
	}

	// Administración: sin clave se rechaza; con la clave consulta la base real.
	if status, _ := pedir(t, http.MethodGet, administracion+"/admin/v1/review-cases", nil); status != http.StatusUnauthorized {
		t.Errorf("GET /admin/v1/review-cases sin clave = %d, se esperaba 401", status)
	}
	if status, cuerpo := pedir(t, http.MethodGet, administracion+"/admin/v1/review-cases", map[string]string{delivery.HeaderAdminAPIKey: claveAdminDePrueba}); status != http.StatusOK {
		t.Errorf("GET /admin/v1/review-cases con clave = %d %q, se esperaba 200", status, cuerpo)
	}

	// El arranque migró el esquema que le tocaba (y solo ese).
	tablas := tablasDelEsquema(t, admin, schema)
	for _, esperada := range []string{"users", "sessions", "outbox_events", "email_challenges", "processed_events", "review_decisions", "sanction_carryovers"} {
		if !tablas[esperada] {
			t.Errorf("tras el arranque falta la tabla %q en el esquema aislado (hay %v)", esperada, tablas)
		}
	}

	esperarApagado(t, apagar, resultado)

	// Reinicio sobre la misma base.
	cfg = entornoValido(t, pg)
	apagar, resultado = arrancar(t, cfg)
	esperarListo(t, "http://127.0.0.1"+cfg.HTTP.Addr(), resultado)
	esperarApagado(t, apagar, resultado)
}

// Sin ADMIN_API_KEY el servicio arranca igual, pero no hay superficie de
// administración: el puerto no se abre.
func TestIntegracionRunSinClaveDeAdministracionNoAbreElPuertoAdmin(t *testing.T) {
	pg, schema, _ := esquemaAislado(t)
	t.Setenv("PGOPTIONS", "-c search_path="+schema)
	pg["ADMIN_API_KEY"] = ""
	cfg := entornoValido(t, pg)

	apagar, resultado := arrancar(t, cfg)
	esperarListo(t, "http://127.0.0.1"+cfg.HTTP.Addr(), resultado)

	client := http.Client{Timeout: 500 * time.Millisecond}
	if resp, err := client.Get("http://127.0.0.1" + cfg.Admin.Addr() + "/admin/v1/review-cases"); err == nil {
		resp.Body.Close()
		t.Errorf("el puerto de administración responde (%d) aunque ADMIN_API_KEY está vacía", resp.StatusCode)
	}

	esperarApagado(t, apagar, resultado)
}

// Un puerto público ocupado hace fallar el arranque con un error, no lo deja
// colgado a medias con la base abierta.
func TestIntegracionRunFallaSiUnPuertoEstaOcupado(t *testing.T) {
	pg, schema, _ := esquemaAislado(t)
	t.Setenv("PGOPTIONS", "-c search_path="+schema)
	cfg := entornoValido(t, pg)
	ocupado, err := net.Listen("tcp", cfg.Internal.Addr())
	if err != nil {
		t.Skipf("no se pudo ocupar el puerto interno: %v", err)
	}
	defer ocupado.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = run(ctx, cfg)

	if err == nil || ctx.Err() != nil {
		t.Fatalf("run debería devolver un error por el puerto ocupado, devolvió %v (contexto vencido: %v)", err, ctx.Err() != nil)
	}
}
