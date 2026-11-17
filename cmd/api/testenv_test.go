package main

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/hpke"
	"github.com/matiasfelau/vinculo-vial-identity/internal/token"
	"github.com/matiasfelau/vinculo-vial-identity/pkg/config"
)

// variablesDelServicio son todas las que lee config.Load. Se vacían antes de
// cada prueba para que lo que haya en el entorno del desarrollador no cambie
// el resultado.
var variablesDelServicio = []string{
	"APP_ENV", "LOG_LEVEL", "HTTP_PORT", "HTTP_DEBUG", "HTTP_MAX_BODY_BYTES",
	"HTTP_READ_TIMEOUT", "HTTP_WRITE_TIMEOUT", "HTTP_IDLE_TIMEOUT", "HTTP_SHUTDOWN_TIMEOUT",
	"HTTP_INTERNAL_PORT", "INTERNAL_SERVICE_TOKEN", "HTTP_ADMIN_PORT", "ADMIN_API_KEY",
	"POSTGRES_HOST", "POSTGRES_PORT", "POSTGRES_USER", "POSTGRES_PASSWORD",
	"POSTGRES_DB", "POSTGRES_SSLMODE", "POSTGRES_LOG_SQL", "EPHEMERAL_DB",
	"POSTGRES_MAX_OPEN_CONNS", "POSTGRES_MAX_IDLE_CONNS", "POSTGRES_STATEMENT_TIMEOUT",
	"IDENTITY_HPKE_PRIVATE_KEY", "IDENTITY_HPKE_INFO", "AES_KEY", "HMAC_SECRET",
	"JWT_PRIVATE_KEY", "JWT_ISSUER", "ACCESS_TOKEN_TTL_MINUTES", "REFRESH_TOKEN_TTL_DAYS", "SESSION_MAX_DAYS",
	"ARGON2_MEMORY_KIB", "ARGON2_ITERATIONS", "ARGON2_PARALLELISM",
	"RABBITMQ_ENABLED", "RABBITMQ_URL", "RABBITMQ_EXCHANGE",
	"RABBITMQ_DIAL_TIMEOUT", "RABBITMQ_HEARTBEAT", "RENAPER_TIMEOUT",
	"RENAPER_BREAKER_FAILURE_THRESHOLD", "RENAPER_BREAKER_WINDOW", "RENAPER_BREAKER_OPEN_DURATION",
	"OUTBOX_WORKER_INTERVAL", "OUTBOX_WORKER_BATCH_SIZE",
	"RABBITMQ_PREFETCH", "MAX_RETRIES", "ALERT_REJECTED_QUEUE", "FRAUD_PENALTY",
	"ALERT_REPORTED_QUEUE", "REPORT_REVIEW_THRESHOLD",
	"AUDIT_PUBLIC_KEY", "AUDIT_KEY_ID", "SANCTION_CARRYOVER_DAYS",
	"SANCTION_CARRYOVER_SWEEP_INTERVAL", "SANCTION_CARRYOVER_SWEEP_BATCH_SIZE",
	"EMAIL_CODE_HMAC_KEY", "EMAIL_CODE_TTL_MINUTES", "EMAIL_CODE_MAX_ATTEMPTS",
	"EMAIL_CODE_RESEND_SECONDS", "EMAIL_CODE_MAX_SENDS_PER_DAY",
	"EMAIL_VERIFICATION_GRANT_TTL_MINUTES", "PASSWORD_RESET_GRANT_TTL_MINUTES",
	"PASSWORD_RESET_MAX_IDENTITY_ATTEMPTS", "SIGNUP_REQUIRE_EMAIL_VERIFICATION",
	"EMAIL_CHALLENGE_SWEEP_INTERVAL", "EMAIL_CHALLENGE_SWEEP_BATCH_SIZE",
	"TERMS_CURRENT_VERSION", "SIGNUP_REQUIRE_TERMS",
}

const (
	claveAdminDePrueba      = "k-admin-0123456789-0123456789-0123456789"
	tokenInternoDePrueba    = "t-interno-0123456789-0123456789-012345"
	contrasenaDeLaBaseFalsa = "contrasena-de-prueba"
)

// entornoValido arma un entorno de configuración completo, con claves reales
// generadas en el momento (una por mecanismo, como exige el servicio) y los tres
// puertos en direcciones libres, y devuelve la configuración ya cargada. Cada
// variable se puede pisar con override antes de cargar.
func entornoValido(t *testing.T, override map[string]string) *config.Config {
	t.Helper()

	for _, k := range variablesDelServicio {
		t.Setenv(k, "")
	}

	hpkePriv, hpkePub, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatalf("no se pudo generar la clave HPKE: %v", err)
	}
	jwtPriv, _, err := token.GenerateKeyPair()
	if err != nil {
		t.Fatalf("no se pudo generar la clave JWT: %v", err)
	}

	env := map[string]string{
		"POSTGRES_USER":             "identity",
		"POSTGRES_PASSWORD":         contrasenaDeLaBaseFalsa,
		"POSTGRES_DB":               "identity",
		"IDENTITY_HPKE_PRIVATE_KEY": hpkePriv,
		"AES_KEY":                   aleatorioBase64(t, 32),
		"HMAC_SECRET":               aleatorioBase64(t, 32),
		"EMAIL_CODE_HMAC_KEY":       aleatorioBase64(t, 32),
		"JWT_PRIVATE_KEY":           strings.ReplaceAll(jwtPriv, "\n", `\n`),
		"AUDIT_PUBLIC_KEY":          hpkePub,
		"AUDIT_KEY_ID":              "2026-11",
		"INTERNAL_SERVICE_TOKEN":    tokenInternoDePrueba,
		"ADMIN_API_KEY":             claveAdminDePrueba,
		"HTTP_PORT":                 puertoLibre(t),
		"HTTP_INTERNAL_PORT":        puertoLibre(t),
		"HTTP_ADMIN_PORT":           puertoLibre(t),
		"HTTP_SHUTDOWN_TIMEOUT":     "5s",
		// Barridos largos: que ningún proceso periódico corra durante la prueba.
		"SANCTION_CARRYOVER_SWEEP_INTERVAL": "1h",
		"EMAIL_CHALLENGE_SWEEP_INTERVAL":    "1h",
		"OUTBOX_WORKER_INTERVAL":            "1h",
	}
	for k, v := range override {
		env[k] = v
	}
	for k, v := range env {
		t.Setenv(k, v)
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("la configuración de prueba no carga: %v", err)
	}
	return cfg
}

func aleatorioBase64(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("sin entropía: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// puertoLibre pide un puerto efímero al sistema y lo suelta. Hay una ventana
// mínima hasta que el servidor lo toma, aceptable para una prueba local.
func puertoLibre(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("no se pudo reservar un puerto: %v", err)
	}
	defer l.Close()
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
}
