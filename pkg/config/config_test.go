package config_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matiasfelau/vinculo-vial-identity/pkg/config"
)

// entornoMinimo es el conjunto de variables sin las cuales el servicio no
// levanta. Cada test parte de acá y degrada una sola.
func entornoMinimo() map[string]string {
	clave := base64.StdEncoding.EncodeToString(make([]byte, 32))
	return map[string]string{
		"POSTGRES_USER":             "identity",
		"POSTGRES_PASSWORD":         "sup3rs3cr3t",
		"POSTGRES_DB":               "identity",
		"IDENTITY_HPKE_PRIVATE_KEY": clave,
		"AES_KEY":                   clave,
		"HMAC_SECRET":               clave,
		"JWT_PRIVATE_KEY":           clavePEMDePrueba,
		"INTERNAL_SERVICE_TOKEN":    strings.Repeat("a", 32),
		// Clave pública de Audit y su id (US-11): config.Load no los interpreta, solo
		// los exige; internal/crypto/auditseal los valida de verdad.
		"AUDIT_PUBLIC_KEY": clave,
		"AUDIT_KEY_ID":     "2026-11",
		// Clave de los desafíos por email (US-13): distinta de AES_KEY y HMAC_SECRET,
		// porque config.Load rechaza reutilizarlas.
		"EMAIL_CODE_HMAC_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
	}
}

// clavePEMDePrueba es un PEM sintácticamente válido pero criptográficamente
// falso: config.Load no interpreta la clave, solo la guarda como Secret y
// deshace el escapado de saltos de línea. Interpretarla de verdad es
// responsabilidad de internal/token, que se prueba aparte con claves RSA
// reales. Viaja con los saltos de línea escapados, tal como cmd/genkeys la
// imprime y tal como tiene que poder pegarse en una sola línea de .env.
const clavePEMDePrueba = `-----BEGIN PRIVATE KEY-----\nZmFsc2E=\n-----END PRIVATE KEY-----\n`

func aplicar(t *testing.T, env map[string]string) {
	t.Helper()

	// Setenv restaura el valor previo al terminar el test.
	for _, k := range []string{
		"APP_ENV", "LOG_LEVEL", "HTTP_PORT", "HTTP_DEBUG", "HTTP_MAX_BODY_BYTES",
		"HTTP_INTERNAL_PORT", "INTERNAL_SERVICE_TOKEN",
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
	} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}

	for k, v := range env {
		t.Setenv(k, v)
	}
}

func TestLoadConElEntornoMinimo(t *testing.T) {
	aplicar(t, entornoMinimo())

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if cfg.HTTP.Port != 8080 {
		t.Errorf("puerto = %d, se esperaba 8080", cfg.HTTP.Port)
	}
	if cfg.HTTP.Addr() != ":8080" {
		t.Errorf("addr = %q, se esperaba \":8080\"", cfg.HTTP.Addr())
	}
	if cfg.Env != "development" {
		t.Errorf("env = %q, se esperaba development", cfg.Env)
	}
	if cfg.Events.Enabled {
		t.Error("el broker debería estar deshabilitado por defecto: no está en el compose local")
	}
	// El info por defecto es vacío a propósito: el contrato compartido no define
	// ninguno y un valor inventado de este lado rompería el descifrado de todo
	// mensaje que produzca una librería HPKE estándar.
	if cfg.Crypto.HPKEInfo != "" {
		t.Errorf("info = %q, se esperaba vacío por defecto", cfg.Crypto.HPKEInfo)
	}
	// Los defaults son los que fija el contrato compartido de US-02, no una
	// elección local: Gateway asume estos mismos TTL del lado de la
	// verificación.
	if cfg.Token.AccessTokenTTL != 15*time.Minute {
		t.Errorf("access token ttl = %v, se esperaban 15 minutos", cfg.Token.AccessTokenTTL)
	}
	if cfg.Token.RefreshTokenTTL != 30*24*time.Hour {
		t.Errorf("refresh token ttl = %v, se esperaban 30 días", cfg.Token.RefreshTokenTTL)
	}
	if cfg.Token.SessionMaxLifetime != 90*24*time.Hour {
		t.Errorf("vida máxima de la sesión = %v, se esperaban 90 días", cfg.Token.SessionMaxLifetime)
	}
	if cfg.Renaper.Timeout != 1500*time.Millisecond {
		t.Errorf("renaper timeout = %v, se esperaban 1500ms", cfg.Renaper.Timeout)
	}
}

// El parser de .env no soporta valores multilínea: el PEM viaja con los
// saltos de línea escapados y config.Load tiene que devolverlos intactos.
func TestLoadDesescapaLosSaltosDeLineaDeLaClaveJWT(t *testing.T) {
	aplicar(t, entornoMinimo())

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	got := cfg.Crypto.JWTPrivateKey.Reveal()
	if strings.Contains(got, `\n`) {
		t.Errorf("la clave conserva saltos de línea escapados: %q", got)
	}
	if !strings.Contains(got, "\n") {
		t.Errorf("la clave debería tener saltos de línea reales: %q", got)
	}
	if !strings.HasPrefix(got, "-----BEGIN PRIVATE KEY-----\n") {
		t.Errorf("la clave no empieza con el encabezado PEM esperado: %q", got)
	}
}

func TestLoadRechazaTTLNoPositivos(t *testing.T) {
	cases := map[string]map[string]string{
		"access token ttl cero":      {"ACCESS_TOKEN_TTL_MINUTES": "0"},
		"access token ttl negativo":  {"ACCESS_TOKEN_TTL_MINUTES": "-1"},
		"refresh token ttl cero":     {"REFRESH_TOKEN_TTL_DAYS": "0"},
		"refresh token ttl negativo": {"REFRESH_TOKEN_TTL_DAYS": "-1"},
		"vida máxima cero":           {"SESSION_MAX_DAYS": "0"},
		"vida máxima negativa":       {"SESSION_MAX_DAYS": "-1"},
		"vida máxima no numérica":    {"SESSION_MAX_DAYS": "mucho"},
	}

	for name, override := range cases {
		t.Run(name, func(t *testing.T) {
			env := entornoMinimo()
			for k, v := range override {
				env[k] = v
			}
			aplicar(t, env)

			if _, err := config.Load(); err == nil {
				t.Error("se esperaba un error de configuración")
			}
		})
	}
}

// Kong exige el claim `iss` para mapear el token al Consumer correcto: sin un
// default, un .env sin JWT_ISSUER emitiría tokens que el gateway rechaza.
func TestLoadUsaElIssuerPorDefecto(t *testing.T) {
	aplicar(t, entornoMinimo())

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if cfg.Token.Issuer != "vinculo-vial-identity" {
		t.Errorf("issuer = %q, se esperaba %q", cfg.Token.Issuer, "vinculo-vial-identity")
	}
}

func TestLoadAceptaUnIssuerPersonalizado(t *testing.T) {
	env := entornoMinimo()
	env["JWT_ISSUER"] = "otro-issuer"
	aplicar(t, env)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if cfg.Token.Issuer != "otro-issuer" {
		t.Errorf("issuer = %q, se esperaba %q", cfg.Token.Issuer, "otro-issuer")
	}
}

func TestLoadAceptaTTLPersonalizados(t *testing.T) {
	env := entornoMinimo()
	env["ACCESS_TOKEN_TTL_MINUTES"] = "5"
	env["REFRESH_TOKEN_TTL_DAYS"] = "7"
	env["SESSION_MAX_DAYS"] = "14"
	aplicar(t, env)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if cfg.Token.AccessTokenTTL != 5*time.Minute {
		t.Errorf("access token ttl = %v, se esperaban 5 minutos", cfg.Token.AccessTokenTTL)
	}
	if cfg.Token.RefreshTokenTTL != 7*24*time.Hour {
		t.Errorf("refresh token ttl = %v, se esperaban 7 días", cfg.Token.RefreshTokenTTL)
	}
	if cfg.Token.SessionMaxLifetime != 14*24*time.Hour {
		t.Errorf("vida máxima de la sesión = %v, se esperaban 14 días", cfg.Token.SessionMaxLifetime)
	}
}

// RENAPER_TIMEOUT es el presupuesto de la única dependencia síncrona saliente
// del servicio: tiene que poder ajustarse sin recompilar, igual que cualquier
// otro timeout de infraestructura.
func TestLoadAceptaUnRenaperTimeoutPersonalizado(t *testing.T) {
	env := entornoMinimo()
	env["RENAPER_TIMEOUT"] = "500ms"
	aplicar(t, env)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if cfg.Renaper.Timeout != 500*time.Millisecond {
		t.Errorf("renaper timeout = %v, se esperaban 500ms", cfg.Renaper.Timeout)
	}
}

func TestLoadRechazaRenaperTimeoutNoPositivo(t *testing.T) {
	cases := map[string]string{
		"cero":     "0s",
		"negativo": "-1s",
	}

	for name, valor := range cases {
		t.Run(name, func(t *testing.T) {
			env := entornoMinimo()
			env["RENAPER_TIMEOUT"] = valor
			aplicar(t, env)

			if _, err := config.Load(); err == nil {
				t.Error("se esperaba un error de configuración")
			}
		})
	}
}

func TestLoadConfiguraElCircuitBreakerDeRenaperPorDefecto(t *testing.T) {
	aplicar(t, entornoMinimo())

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if cfg.Renaper.BreakerFailureThreshold != 5 {
		t.Errorf("breaker failure threshold = %d, se esperaban 5", cfg.Renaper.BreakerFailureThreshold)
	}
	if cfg.Renaper.BreakerWindow != time.Minute {
		t.Errorf("breaker window = %v, se esperaba 1m", cfg.Renaper.BreakerWindow)
	}
	if cfg.Renaper.BreakerOpenDuration != 30*time.Second {
		t.Errorf("breaker open duration = %v, se esperaban 30s", cfg.Renaper.BreakerOpenDuration)
	}
}

func TestLoadAceptaUnCircuitBreakerDeRenaperPersonalizado(t *testing.T) {
	env := entornoMinimo()
	env["RENAPER_BREAKER_FAILURE_THRESHOLD"] = "2"
	env["RENAPER_BREAKER_WINDOW"] = "10s"
	env["RENAPER_BREAKER_OPEN_DURATION"] = "5s"
	aplicar(t, env)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if cfg.Renaper.BreakerFailureThreshold != 2 {
		t.Errorf("breaker failure threshold = %d, se esperaban 2", cfg.Renaper.BreakerFailureThreshold)
	}
	if cfg.Renaper.BreakerWindow != 10*time.Second {
		t.Errorf("breaker window = %v, se esperaban 10s", cfg.Renaper.BreakerWindow)
	}
	if cfg.Renaper.BreakerOpenDuration != 5*time.Second {
		t.Errorf("breaker open duration = %v, se esperaban 5s", cfg.Renaper.BreakerOpenDuration)
	}
}

func TestLoadRechazaElCircuitBreakerDeRenaperMalConfigurado(t *testing.T) {
	cases := map[string]map[string]string{
		"umbral cero":     {"RENAPER_BREAKER_FAILURE_THRESHOLD": "0"},
		"umbral negativo": {"RENAPER_BREAKER_FAILURE_THRESHOLD": "-1"},
		"ventana cero":    {"RENAPER_BREAKER_WINDOW": "0s"},
		"apertura cero":   {"RENAPER_BREAKER_OPEN_DURATION": "0s"},
	}

	for name, override := range cases {
		t.Run(name, func(t *testing.T) {
			env := entornoMinimo()
			for k, v := range override {
				env[k] = v
			}
			aplicar(t, env)

			if _, err := config.Load(); err == nil {
				t.Error("se esperaba un error de configuración")
			}
		})
	}
}

func TestLoadConfiguraLosConsumidoresPorDefecto(t *testing.T) {
	aplicar(t, entornoMinimo())

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if cfg.Consumer.Prefetch != 10 {
		t.Errorf("prefetch = %d, se esperaban 10", cfg.Consumer.Prefetch)
	}
	if cfg.Consumer.MaxRetries != 5 {
		t.Errorf("max retries = %d, se esperaban 5", cfg.Consumer.MaxRetries)
	}
	if cfg.Consumer.AlertRejectedQueue != "identity.alert-rejected.q" {
		t.Errorf("cola de rechazos = %q, se esperaba identity.alert-rejected.q", cfg.Consumer.AlertRejectedQueue)
	}
	if cfg.Reputation.FraudPenalty != 10 {
		t.Errorf("fraud penalty = %d, se esperaban 10", cfg.Reputation.FraudPenalty)
	}
	if cfg.Consumer.AlertReportedQueue != "identity.alert-reported.q" {
		t.Errorf("cola de reportes = %q, se esperaba identity.alert-reported.q", cfg.Consumer.AlertReportedQueue)
	}
	if cfg.Reputation.ReviewThreshold != 1 {
		t.Errorf("umbral de revisión = %d, se esperaba 1", cfg.Reputation.ReviewThreshold)
	}
}

func TestLoadAceptaUnUmbralDeRevisionPersonalizado(t *testing.T) {
	env := entornoMinimo()
	env["REPORT_REVIEW_THRESHOLD"] = "3"
	env["ALERT_REPORTED_QUEUE"] = "identity.otra.q"
	aplicar(t, env)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if cfg.Reputation.ReviewThreshold != 3 {
		t.Errorf("umbral de revisión = %d, se esperaba 3", cfg.Reputation.ReviewThreshold)
	}
	if cfg.Consumer.AlertReportedQueue != "identity.otra.q" {
		t.Errorf("cola de reportes = %q", cfg.Consumer.AlertReportedQueue)
	}
}

func TestLoadRechazaUnUmbralDeRevisionInvalido(t *testing.T) {
	// Con umbral 0 todo usuario quedaría en revisión sin recibir un reporte.
	for nombre, valor := range map[string]string{"cero": "0", "negativo": "-1", "no numérico": "uno"} {
		t.Run(nombre, func(t *testing.T) {
			env := entornoMinimo()
			env["REPORT_REVIEW_THRESHOLD"] = valor
			aplicar(t, env)

			if _, err := config.Load(); err == nil {
				t.Error("se esperaba un error de configuración")
			}
		})
	}
}

func TestLoadAceptaUnaReputacionPersonalizada(t *testing.T) {
	env := entornoMinimo()
	env["FRAUD_PENALTY"] = "25"
	env["ALERT_REJECTED_QUEUE"] = "identity.otra.q"
	aplicar(t, env)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if cfg.Reputation.FraudPenalty != 25 {
		t.Errorf("fraud penalty = %d, se esperaban 25", cfg.Reputation.FraudPenalty)
	}
	if cfg.Consumer.AlertRejectedQueue != "identity.otra.q" {
		t.Errorf("cola de rechazos = %q", cfg.Consumer.AlertRejectedQueue)
	}
}

func TestLoadRechazaUnaPenalizacionNegativa(t *testing.T) {
	// Una penalización negativa sumaría reputación al fraude.
	for nombre, valor := range map[string]string{"negativa": "-1", "no numérica": "diez"} {
		t.Run(nombre, func(t *testing.T) {
			env := entornoMinimo()
			env["FRAUD_PENALTY"] = valor
			aplicar(t, env)

			if _, err := config.Load(); err == nil {
				t.Error("se esperaba un error de configuración")
			}
		})
	}
}

func TestLoadAceptaUnosConsumidoresPersonalizados(t *testing.T) {
	env := entornoMinimo()
	env["RABBITMQ_PREFETCH"] = "1"
	env["MAX_RETRIES"] = "0"
	aplicar(t, env)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if cfg.Consumer.Prefetch != 1 {
		t.Errorf("prefetch = %d, se esperaba 1", cfg.Consumer.Prefetch)
	}
	if cfg.Consumer.MaxRetries != 0 {
		t.Errorf("max retries = %d, se esperaba 0: derivar a la DLQ sin reintentar es válido", cfg.Consumer.MaxRetries)
	}
}

func TestLoadRechazaLosConsumidoresMalConfigurados(t *testing.T) {
	cases := map[string]map[string]string{
		"prefetch cero":                 {"RABBITMQ_PREFETCH": "0"},
		"prefetch negativo":             {"RABBITMQ_PREFETCH": "-1"},
		"prefetch sobre el límite AMQP": {"RABBITMQ_PREFETCH": "65536"},
		"prefetch no numérico":          {"RABBITMQ_PREFETCH": "diez"},
		"max retries negativo":          {"MAX_RETRIES": "-1"},
		"max retries no numérico":       {"MAX_RETRIES": "cinco"},
	}

	for name, override := range cases {
		t.Run(name, func(t *testing.T) {
			env := entornoMinimo()
			for k, v := range override {
				env[k] = v
			}
			aplicar(t, env)

			if _, err := config.Load(); err == nil {
				t.Error("se esperaba un error de configuración")
			}
		})
	}
}

func TestLoadConfiguraElWorkerDeOutboxPorDefecto(t *testing.T) {
	aplicar(t, entornoMinimo())

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if cfg.Outbox.WorkerInterval != 2*time.Second {
		t.Errorf("worker interval = %v, se esperaban 2s", cfg.Outbox.WorkerInterval)
	}
	if cfg.Outbox.WorkerBatchSize != 20 {
		t.Errorf("worker batch size = %d, se esperaban 20", cfg.Outbox.WorkerBatchSize)
	}
}

func TestLoadAceptaUnWorkerDeOutboxPersonalizado(t *testing.T) {
	env := entornoMinimo()
	env["OUTBOX_WORKER_INTERVAL"] = "500ms"
	env["OUTBOX_WORKER_BATCH_SIZE"] = "5"
	aplicar(t, env)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if cfg.Outbox.WorkerInterval != 500*time.Millisecond {
		t.Errorf("worker interval = %v, se esperaban 500ms", cfg.Outbox.WorkerInterval)
	}
	if cfg.Outbox.WorkerBatchSize != 5 {
		t.Errorf("worker batch size = %d, se esperaban 5", cfg.Outbox.WorkerBatchSize)
	}
}

func TestLoadRechazaElWorkerDeOutboxMalConfigurado(t *testing.T) {
	cases := map[string]map[string]string{
		"intervalo cero":      {"OUTBOX_WORKER_INTERVAL": "0s"},
		"intervalo negativo":  {"OUTBOX_WORKER_INTERVAL": "-1s"},
		"batch size cero":     {"OUTBOX_WORKER_BATCH_SIZE": "0"},
		"batch size negativo": {"OUTBOX_WORKER_BATCH_SIZE": "-1"},
	}

	for name, override := range cases {
		t.Run(name, func(t *testing.T) {
			env := entornoMinimo()
			for k, v := range override {
				env[k] = v
			}
			aplicar(t, env)

			if _, err := config.Load(); err == nil {
				t.Error("se esperaba un error de configuración")
			}
		})
	}
}

// DialTimeout y Heartbeat no tenían variable de entorno propia: quedaban
// fijos en los defaults del paquete events sin forma de ajustarlos sin
// recompilar, al margen del resto de los timeouts salientes del servicio.
func TestLoadConfiguraElDialTimeoutYElHeartbeatDelBrokerPorDefecto(t *testing.T) {
	aplicar(t, entornoMinimo())

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if cfg.Events.DialTimeout != 10*time.Second {
		t.Errorf("dial timeout = %v, se esperaban 10s", cfg.Events.DialTimeout)
	}
	if cfg.Events.Heartbeat != 10*time.Second {
		t.Errorf("heartbeat = %v, se esperaban 10s", cfg.Events.Heartbeat)
	}
}

func TestLoadAceptaUnDialTimeoutYHeartbeatPersonalizados(t *testing.T) {
	env := entornoMinimo()
	env["RABBITMQ_DIAL_TIMEOUT"] = "2s"
	env["RABBITMQ_HEARTBEAT"] = "30s"
	aplicar(t, env)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if cfg.Events.DialTimeout != 2*time.Second {
		t.Errorf("dial timeout = %v, se esperaban 2s", cfg.Events.DialTimeout)
	}
	if cfg.Events.Heartbeat != 30*time.Second {
		t.Errorf("heartbeat = %v, se esperaban 30s", cfg.Events.Heartbeat)
	}
}

func TestLoadExigeLosSecretos(t *testing.T) {
	obligatorias := []string{
		"POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB",
		"IDENTITY_HPKE_PRIVATE_KEY", "AES_KEY", "HMAC_SECRET", "JWT_PRIVATE_KEY",
		"INTERNAL_SERVICE_TOKEN", "AUDIT_PUBLIC_KEY", "AUDIT_KEY_ID", "EMAIL_CODE_HMAC_KEY",
	}

	for _, faltante := range obligatorias {
		t.Run("sin "+faltante, func(t *testing.T) {
			env := entornoMinimo()
			delete(env, faltante)
			aplicar(t, env)

			_, err := config.Load()
			if err == nil {
				t.Fatalf("se esperaba un error al faltar %s", faltante)
			}
			if !strings.Contains(err.Error(), faltante) {
				t.Errorf("el error debería nombrar la variable faltante: %v", err)
			}
		})
	}
}

// Un arranque mal configurado debe informar todo lo que falta de una sola vez,
// no obligar a descubrirlo de a un despliegue por variable.
func TestLoadAcumulaLosErrores(t *testing.T) {
	aplicar(t, nil)

	_, err := config.Load()
	if err == nil {
		t.Fatal("se esperaba un error")
	}

	for _, faltante := range []string{"POSTGRES_USER", "IDENTITY_HPKE_PRIVATE_KEY", "AES_KEY", "HMAC_SECRET", "JWT_PRIVATE_KEY", "INTERNAL_SERVICE_TOKEN", "AUDIT_PUBLIC_KEY", "AUDIT_KEY_ID", "EMAIL_CODE_HMAC_KEY"} {
		if !strings.Contains(err.Error(), faltante) {
			t.Errorf("el error debería mencionar %s: %v", faltante, err)
		}
	}
}

func TestLoadRechazaValoresMalFormados(t *testing.T) {
	cases := map[string]map[string]string{
		"puerto no numérico":            {"HTTP_PORT": "ocho-mil"},
		"puerto fuera de rango":         {"HTTP_PORT": "70000"},
		"puerto interno fuera de rango": {"HTTP_INTERNAL_PORT": "70000"},
		"duración inválida":             {"HTTP_READ_TIMEOUT": "diez segundos"},
		"booleano inválido":             {"RABBITMQ_ENABLED": "quizás"},
		"nivel de log inválido":         {"LOG_LEVEL": "verboso"},
		"memoria Argon2 baja":           {"ARGON2_MEMORY_KIB": "1024"},
		"iteraciones Argon2 cero":       {"ARGON2_ITERATIONS": "0"},
		"pool ocioso mayor":             {"POSTGRES_MAX_OPEN_CONNS": "5", "POSTGRES_MAX_IDLE_CONNS": "10"},
		// El valor real que causó el incidente: el default de antes de la
		// selfie, olvidado en un .env que nunca se sincronizó con .env.example.
		"tope de body demasiado bajo para una selfie": {"HTTP_MAX_BODY_BYTES": "8192"},
	}

	for name, override := range cases {
		t.Run(name, func(t *testing.T) {
			env := entornoMinimo()
			for k, v := range override {
				env[k] = v
			}
			aplicar(t, env)

			if _, err := config.Load(); err == nil {
				t.Error("se esperaba un error de configuración")
			}
		})
	}
}

// El router interno pierde su aislamiento de puerto si comparte el
// mismo número que el público: dos *http.Server no pueden escuchar el mismo
// puerto, y si pudieran, ya no habría separación que defender.
func TestLoadRechazaElPuertoInternoIgualAlPublico(t *testing.T) {
	env := entornoMinimo()
	env["HTTP_PORT"] = "9000"
	env["HTTP_INTERNAL_PORT"] = "9000"
	aplicar(t, env)

	_, err := config.Load()
	if err == nil {
		t.Fatal("se esperaba un error de configuración")
	}
	if !strings.Contains(err.Error(), "HTTP_INTERNAL_PORT") {
		t.Errorf("el error debería nombrar la variable: %v", err)
	}
}

// INTERNAL_SERVICE_TOKEN es un secreto comparado byte a byte, sin ningún
// derivador de clave (Argon2) que compense un valor corto: su propia
// longitud es la única defensa contra que alguien lo adivine.
func TestLoadRechazaElSecretoDeServicioDemasiadoCorto(t *testing.T) {
	env := entornoMinimo()
	env["INTERNAL_SERVICE_TOKEN"] = strings.Repeat("a", 31)
	aplicar(t, env)

	_, err := config.Load()
	if err == nil {
		t.Fatal("se esperaba un error de configuración")
	}
	if !strings.Contains(err.Error(), "INTERNAL_SERVICE_TOKEN") {
		t.Errorf("el error debería nombrar la variable: %v", err)
	}
}

func TestLoadUsaElPuertoInternoPorDefecto(t *testing.T) {
	aplicar(t, entornoMinimo())

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if cfg.Internal.Port != 8081 {
		t.Errorf("puerto interno = %d, se esperaba 8081", cfg.Internal.Port)
	}
	if cfg.Internal.Addr() != ":8081" {
		t.Errorf("addr = %q, se esperaba \":8081\"", cfg.Internal.Addr())
	}
}

// Regresión del incidente real: un .env con HTTP_MAX_BODY_BYTES=8192 (el
// default de antes de la selfie) hacía que el servicio arrancara sin quejarse
// y rechazara el 100% de los registros recién con el primer intento real,
// con un error que no decía nada sobre el límite de body. El mensaje tiene
// que ser explícito para que la próxima vez se diagnostique desde el propio
// log de arranque, no desde una prueba E2E.
func TestLoadRechazaTopeDeBodyMenorAlMinimoViable(t *testing.T) {
	env := entornoMinimo()
	env["HTTP_MAX_BODY_BYTES"] = "8192"
	aplicar(t, env)

	_, err := config.Load()
	if err == nil {
		t.Fatal("se esperaba un error de configuración")
	}
	if !strings.Contains(err.Error(), "HTTP_MAX_BODY_BYTES") {
		t.Errorf("el error debería nombrar la variable: %v", err)
	}
	if !strings.Contains(err.Error(), "selfie") {
		t.Errorf("el error debería explicar por qué el límite importa, no solo que está mal: %v", err)
	}
}

// En producción no se admiten atajos que en local son cómodos.
func TestProduccionRechazaConfiguracionesInseguras(t *testing.T) {
	cases := map[string]map[string]string{
		"tráfico a la base en claro": {"POSTGRES_SSLMODE": "disable"},
		"log de SQL encendido":       {"POSTGRES_SSLMODE": "require", "POSTGRES_LOG_SQL": "true"},
		"eventos descartados":        {"POSTGRES_SSLMODE": "require", "RABBITMQ_ENABLED": "false"},
		"base efímera":               {"POSTGRES_SSLMODE": "require", "EPHEMERAL_DB": "true"},
	}

	for name, override := range cases {
		t.Run(name, func(t *testing.T) {
			env := entornoMinimo()
			env["APP_ENV"] = "production"
			env["RABBITMQ_ENABLED"] = "true"
			env["RABBITMQ_URL"] = "amqps://broker:5671/"
			for k, v := range override {
				env[k] = v
			}
			aplicar(t, env)

			if _, err := config.Load(); err == nil {
				t.Errorf("se esperaba que %q fuera rechazado en producción", name)
			}
		})
	}
}

// EPHEMERAL_DB borra el esquema completo en cada arranque: por defecto tiene
// que estar apagado, para que un .env sin esa variable nunca arranque en modo
// destructivo por accidente.
func TestLoadEphemeralDBApagadaPorDefecto(t *testing.T) {
	aplicar(t, entornoMinimo())

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if cfg.Postgres.EphemeralDB {
		t.Error("EphemeralDB debería ser false por defecto")
	}
}

// Fuera de producción, EPHEMERAL_DB=true es exactamente el caso de uso que
// pide (despliegues efímeros de pruebas E2E) y tiene que aceptarse.
func TestLoadEphemeralDBSeAceptaFueraDeProduccion(t *testing.T) {
	env := entornoMinimo()
	env["EPHEMERAL_DB"] = "true"
	aplicar(t, env)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if !cfg.Postgres.EphemeralDB {
		t.Error("EphemeralDB debería ser true")
	}
}

func TestProduccionBienConfiguradaLevanta(t *testing.T) {
	env := entornoMinimo()
	env["APP_ENV"] = "production"
	env["POSTGRES_SSLMODE"] = "require"
	env["RABBITMQ_ENABLED"] = "true"
	env["RABBITMQ_URL"] = "amqps://broker:5671/"
	aplicar(t, env)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if !cfg.IsProduction() {
		t.Error("se esperaba modo producción")
	}
}

func TestBrokerHabilitadoExigeUnaURLValida(t *testing.T) {
	cases := map[string]string{
		"sin URL":         "",
		"esquema erróneo": "http://broker:15672/",
	}

	for name, u := range cases {
		t.Run(name, func(t *testing.T) {
			env := entornoMinimo()
			env["RABBITMQ_ENABLED"] = "true"
			if u != "" {
				env["RABBITMQ_URL"] = u
			}
			aplicar(t, env)

			if _, err := config.Load(); err == nil {
				t.Error("se esperaba un error de configuración del broker")
			}
		})
	}
}

// La configuración se loguea entera en el arranque: ningún secreto puede salir
// por esa vía, ni con %v, ni con %#v, ni con slog.
func TestLosSecretosNoSeImprimen(t *testing.T) {
	const password = "sup3rs3cr3t"
	env := entornoMinimo()
	env["POSTGRES_PASSWORD"] = password
	env["RABBITMQ_ENABLED"] = "true"
	env["RABBITMQ_URL"] = "amqp://identity:otr0s3cr3t@broker:5672/"
	aplicar(t, env)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	logs := &strings.Builder{}
	slog.New(slog.NewTextHandler(logs, nil)).Info("arranque", slog.Any("config", cfg))

	rendered := []string{
		logs.String(),
		fmt.Sprint(cfg.Postgres.Password),
		fmt.Sprintf("%v %#v %s", cfg.Crypto.AESKey, cfg.Crypto.HMACSecret, cfg.Events.URL),
	}
	for _, secreto := range []string{password, "otr0s3cr3t"} {
		for _, salida := range rendered {
			if strings.Contains(salida, secreto) {
				t.Errorf("se filtró %q en: %s", secreto, salida)
			}
		}
	}

	// Y sin embargo el valor tiene que poder recuperarse explícitamente.
	if cfg.Postgres.Password.Reveal() != password {
		t.Error("Reveal debería devolver el valor en claro")
	}
	if !strings.Contains(cfg.Postgres.DSN(), password) {
		t.Error("el DSN debería llevar la contraseña real")
	}
}

// statement_timeout protege del lado del servidor contra una sentencia
// colgada, defensa en profundidad junto al deadline por consulta del
// cliente (internal/repository/postgres.queryTimeout).
func TestDSNIncluyeElStatementTimeoutPorDefecto(t *testing.T) {
	aplicar(t, entornoMinimo())

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if !strings.Contains(cfg.Postgres.DSN(), "statement_timeout=1500") {
		t.Errorf("DSN = %q, se esperaba statement_timeout=1500 (1500ms por defecto)", cfg.Postgres.DSN())
	}
}

func TestDSNRespetaUnStatementTimeoutPersonalizado(t *testing.T) {
	env := entornoMinimo()
	env["POSTGRES_STATEMENT_TIMEOUT"] = "500ms"
	aplicar(t, env)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if !strings.Contains(cfg.Postgres.DSN(), "statement_timeout=500") {
		t.Errorf("DSN = %q, se esperaba statement_timeout=500", cfg.Postgres.DSN())
	}
}

func TestLoadRechazaStatementTimeoutNoPositivo(t *testing.T) {
	cases := map[string]string{
		"cero":     "0s",
		"negativo": "-1s",
	}

	for name, valor := range cases {
		t.Run(name, func(t *testing.T) {
			env := entornoMinimo()
			env["POSTGRES_STATEMENT_TIMEOUT"] = valor
			aplicar(t, env)

			if _, err := config.Load(); err == nil {
				t.Error("se esperaba un error de configuración")
			}
		})
	}
}

func TestLoadDotEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")

	contenido := strings.Join([]string{
		"# comentario",
		"",
		"CLAVE_NUEVA=valor",
		`CLAVE_ENTRECOMILLADA="con espacios"`,
		"export CLAVE_EXPORTADA=exportada",
		"CLAVE_YA_DEFINIDA=del-archivo",
	}, "\n")
	if err := os.WriteFile(path, []byte(contenido), 0o600); err != nil {
		t.Fatalf("no se pudo escribir el archivo: %v", err)
	}

	t.Setenv("CLAVE_YA_DEFINIDA", "del-entorno")

	if err := config.LoadDotEnv(path); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	t.Cleanup(func() {
		for _, k := range []string{"CLAVE_NUEVA", "CLAVE_ENTRECOMILLADA", "CLAVE_EXPORTADA"} {
			os.Unsetenv(k)
		}
	})

	cases := map[string]string{
		"CLAVE_NUEVA":          "valor",
		"CLAVE_ENTRECOMILLADA": "con espacios",
		"CLAVE_EXPORTADA":      "exportada",
		// Precedencia deliberada: un .env olvidado en el disco no puede alterar
		// un despliegue donde la variable ya viene del orquestador.
		"CLAVE_YA_DEFINIDA": "del-entorno",
	}
	for k, want := range cases {
		if got := os.Getenv(k); got != want {
			t.Errorf("%s = %q, se esperaba %q", k, got, want)
		}
	}
}

// Que no exista .env es el caso normal en producción.
func TestLoadDotEnvIgnoraLaAusenciaDelArchivo(t *testing.T) {
	if err := config.LoadDotEnv(filepath.Join(t.TempDir(), "no-existe")); err != nil {
		t.Errorf("error inesperado: %v", err)
	}
}

func TestLoadDotEnvRechazaLineasMalFormadas(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("esto no es una asignación\n"), 0o600); err != nil {
		t.Fatalf("no se pudo escribir el archivo: %v", err)
	}

	if err := config.LoadDotEnv(path); err == nil {
		t.Error("se esperaba un error por una línea sin la forma CLAVE=valor")
	}
}

// Sellado hacia Audit (US-11): la clave pública y su id son obligatorios, y el
// servicio no arranca sin ellos.
func TestLoadCargaLaConfiguracionDeAudit(t *testing.T) {
	aplicar(t, entornoMinimo())

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if cfg.Audit.PublicKey == "" {
		t.Errorf("AUDIT_PUBLIC_KEY no se cargó")
	}
	if cfg.Audit.KeyID != "2026-11" {
		t.Errorf("AUDIT_KEY_ID = %q, se esperaba 2026-11", cfg.Audit.KeyID)
	}
}

func TestLoadExigeLaConfiguracionDeAudit(t *testing.T) {
	for _, variable := range []string{"AUDIT_PUBLIC_KEY", "AUDIT_KEY_ID"} {
		for nombre, valor := range map[string]string{"ausente": "", "en blanco": "   "} {
			t.Run(variable+" "+nombre, func(t *testing.T) {
				env := entornoMinimo()
				env[variable] = valor
				aplicar(t, env)

				_, err := config.Load()
				if err == nil {
					t.Fatal("se esperaba un error")
				}
				if !strings.Contains(err.Error(), variable) {
					t.Errorf("el error debería nombrar %s: %v", variable, err)
				}
			})
		}
	}
}

// Herencia de la sanción de una cuenta dada de baja (US-11): 1095 días por
// defecto, con el barrido a intervalo y lote operativos.
func TestLoadUsaLosDefaultsDeLaHerenciaDeSancion(t *testing.T) {
	aplicar(t, entornoMinimo())

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if cfg.Sanction.CarryoverDays != 1095 {
		t.Errorf("SANCTION_CARRYOVER_DAYS = %d, se esperaban 1095", cfg.Sanction.CarryoverDays)
	}
	if cfg.Sanction.SweepInterval != time.Hour {
		t.Errorf("SANCTION_CARRYOVER_SWEEP_INTERVAL = %v, se esperaba 1h", cfg.Sanction.SweepInterval)
	}
	if cfg.Sanction.SweepBatchSize != 500 {
		t.Errorf("SANCTION_CARRYOVER_SWEEP_BATCH_SIZE = %d, se esperaban 500", cfg.Sanction.SweepBatchSize)
	}
}

func TestLoadAceptaLaHerenciaDeSancionPersonalizada(t *testing.T) {
	env := entornoMinimo()
	env["SANCTION_CARRYOVER_DAYS"] = "1"
	env["SANCTION_CARRYOVER_SWEEP_INTERVAL"] = "30s"
	env["SANCTION_CARRYOVER_SWEEP_BATCH_SIZE"] = "10"
	aplicar(t, env)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if cfg.Sanction.CarryoverDays != 1 || cfg.Sanction.SweepInterval != 30*time.Second || cfg.Sanction.SweepBatchSize != 10 {
		t.Errorf("Sanction = %+v", cfg.Sanction)
	}
}

func TestLoadRechazaLaHerenciaDeSancionMalConfigurada(t *testing.T) {
	casos := map[string]struct {
		env      map[string]string
		variable string
	}{
		"días en cero":       {map[string]string{"SANCTION_CARRYOVER_DAYS": "0"}, "SANCTION_CARRYOVER_DAYS"},
		"días negativos":     {map[string]string{"SANCTION_CARRYOVER_DAYS": "-5"}, "SANCTION_CARRYOVER_DAYS"},
		"días no numéricos":  {map[string]string{"SANCTION_CARRYOVER_DAYS": "tres años"}, "SANCTION_CARRYOVER_DAYS"},
		"intervalo en cero":  {map[string]string{"SANCTION_CARRYOVER_SWEEP_INTERVAL": "0s"}, "SANCTION_CARRYOVER_SWEEP_INTERVAL"},
		"intervalo negativo": {map[string]string{"SANCTION_CARRYOVER_SWEEP_INTERVAL": "-1m"}, "SANCTION_CARRYOVER_SWEEP_INTERVAL"},
		"lote en cero":       {map[string]string{"SANCTION_CARRYOVER_SWEEP_BATCH_SIZE": "0"}, "SANCTION_CARRYOVER_SWEEP_BATCH_SIZE"},
	}

	for nombre, caso := range casos {
		t.Run(nombre, func(t *testing.T) {
			env := entornoMinimo()
			for k, v := range caso.env {
				env[k] = v
			}
			aplicar(t, env)

			_, err := config.Load()
			if err == nil {
				t.Fatal("se esperaba un error")
			}
			if !strings.Contains(err.Error(), caso.variable) {
				t.Errorf("el error debería nombrar %s: %v", caso.variable, err)
			}
		})
	}
}

// El log de arranque informa el id de la clave y la herencia, pero no vuelca la
// clave pública.
func TestLaConfiguracionLogueaAuditSinLaClave(t *testing.T) {
	env := entornoMinimo()
	env["AUDIT_PUBLIC_KEY"] = "clave-publica-que-no-debe-aparecer-en-el-log"
	aplicar(t, env)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	var salida strings.Builder
	slog.New(slog.NewTextHandler(&salida, nil)).Info("config", slog.Any("config", cfg))

	for _, esperado := range []string{"audit_key_id=2026-11", "sanction_carryover_days=1095"} {
		if !strings.Contains(salida.String(), esperado) {
			t.Errorf("el log debería informar %s: %s", esperado, salida.String())
		}
	}
	if strings.Contains(salida.String(), "clave-publica-que-no-debe-aparecer") {
		t.Errorf("el log no debería volcar la clave: %s", salida.String())
	}
}
