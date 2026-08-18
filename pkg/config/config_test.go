package config_test

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	}
}

func aplicar(t *testing.T, env map[string]string) {
	t.Helper()

	// Setenv restaura el valor previo al terminar el test.
	for _, k := range []string{
		"APP_ENV", "LOG_LEVEL", "HTTP_PORT", "HTTP_DEBUG", "HTTP_MAX_BODY_BYTES",
		"POSTGRES_HOST", "POSTGRES_PORT", "POSTGRES_USER", "POSTGRES_PASSWORD",
		"POSTGRES_DB", "POSTGRES_SSLMODE", "POSTGRES_LOG_SQL",
		"POSTGRES_MAX_OPEN_CONNS", "POSTGRES_MAX_IDLE_CONNS",
		"IDENTITY_HPKE_PRIVATE_KEY", "IDENTITY_HPKE_INFO", "AES_KEY", "HMAC_SECRET",
		"ARGON2_MEMORY_KIB", "ARGON2_ITERATIONS", "ARGON2_PARALLELISM",
		"RABBITMQ_ENABLED", "RABBITMQ_URL", "RABBITMQ_EXCHANGE",
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
}

func TestLoadExigeLosSecretos(t *testing.T) {
	obligatorias := []string{
		"POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB",
		"IDENTITY_HPKE_PRIVATE_KEY", "AES_KEY", "HMAC_SECRET",
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

	for _, faltante := range []string{"POSTGRES_USER", "IDENTITY_HPKE_PRIVATE_KEY", "AES_KEY", "HMAC_SECRET"} {
		if !strings.Contains(err.Error(), faltante) {
			t.Errorf("el error debería mencionar %s: %v", faltante, err)
		}
	}
}

func TestLoadRechazaValoresMalFormados(t *testing.T) {
	cases := map[string]map[string]string{
		"puerto no numérico":      {"HTTP_PORT": "ocho-mil"},
		"puerto fuera de rango":   {"HTTP_PORT": "70000"},
		"duración inválida":       {"HTTP_READ_TIMEOUT": "diez segundos"},
		"booleano inválido":       {"RABBITMQ_ENABLED": "quizás"},
		"nivel de log inválido":   {"LOG_LEVEL": "verboso"},
		"memoria Argon2 baja":     {"ARGON2_MEMORY_KIB": "1024"},
		"iteraciones Argon2 cero": {"ARGON2_ITERATIONS": "0"},
		"pool ocioso mayor":       {"POSTGRES_MAX_OPEN_CONNS": "5", "POSTGRES_MAX_IDLE_CONNS": "10"},
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
