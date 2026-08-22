package config_test

import (
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
		"POSTGRES_DB", "POSTGRES_SSLMODE", "POSTGRES_LOG_SQL",
		"POSTGRES_MAX_OPEN_CONNS", "POSTGRES_MAX_IDLE_CONNS",
		"IDENTITY_HPKE_PRIVATE_KEY", "IDENTITY_HPKE_INFO", "AES_KEY", "HMAC_SECRET",
		"JWT_PRIVATE_KEY", "ACCESS_TOKEN_TTL_MINUTES", "REFRESH_TOKEN_TTL_DAYS",
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
	// Los defaults son los que fija el contrato compartido de US-02, no una
	// elección local: Gateway asume estos mismos TTL del lado de la
	// verificación.
	if cfg.Token.AccessTokenTTL != 15*time.Minute {
		t.Errorf("access token ttl = %v, se esperaban 15 minutos", cfg.Token.AccessTokenTTL)
	}
	if cfg.Token.RefreshTokenTTL != 30*24*time.Hour {
		t.Errorf("refresh token ttl = %v, se esperaban 30 días", cfg.Token.RefreshTokenTTL)
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

func TestLoadAceptaTTLPersonalizados(t *testing.T) {
	env := entornoMinimo()
	env["ACCESS_TOKEN_TTL_MINUTES"] = "5"
	env["REFRESH_TOKEN_TTL_DAYS"] = "7"
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
}

func TestLoadExigeLosSecretos(t *testing.T) {
	obligatorias := []string{
		"POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB",
		"IDENTITY_HPKE_PRIVATE_KEY", "AES_KEY", "HMAC_SECRET", "JWT_PRIVATE_KEY",
		"INTERNAL_SERVICE_TOKEN",
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

	for _, faltante := range []string{"POSTGRES_USER", "IDENTITY_HPKE_PRIVATE_KEY", "AES_KEY", "HMAC_SECRET", "JWT_PRIVATE_KEY", "INTERNAL_SERVICE_TOKEN"} {
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

// El router interno de US-04 pierde su aislamiento de puerto si comparte el
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
