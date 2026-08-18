// Package config carga y valida la configuración del servicio desde el entorno.
//
// Todo se valida en el arranque, incluido el material criptográfico: si una
// clave falta, no es base64 o tiene el largo equivocado, el proceso no levanta.
// Descubrirlo con el primer vecino que intenta registrarse es mucho peor.
package config

import (
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"
)

// Secret envuelve un valor sensible para que no pueda imprimirse por accidente.
//
// Los tres métodos que Go usa para formatear un valor —String, GoString y
// LogValue— quedan redactados, de modo que un %v, un %#v o un slog.Any sobre la
// configuración no filtren la clave.
type Secret string

func (s Secret) String() string       { return "[redactado]" }
func (s Secret) GoString() string     { return "[redactado]" }
func (s Secret) LogValue() slog.Value { return slog.StringValue("[redactado]") }

// Reveal devuelve el valor en claro. El nombre es explícito a propósito: cada
// uso queda visible en una búsqueda del código.
func (s Secret) Reveal() string { return string(s) }

// Config es la configuración completa del servicio.
type Config struct {
	Env      string
	LogLevel slog.Level

	HTTP     HTTPConfig
	Postgres PostgresConfig
	Crypto   CryptoConfig
	Events   EventsConfig
}

// HTTPConfig son los parámetros del servidor.
type HTTPConfig struct {
	Port int
	// ReadTimeout y WriteTimeout acotan a un cliente lento; sin ellos, unas
	// pocas conexiones abiertas y ociosas agotan el servidor.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
	// ShutdownTimeout es lo que se espera a que terminen las peticiones en
	// curso antes de cortar.
	ShutdownTimeout time.Duration
	MaxBodyBytes    int64
	Debug           bool
}

// Addr es la dirección de escucha.
func (c HTTPConfig) Addr() string { return fmt.Sprintf(":%d", c.Port) }

// PostgresConfig son los parámetros de la base.
type PostgresConfig struct {
	Host     string
	Port     int
	User     string
	Password Secret
	Database string
	SSLMode  string

	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
	LogSQL          bool
}

// DSN arma la cadena de conexión.
func (c PostgresConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password.Reveal(), c.Database, c.SSLMode,
	)
}

// CryptoConfig agrupa el material criptográfico. Son tres claves independientes
// y no se derivan una de otra: comprometer una no debe comprometer las demás.
type CryptoConfig struct {
	// HPKEPrivateKey descifra el mensaje de transporte (base64 de 32 bytes). Es
	// la mitad privada del par cuya pública embebe el frontend en
	// IDENTITY_HPKE_PUBLIC_KEY.
	HPKEPrivateKey Secret
	// HPKEInfo es el contexto de derivación (`info` en RFC 9180). Debe coincidir
	// byte a byte con el que use el cliente al cifrar; si difiere, el AEAD no
	// autentica y todas las altas fallan.
	//
	// El valor por defecto es vacío, que es lo que produce una librería HPKE
	// cuando no se le pasa un info explícito: el contrato compartido no define
	// ninguno, así que lo interoperable es no inventarlo de este lado.
	HPKEInfo string
	// AESKey cifra el DNI at-rest (base64 de 32 bytes).
	AESKey Secret
	// HMACSecret genera el Blind Index del DNI (base64 de 32 bytes o más).
	HMACSecret Secret

	Argon2MemoryKiB   int
	Argon2Iterations  int
	Argon2Parallelism int
}

// EventsConfig son los parámetros del broker.
type EventsConfig struct {
	// Enabled en false usa el publisher inerte. El broker es global y no forma
	// parte del docker-compose de este servicio, así que el entorno local
	// levanta con esta opción apagada.
	Enabled        bool
	URL            Secret
	Exchange       string
	Producer       string
	PublishTimeout time.Duration
}

// Valores por defecto pensados para que el entorno local levante sin definir
// más que los secretos.
const (
	defaultHTTPPort        = 8080
	defaultReadTimeout     = 10 * time.Second
	defaultWriteTimeout    = 15 * time.Second
	defaultIdleTimeout     = 60 * time.Second
	defaultShutdownTimeout = 15 * time.Second
	// El payload incluye una selfie: ver la nota de router.DefaultMaxBodyBytes
	// para el cálculo. Los dos valores deben moverse juntos.
	defaultMaxBodyBytes = 10 << 20
	// minViableMaxBodyBytes es el piso que exige (*Config).validate(); ver el
	// comentario ahí.
	// 512 KiB es 64 veces el default de antes de la selfie (8 KiB) —lo bastante
	// por encima como para que un valor "olvidado sin actualizar" quede
	// atrapado acá, y lo bastante por debajo del default (10 MiB) como para
	// dejarle margen real a un operador que sepa que su app produce selfies
	// livianas y quiera ajustar el límite hacia abajo a propósito.
	minViableMaxBodyBytes      = 512 << 10
	defaultMaxOpenConns        = 20
	defaultMaxIdleConns        = 5
	defaultConnMaxLifetime     = 30 * time.Minute
	defaultConnMaxIdleTime     = 5 * time.Minute
	defaultHPKEInfo            = ""
	defaultEventsExchange      = "vinculo-vial.events"
	defaultEventsProducer      = "vinculo-vial-identity"
	defaultEventsPublishTimeut = 5 * time.Second
)

// Load lee la configuración del entorno y la valida.
func Load() (*Config, error) {
	r := &reader{}

	cfg := &Config{
		Env: r.str("APP_ENV", "development"),

		HTTP: HTTPConfig{
			Port:            r.integer("HTTP_PORT", defaultHTTPPort),
			ReadTimeout:     r.duration("HTTP_READ_TIMEOUT", defaultReadTimeout),
			WriteTimeout:    r.duration("HTTP_WRITE_TIMEOUT", defaultWriteTimeout),
			IdleTimeout:     r.duration("HTTP_IDLE_TIMEOUT", defaultIdleTimeout),
			ShutdownTimeout: r.duration("HTTP_SHUTDOWN_TIMEOUT", defaultShutdownTimeout),
			MaxBodyBytes:    int64(r.integer("HTTP_MAX_BODY_BYTES", defaultMaxBodyBytes)),
		},

		Postgres: PostgresConfig{
			Host:            r.str("POSTGRES_HOST", "localhost"),
			Port:            r.integer("POSTGRES_PORT", 5432),
			User:            r.required("POSTGRES_USER"),
			Password:        Secret(r.required("POSTGRES_PASSWORD")),
			Database:        r.required("POSTGRES_DB"),
			SSLMode:         r.str("POSTGRES_SSLMODE", "disable"),
			MaxOpenConns:    r.integer("POSTGRES_MAX_OPEN_CONNS", defaultMaxOpenConns),
			MaxIdleConns:    r.integer("POSTGRES_MAX_IDLE_CONNS", defaultMaxIdleConns),
			ConnMaxLifetime: r.duration("POSTGRES_CONN_MAX_LIFETIME", defaultConnMaxLifetime),
			ConnMaxIdleTime: r.duration("POSTGRES_CONN_MAX_IDLE_TIME", defaultConnMaxIdleTime),
			LogSQL:          r.boolean("POSTGRES_LOG_SQL", false),
		},

		Crypto: CryptoConfig{
			HPKEPrivateKey:    Secret(r.required("IDENTITY_HPKE_PRIVATE_KEY")),
			HPKEInfo:          r.str("IDENTITY_HPKE_INFO", defaultHPKEInfo),
			AESKey:            Secret(r.required("AES_KEY")),
			HMACSecret:        Secret(r.required("HMAC_SECRET")),
			Argon2MemoryKiB:   r.integer("ARGON2_MEMORY_KIB", 64*1024),
			Argon2Iterations:  r.integer("ARGON2_ITERATIONS", 3),
			Argon2Parallelism: r.integer("ARGON2_PARALLELISM", 1),
		},

		Events: EventsConfig{
			Enabled:        r.boolean("RABBITMQ_ENABLED", false),
			URL:            Secret(r.str("RABBITMQ_URL", "")),
			Exchange:       r.str("RABBITMQ_EXCHANGE", defaultEventsExchange),
			Producer:       r.str("RABBITMQ_PRODUCER", defaultEventsProducer),
			PublishTimeout: r.duration("RABBITMQ_PUBLISH_TIMEOUT", defaultEventsPublishTimeut),
		},
	}

	cfg.LogLevel = parseLevel(r, r.str("LOG_LEVEL", "info"))
	cfg.HTTP.Debug = r.boolean("HTTP_DEBUG", cfg.Env == "development")

	if err := r.err(); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) validate() error {
	r := &reader{}

	if c.HTTP.Port < 1 || c.HTTP.Port > 65535 {
		r.fail("config: HTTP_PORT fuera de rango: %d", c.HTTP.Port)
	}
	if c.HTTP.MaxBodyBytes <= 0 {
		r.fail("config: HTTP_MAX_BODY_BYTES debe ser positivo")
	} else if c.HTTP.MaxBodyBytes < minViableMaxBodyBytes {
		// No es un tope estricto arbitrario: por debajo de esto, ningún alta
		// real puede completarse, porque el payload incluye una selfie. Un
		// valor así no es "conservador", es un servicio que rechaza el 100% de
		// los registros legítimos sin decir por qué —exactamente lo que pasó
		// cuando HTTP_MAX_BODY_BYTES quedó en 8 KiB (el valor de antes de la
		// selfie) en un .env que nunca se sincronizó con .env.example—. Mejor
		// que el proceso ni arranque a que arranque y falle en silencio recién
		// con el primer registro real.
		r.fail("config: HTTP_MAX_BODY_BYTES (%d) es menor al mínimo viable (%d): el payload incluye una selfie, y con este límite ningún alta real podría completarse",
			c.HTTP.MaxBodyBytes, minViableMaxBodyBytes)
	}
	if c.Postgres.MaxOpenConns < 1 {
		r.fail("config: POSTGRES_MAX_OPEN_CONNS debe ser al menos 1")
	}
	if c.Postgres.MaxIdleConns > c.Postgres.MaxOpenConns {
		r.fail("config: POSTGRES_MAX_IDLE_CONNS (%d) no puede superar POSTGRES_MAX_OPEN_CONNS (%d)",
			c.Postgres.MaxIdleConns, c.Postgres.MaxOpenConns)
	}

	// sslmode=disable manda el tráfico en claro. Vale en el compose local, donde
	// la base vive en la misma red de Docker, pero nunca fuera de ahí.
	if c.IsProduction() && c.Postgres.SSLMode == "disable" {
		r.fail("config: POSTGRES_SSLMODE=disable no es admisible con APP_ENV=production")
	}
	if c.IsProduction() && c.Postgres.LogSQL {
		r.fail("config: POSTGRES_LOG_SQL registraría el DNI cifrado y el hash de contraseña; no es admisible en producción")
	}

	if c.Crypto.Argon2MemoryKiB < 19*1024 {
		r.fail("config: ARGON2_MEMORY_KIB debe ser al menos 19456")
	}
	if c.Crypto.Argon2Iterations < 1 {
		r.fail("config: ARGON2_ITERATIONS debe ser al menos 1")
	}
	if c.Crypto.Argon2Parallelism < 1 || c.Crypto.Argon2Parallelism > 255 {
		r.fail("config: ARGON2_PARALLELISM debe estar entre 1 y 255")
	}

	if c.Events.Enabled {
		if c.Events.URL.Reveal() == "" {
			r.fail("config: RABBITMQ_URL es obligatoria con RABBITMQ_ENABLED=true")
		} else if u, err := url.Parse(c.Events.URL.Reveal()); err != nil {
			r.fail("config: RABBITMQ_URL no es una URL válida")
		} else if u.Scheme != "amqp" && u.Scheme != "amqps" {
			r.fail("config: RABBITMQ_URL debe usar el esquema amqp o amqps, se recibió %q", u.Scheme)
		}
	} else if c.IsProduction() {
		// El publisher inerte descarta los eventos: es un modo de desarrollo.
		r.fail("config: RABBITMQ_ENABLED=false descartaría los eventos; no es admisible con APP_ENV=production")
	}

	return r.err()
}

// IsProduction informa si el servicio corre con la configuración endurecida.
func (c *Config) IsProduction() bool {
	return strings.EqualFold(c.Env, "production")
}

// LogValue expone la configuración al log sin ningún secreto: el tipo Secret ya
// se redacta solo, pero se enumeran los campos explícitamente para que sumar uno
// nuevo obligue a decidir si se registra.
func (c *Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("env", c.Env),
		slog.String("log_level", c.LogLevel.String()),
		slog.Int("http_port", c.HTTP.Port),
		slog.Bool("http_debug", c.HTTP.Debug),
		slog.String("postgres_host", c.Postgres.Host),
		slog.Int("postgres_port", c.Postgres.Port),
		slog.String("postgres_db", c.Postgres.Database),
		slog.String("postgres_sslmode", c.Postgres.SSLMode),
		slog.Bool("events_enabled", c.Events.Enabled),
		slog.String("events_exchange", c.Events.Exchange),
		slog.Int("argon2_memory_kib", c.Crypto.Argon2MemoryKiB),
	)
}

func parseLevel(r *reader, raw string) slog.Level {
	switch strings.ToLower(raw) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		r.fail("config: LOG_LEVEL debe ser debug, info, warn o error, se recibió %q", raw)
		return slog.LevelInfo
	}
}
