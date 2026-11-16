// Package config carga y valida la configuración del servicio desde el entorno.
//
// Todo se valida en el arranque, incluido el material criptográfico: si una
// clave falta, no es base64 o tiene el largo equivocado, el proceso no levanta.
// Descubrirlo con el primer vecino que intenta registrarse es mucho peor.
package config

import (
	"encoding/base64"
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

	HTTP       HTTPConfig
	Internal   InternalConfig
	Postgres   PostgresConfig
	Crypto     CryptoConfig
	Events     EventsConfig
	Consumer   ConsumerConfig
	Reputation ReputationConfig
	Audit      AuditConfig
	Sanction   SanctionConfig
	Token      TokenConfig
	Renaper    RenaperConfig
	Outbox     OutboxConfig
	Email      EmailConfig
	Terms      TermsConfig
}

// TermsConfig son los parámetros de la aceptación de los Términos y Condiciones
// en el alta (US-19).
type TermsConfig struct {
	// CurrentVersion es la versión vigente del documento (TERMS_CURRENT_VERSION).
	// El alta solo la acepta si coincide exactamente, y es lo que se guarda en
	// users.terms_version (varchar(16)). Tiene que coincidir con la que lleva el
	// Frontend en TERMS_VERSION.
	CurrentVersion string
	// RequireOnSignup exige que el alta traiga la versión vigente
	// (SIGNUP_REQUIRE_TERMS). En false existe solo para no romper el alta entre el
	// merge de este servicio y el del Frontend: validate() lo rechaza con
	// APP_ENV=production.
	RequireOnSignup bool
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

// InternalConfig son los parámetros del router interno (rutas /internal/*,
// hoy POST /internal/audit/dni). Se sirve en un
// *http.Server separado del público, en su propio puerto, que ni Kong ni el
// docker-compose de este servicio publican fuera de la red interna.
//
// Esa separación de puerto es una condición necesaria pero no suficiente:
// dentro de la red Docker cualquier contenedor puede alcanzar cualquier
// puerto de otro. ServiceToken es la segunda capa —un secreto compartido de
// servicio a servicio que el servicio llamador (vinculo-vial-alert) debe presentar en cada
// petición— y las dos capas son independientes entre sí (ver el comentario
// de InternalRouterConfig en internal/delivery/http).
type InternalConfig struct {
	Port         int
	ServiceToken Secret
}

// Addr es la dirección de escucha del router interno.
func (c InternalConfig) Addr() string { return fmt.Sprintf(":%d", c.Port) }

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
	// EphemeralDB borra y recrea el esquema `public` en cada arranque, antes
	// de AutoMigrate, para que un despliegue efímero de pruebas E2E siempre
	// levante con una base vacía. Es destructivo por diseño: nunca admisible
	// con APP_ENV=production (ver (*Config).validate()).
	EphemeralDB bool
	// StatementTimeout acota, del lado del servidor, cualquier sentencia que
	// exceda este plazo (protege contra una consulta colgada aunque el
	// cliente Go no respete su propio contexto). Es defensa en profundidad
	// junto al deadline por consulta que aplica cada repositorio
	// (internal/repository/postgres.queryTimeout): ese protege contra la
	// espera por una conexión libre del pool, este contra una sentencia que
	// ya arrancó y se cuelga.
	StatementTimeout time.Duration
}

// DSN arma la cadena de conexión. pgx trata un parámetro que no reconoce como
// propio de la cadena de conexión como un parámetro de sesión de PostgreSQL
// (equivalente a un SET tras conectar), así que alcanza con incluir
// statement_timeout acá, sin tocar el driver.
func (c PostgresConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s statement_timeout=%d",
		c.Host, c.Port, c.User, c.Password.Reveal(), c.Database, c.SSLMode,
		c.StatementTimeout.Milliseconds(),
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
	// JWTPrivateKey firma el Access Token (RS256, PEM RSA). Identity es el único
	// custodio: Gateway y el resto de la plataforma reciben solo la Public Key
	// correspondiente (JWT_PUBLIC_KEY), que este servicio nunca necesita leer.
	//
	// En el .env viaja en una sola línea, con los saltos de línea del PEM
	// escapados como \n literal —el parser de .env no soporta valores
	// multilínea—; se desescapan acá, antes de guardarla. cmd/genkeys ya la
	// imprime en ese formato, lista para pegar.
	JWTPrivateKey Secret

	Argon2MemoryKiB   int
	Argon2Iterations  int
	Argon2Parallelism int
}

// TokenConfig son los parámetros de los tokens de sesión que emite el login
// (US-02).
type TokenConfig struct {
	// AccessTokenTTL es la vida del JWT de acceso. El contrato compartido fija
	// la variable en minutos (ACCESS_TOKEN_TTL_MINUTES), no como duración de Go.
	AccessTokenTTL time.Duration
	// RefreshTokenTTL es la vida del Refresh Token opaco. El contrato compartido
	// fija la variable en días (REFRESH_TOKEN_TTL_DAYS).
	RefreshTokenTTL time.Duration
	// SessionMaxLifetime es la vida máxima de una sesión desde el inicio de
	// sesión con credenciales (US-12): por mucho que el Refresh Token rote, al
	// pasarla se exige volver a ingresar. REFRESH_TOKEN_TTL_DAYS sigue siendo
	// la inactividad máxima. Variable: SESSION_MAX_DAYS, en días.
	SessionMaxLifetime time.Duration
	// Issuer es el claim `iss` que lleva el Access Token. Kong lo exige para
	// mapear el token al Consumer correcto antes de validar la firma RS256.
	Issuer string
}

// RenaperConfig son los parámetros de la consulta a RENAPER (US-01).
type RenaperConfig struct {
	// Timeout acota la consulta completa —conexión y lectura—. Sin este plazo
	// propio, una llamada a RENAPER solo queda limitada por el contexto de la
	// petición HTTP entrante, que no tiene por qué dejarle a esta única
	// dependencia síncrona del servicio un presupuesto razonable dentro del
	// total de /auth/signup.
	Timeout time.Duration
	// BreakerFailureThreshold es la cantidad de fallas —timeout, conexión
	// rechazada, 5xx del upstream— dentro de BreakerWindow que abren el
	// circuito hacia RENAPER.
	BreakerFailureThreshold int
	// BreakerWindow es la ventana deslizante sobre la que se cuentan esas
	// fallas.
	BreakerWindow time.Duration
	// BreakerOpenDuration es cuánto permanece abierto el circuito antes de
	// admitir una única llamada de prueba (medio abierto).
	BreakerOpenDuration time.Duration
}

// OutboxConfig son los parámetros del worker en background que publica los
// eventos del patrón Transactional Outbox (US-06).
type OutboxConfig struct {
	// WorkerInterval es cada cuánto corre un ciclo de publicación.
	WorkerInterval time.Duration
	// WorkerBatchSize acota cuántos eventos pendientes se intentan publicar
	// por ciclo.
	WorkerBatchSize int
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
	// DialTimeout acota el establecimiento de la conexión AMQP, incluida una
	// reconexión a mitad de un publish: ver la nota de dialWithDeadline en
	// internal/delivery/events.
	DialTimeout time.Duration
	// Heartbeat es el latido de la conexión AMQP; permite detectar un broker
	// caído sin esperar al timeout de TCP.
	Heartbeat time.Duration
}

// ConsumerConfig son los parámetros comunes a los consumidores de eventos
// (US-08). La conexión con el broker es la de EventsConfig.
type ConsumerConfig struct {
	// Prefetch es el tope de mensajes sin ack que el broker adelanta a cada
	// consumidor (basic.qos). Sin él, el broker empuja toda la cola al proceso.
	Prefetch int
	// MaxRetries es la cantidad máxima de reintentos de un fallo transitorio.
	// Agotada, el mensaje se deriva a la DLQ.
	MaxRetries int
	// AlertRejectedQueue es la cola de trabajo de alert.rejected. La declara
	// vinculo-vial-core; este servicio solo la consume.
	AlertRejectedQueue string
	// AlertReportedQueue es la cola de trabajo de alert.reported. También la
	// declara vinculo-vial-core.
	AlertReportedQueue string
}

// ReputationConfig son los parámetros de la reputación de los usuarios
// (US-08). Se configuran por entorno: nunca van fijos en el código.
type ReputationConfig struct {
	// FraudPenalty son los puntos que se restan a reputation_score por cada
	// alerta rechazada por fraude.
	FraudPenalty int
	// ReviewThreshold es la cantidad de reportes que pone a un usuario en
	// revisión (UNDER_REVIEW): sin poder enviar alertas, pero con el resto de
	// la cuenta intacta.
	ReviewThreshold int
}

// AuditConfig son los parámetros con que Identity sella el DNI del emisor de una
// alerta hacia el Audit Service (US-11).
type AuditConfig struct {
	// PublicKey es la clave pública X25519 de Audit, en base64 (AUDIT_PUBLIC_KEY).
	// La privada se genera fuera de línea con audit-keygen, la custodia el
	// responsable legal y ningún servicio la carga, ni siquiera Audit. Es
	// obligatoria: sin ella no hay forma de sellar el DNI, y el servicio no
	// arranca. No es un secreto, pero tampoco se vuelca al log. Tiene que
	// coincidir con la de Vehicle.
	PublicKey string
	// KeyID es el id corto del par de claves (AUDIT_KEY_ID, por ejemplo "2026-11"):
	// viaja con cada criptograma para poder rotar las claves. Tiene que coincidir
	// con el de Vehicle. Su formato lo valida auditseal.New en el arranque.
	KeyID string
}

// SanctionConfig son los parámetros de la herencia de la sanción de una cuenta
// penalizada que se dio de baja (US-11).
type SanctionConfig struct {
	// CarryoverDays son los días que la sanción se hereda si el mismo DNI se vuelve
	// a registrar (SANCTION_CARRYOVER_DAYS): 1095, tres años, por el art. 2561 del
	// CCyC y el art. 62 del CP.
	CarryoverDays int
	// SweepInterval es cada cuánto corre el barrido que borra las sanciones
	// vencidas (SANCTION_CARRYOVER_SWEEP_INTERVAL).
	SweepInterval time.Duration
	// SweepBatchSize acota cuántas sanciones borra cada sentencia del barrido
	// (SANCTION_CARRYOVER_SWEEP_BATCH_SIZE).
	SweepBatchSize int
}

// EmailConfig son los parámetros de la verificación de email del alta y de la
// recuperación de contraseña (US-13). Los valores por defecto son los del
// contrato de la etapa 1, salvo la clave, que es obligatoria.
type EmailConfig struct {
	// CodeHMACKey es la clave con que se guardan el subject y el código de los
	// desafíos (EMAIL_CODE_HMAC_KEY: base64 de al menos 32 bytes). Es propia de
	// este mecanismo y no puede coincidir con ninguna otra clave del servicio:
	// la genera cmd/genkeys.
	CodeHMACKey Secret
	// CodeTTL es la vida del código enviado por email (EMAIL_CODE_TTL_MINUTES).
	CodeTTL time.Duration
	// CodeMaxAttempts es el tope de intentos de un código (EMAIL_CODE_MAX_ATTEMPTS).
	CodeMaxAttempts int
	// CodeResendInterval es el mínimo entre dos envíos al mismo subject
	// (EMAIL_CODE_RESEND_SECONDS). Tiene que coincidir con el del Frontend, que lo
	// usa en la cuenta regresiva del botón "Reenviar".
	CodeResendInterval time.Duration
	// CodeMaxSendsPerDay es el tope de envíos por subject en una ventana de 24 h
	// (EMAIL_CODE_MAX_SENDS_PER_DAY).
	CodeMaxSendsPerDay int
	// VerificationGrantTTL es la vida del token de verificación de email que
	// consume el alta (EMAIL_VERIFICATION_GRANT_TTL_MINUTES).
	VerificationGrantTTL time.Duration
	// ResetGrantTTL es la vida del reset_token de la recuperación
	// (PASSWORD_RESET_GRANT_TTL_MINUTES).
	ResetGrantTTL time.Duration
	// ResetMaxIdentityAttempts es el tope de rechazos de identidad de un
	// reset_token (PASSWORD_RESET_MAX_IDENTITY_ATTEMPTS).
	ResetMaxIdentityAttempts int
	// RequireVerificationOnSignup exige el token de verificación de email en el
	// alta (SIGNUP_REQUIRE_EMAIL_VERIFICATION). En false existe solo para no romper
	// el alta en desarrollo mientras el Frontend no lo envía: validate() lo
	// rechaza con APP_ENV=production.
	RequireVerificationOnSignup bool
	// SweepInterval es cada cuánto corre el barrido que borra los desafíos vencidos
	// (EMAIL_CHALLENGE_SWEEP_INTERVAL).
	SweepInterval time.Duration
	// SweepBatchSize acota cuántos desafíos borra cada sentencia del barrido
	// (EMAIL_CHALLENGE_SWEEP_BATCH_SIZE).
	SweepBatchSize int
}

// Valores por defecto pensados para que el entorno local levante sin definir
// más que los secretos.
const (
	// Los valores de US-13 son los del contrato de la etapa 1. El barrido sigue la
	// misma decisión operativa que el de sanciones: borrar con una hora de demora
	// no cambia nada.
	defaultEmailCodeTTLMinutes             = 10
	defaultEmailCodeMaxAttempts            = 5
	defaultEmailCodeResendSeconds          = 60
	defaultEmailCodeMaxSendsPerDay         = 5
	defaultEmailVerificationGrantMinutes   = 30
	defaultPasswordResetGrantMinutes       = 15
	defaultPasswordResetMaxIdentityRetries = 3
	defaultEmailChallengeSweepInterval     = time.Hour
	defaultEmailChallengeSweepBatchSize    = 500
	// minEmailCodeHMACKeyLength es el mínimo de la clave de los desafíos: el
	// tamaño de salida de SHA-256.
	minEmailCodeHMACKeyLength = 32
	// defaultTermsCurrentVersion es la versión del texto que fija el contrato de
	// US-19. maxTermsVersionLength es el largo de la columna terms_version.
	defaultTermsCurrentVersion = "1.0"
	maxTermsVersionLength      = 16
	// defaultSanctionCarryoverDays es el contrato de US-11: tres años.
	defaultSanctionCarryoverDays = 1095
	// defaultSanctionSweepInterval y defaultSanctionSweepBatchSize son una
	// decisión operativa: el plazo es de años, así que borrar una sanción con una
	// hora de demora no cambia nada.
	defaultSanctionSweepInterval  = time.Hour
	defaultSanctionSweepBatchSize = 500
	defaultHTTPPort               = 8080
	defaultInternalPort           = 8081
	// minServiceTokenLength es el piso de entropía admitido para
	// INTERNAL_SERVICE_TOKEN: es un secreto compartido comparado byte a byte
	// (no una contraseña con Argon2 detrás), así que su propia longitud es
	// toda la defensa contra que alguien lo adivine.
	minServiceTokenLength  = 32
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
	minViableMaxBodyBytes  = 512 << 10
	defaultMaxOpenConns    = 20
	defaultMaxIdleConns    = 5
	defaultConnMaxLifetime = 30 * time.Minute
	defaultConnMaxIdleTime = 5 * time.Minute
	// defaultStatementTimeout y defaultRenaperTimeout son las dos
	// dependencias síncronas que /auth/signup encadena en el peor caso
	// (RENAPER y la escritura en base): 1500 ms × 2 + ~500 ms de margen para
	// Argon2id y el resto de la CPU propia (cifrado, framework) ≈ 3500 ms,
	// bajo el techo de 5000 ms del contrato de resiliencia para el request
	// completo. defaultEventsPublishTimeut tiene el mismo valor por
	// coherencia, pero lo consume el worker del outbox, fuera de cualquier
	// request.
	defaultStatementTimeout = 1500 * time.Millisecond
	defaultHPKEInfo         = ""
	defaultRenaperTimeout   = 1500 * time.Millisecond
	// Mismos valores que renaper.DefaultBreaker*: no hay un import cruzado
	// entre este paquete y renaper —acá solo se leen variables de entorno—,
	// así que el default se repite a propósito, igual que ya ocurre con
	// defaultEventsExchange frente a events.DefaultExchange.
	defaultRenaperBreakerFailureThreshold = 5
	defaultRenaperBreakerWindow           = time.Minute
	defaultRenaperBreakerOpenDuration     = 30 * time.Second
	// defaultOutboxWorkerInterval y defaultOutboxWorkerBatchSize no derivan
	// del presupuesto de ningún request: el worker corre fuera del camino
	// síncrono de /refresh, así que su cadencia es una decisión operativa
	// (cuánto puede demorar en salir un evento), no de latencia.
	defaultOutboxWorkerInterval  = 2 * time.Second
	defaultOutboxWorkerBatchSize = 20
	defaultEventsExchange        = "vvi.topic.exchange"
	defaultEventsProducer        = "vinculo-vial-identity"
	defaultEventsPublishTimeut   = 1500 * time.Millisecond
	defaultEventsDialTimeout     = 10 * time.Second
	defaultEventsHeartbeat       = 10 * time.Second
	// defaultConsumerPrefetch y defaultConsumerMaxRetries son los valores del
	// contrato de US-08. maxConsumerPrefetch es el techo del protocolo AMQP: el
	// prefetch de basic.qos es un entero de 16 bits sin signo.
	defaultConsumerPrefetch   = 10
	defaultConsumerMaxRetries = 5
	maxConsumerPrefetch       = 65535
	// defaultAlertRejectedQueue y defaultFraudPenalty son los valores del
	// contrato de US-08. El nombre de la cola es parte de la topología que
	// declara vinculo-vial-core: ver la tabla de eventos del contrato.
	defaultAlertRejectedQueue = "identity.alert-rejected.q"
	defaultFraudPenalty       = 10
	defaultAlertReportedQueue = "identity.alert-reported.q"
	defaultReviewThreshold    = 1
	// defaultAccessTokenTTLMinutes y defaultRefreshTokenTTLDays son los valores
	// que fija el contrato compartido de US-02, no una elección local: Gateway
	// asume estos mismos TTL del lado de la verificación.
	defaultAccessTokenTTLMinutes = 15
	defaultRefreshTokenTTLDays   = 30
	// defaultSessionMaxDays es la vida máxima de la sesión que fija el
	// contrato de US-12.
	defaultSessionMaxDays = 90
	// defaultJWTIssuer es el nombre de este servicio en el claim `iss`, el que
	// Kong espera cuando no se sobrescribe con JWT_ISSUER.
	defaultJWTIssuer = "vinculo-vial-identity"
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

		Internal: InternalConfig{
			Port:         r.integer("HTTP_INTERNAL_PORT", defaultInternalPort),
			ServiceToken: Secret(r.required("INTERNAL_SERVICE_TOKEN")),
		},

		Postgres: PostgresConfig{
			Host:             r.str("POSTGRES_HOST", "localhost"),
			Port:             r.integer("POSTGRES_PORT", 5432),
			User:             r.required("POSTGRES_USER"),
			Password:         Secret(r.required("POSTGRES_PASSWORD")),
			Database:         r.required("POSTGRES_DB"),
			SSLMode:          r.str("POSTGRES_SSLMODE", "disable"),
			MaxOpenConns:     r.integer("POSTGRES_MAX_OPEN_CONNS", defaultMaxOpenConns),
			MaxIdleConns:     r.integer("POSTGRES_MAX_IDLE_CONNS", defaultMaxIdleConns),
			ConnMaxLifetime:  r.duration("POSTGRES_CONN_MAX_LIFETIME", defaultConnMaxLifetime),
			ConnMaxIdleTime:  r.duration("POSTGRES_CONN_MAX_IDLE_TIME", defaultConnMaxIdleTime),
			LogSQL:           r.boolean("POSTGRES_LOG_SQL", false),
			EphemeralDB:      r.boolean("EPHEMERAL_DB", false),
			StatementTimeout: r.duration("POSTGRES_STATEMENT_TIMEOUT", defaultStatementTimeout),
		},

		Crypto: CryptoConfig{
			HPKEPrivateKey:    Secret(r.required("IDENTITY_HPKE_PRIVATE_KEY")),
			HPKEInfo:          r.str("IDENTITY_HPKE_INFO", defaultHPKEInfo),
			AESKey:            Secret(r.required("AES_KEY")),
			HMACSecret:        Secret(r.required("HMAC_SECRET")),
			JWTPrivateKey:     Secret(unescapeNewlines(r.required("JWT_PRIVATE_KEY"))),
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
			DialTimeout:    r.duration("RABBITMQ_DIAL_TIMEOUT", defaultEventsDialTimeout),
			Heartbeat:      r.duration("RABBITMQ_HEARTBEAT", defaultEventsHeartbeat),
		},

		Consumer: ConsumerConfig{
			Prefetch:           r.integer("RABBITMQ_PREFETCH", defaultConsumerPrefetch),
			MaxRetries:         r.integer("MAX_RETRIES", defaultConsumerMaxRetries),
			AlertRejectedQueue: r.str("ALERT_REJECTED_QUEUE", defaultAlertRejectedQueue),
			AlertReportedQueue: r.str("ALERT_REPORTED_QUEUE", defaultAlertReportedQueue),
		},

		Reputation: ReputationConfig{
			FraudPenalty:    r.integer("FRAUD_PENALTY", defaultFraudPenalty),
			ReviewThreshold: r.integer("REPORT_REVIEW_THRESHOLD", defaultReviewThreshold),
		},

		Audit: AuditConfig{
			PublicKey: r.required("AUDIT_PUBLIC_KEY"),
			KeyID:     r.required("AUDIT_KEY_ID"),
		},

		Sanction: SanctionConfig{
			CarryoverDays:  r.integer("SANCTION_CARRYOVER_DAYS", defaultSanctionCarryoverDays),
			SweepInterval:  r.duration("SANCTION_CARRYOVER_SWEEP_INTERVAL", defaultSanctionSweepInterval),
			SweepBatchSize: r.integer("SANCTION_CARRYOVER_SWEEP_BATCH_SIZE", defaultSanctionSweepBatchSize),
		},

		Token: TokenConfig{
			AccessTokenTTL:     time.Duration(r.integer("ACCESS_TOKEN_TTL_MINUTES", defaultAccessTokenTTLMinutes)) * time.Minute,
			RefreshTokenTTL:    time.Duration(r.integer("REFRESH_TOKEN_TTL_DAYS", defaultRefreshTokenTTLDays)) * 24 * time.Hour,
			SessionMaxLifetime: time.Duration(r.integer("SESSION_MAX_DAYS", defaultSessionMaxDays)) * 24 * time.Hour,
			Issuer:             r.str("JWT_ISSUER", defaultJWTIssuer),
		},

		Renaper: RenaperConfig{
			Timeout:                 r.duration("RENAPER_TIMEOUT", defaultRenaperTimeout),
			BreakerFailureThreshold: r.integer("RENAPER_BREAKER_FAILURE_THRESHOLD", defaultRenaperBreakerFailureThreshold),
			BreakerWindow:           r.duration("RENAPER_BREAKER_WINDOW", defaultRenaperBreakerWindow),
			BreakerOpenDuration:     r.duration("RENAPER_BREAKER_OPEN_DURATION", defaultRenaperBreakerOpenDuration),
		},

		Outbox: OutboxConfig{
			WorkerInterval:  r.duration("OUTBOX_WORKER_INTERVAL", defaultOutboxWorkerInterval),
			WorkerBatchSize: r.integer("OUTBOX_WORKER_BATCH_SIZE", defaultOutboxWorkerBatchSize),
		},

		Email: EmailConfig{
			CodeHMACKey:                 Secret(r.required("EMAIL_CODE_HMAC_KEY")),
			CodeTTL:                     time.Duration(r.integer("EMAIL_CODE_TTL_MINUTES", defaultEmailCodeTTLMinutes)) * time.Minute,
			CodeMaxAttempts:             r.integer("EMAIL_CODE_MAX_ATTEMPTS", defaultEmailCodeMaxAttempts),
			CodeResendInterval:          time.Duration(r.integer("EMAIL_CODE_RESEND_SECONDS", defaultEmailCodeResendSeconds)) * time.Second,
			CodeMaxSendsPerDay:          r.integer("EMAIL_CODE_MAX_SENDS_PER_DAY", defaultEmailCodeMaxSendsPerDay),
			VerificationGrantTTL:        time.Duration(r.integer("EMAIL_VERIFICATION_GRANT_TTL_MINUTES", defaultEmailVerificationGrantMinutes)) * time.Minute,
			ResetGrantTTL:               time.Duration(r.integer("PASSWORD_RESET_GRANT_TTL_MINUTES", defaultPasswordResetGrantMinutes)) * time.Minute,
			ResetMaxIdentityAttempts:    r.integer("PASSWORD_RESET_MAX_IDENTITY_ATTEMPTS", defaultPasswordResetMaxIdentityRetries),
			RequireVerificationOnSignup: r.boolean("SIGNUP_REQUIRE_EMAIL_VERIFICATION", true),
			SweepInterval:               r.duration("EMAIL_CHALLENGE_SWEEP_INTERVAL", defaultEmailChallengeSweepInterval),
			SweepBatchSize:              r.integer("EMAIL_CHALLENGE_SWEEP_BATCH_SIZE", defaultEmailChallengeSweepBatchSize),
		},

		Terms: TermsConfig{
			CurrentVersion:  r.str("TERMS_CURRENT_VERSION", defaultTermsCurrentVersion),
			RequireOnSignup: r.boolean("SIGNUP_REQUIRE_TERMS", true),
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
	if c.Internal.Port < 1 || c.Internal.Port > 65535 {
		r.fail("config: HTTP_INTERNAL_PORT fuera de rango: %d", c.Internal.Port)
	}
	if c.HTTP.Port == c.Internal.Port {
		// No es solo una advertencia: dos *http.Server no pueden escuchar el
		// mismo puerto, y si pudieran, dejaría de existir el aislamiento que
		// esta variable existe para garantizar.
		r.fail("config: HTTP_INTERNAL_PORT no puede coincidir con HTTP_PORT (%d): el router interno perdería su puerto propio", c.HTTP.Port)
	}
	if len(c.Internal.ServiceToken.Reveal()) < minServiceTokenLength {
		r.fail("config: INTERNAL_SERVICE_TOKEN debe tener al menos %d caracteres", minServiceTokenLength)
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
	if c.Postgres.StatementTimeout <= 0 {
		r.fail("config: POSTGRES_STATEMENT_TIMEOUT debe ser positivo")
	}

	// sslmode=disable manda el tráfico en claro. Vale en el compose local, donde
	// la base vive en la misma red de Docker, pero nunca fuera de ahí.
	if c.IsProduction() && c.Postgres.SSLMode == "disable" {
		r.fail("config: POSTGRES_SSLMODE=disable no es admisible con APP_ENV=production")
	}
	if c.IsProduction() && c.Postgres.LogSQL {
		r.fail("config: POSTGRES_LOG_SQL registraría el DNI cifrado y el hash de contraseña; no es admisible en producción")
	}
	if c.IsProduction() && c.Postgres.EphemeralDB {
		// No es un descuido a documentar: EPHEMERAL_DB borra el esquema entero
		// en cada arranque. Pensado para levantar despliegues efímeros de
		// pruebas E2E con una base siempre limpia, jamás para un entorno con
		// datos reales.
		r.fail("config: EPHEMERAL_DB=true borraría el esquema completo en cada arranque; no es admisible con APP_ENV=production")
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

	if c.Token.AccessTokenTTL <= 0 {
		r.fail("config: ACCESS_TOKEN_TTL_MINUTES debe ser positivo")
	}
	if c.Token.RefreshTokenTTL <= 0 {
		r.fail("config: REFRESH_TOKEN_TTL_DAYS debe ser positivo")
	}
	if c.Token.SessionMaxLifetime <= 0 {
		r.fail("config: SESSION_MAX_DAYS debe ser positivo")
	}

	if c.Renaper.Timeout <= 0 {
		r.fail("config: RENAPER_TIMEOUT debe ser positivo")
	}
	if c.Renaper.BreakerFailureThreshold <= 0 {
		r.fail("config: RENAPER_BREAKER_FAILURE_THRESHOLD debe ser al menos 1")
	}
	if c.Renaper.BreakerWindow <= 0 {
		r.fail("config: RENAPER_BREAKER_WINDOW debe ser positivo")
	}
	if c.Renaper.BreakerOpenDuration <= 0 {
		r.fail("config: RENAPER_BREAKER_OPEN_DURATION debe ser positivo")
	}

	if c.Outbox.WorkerInterval <= 0 {
		r.fail("config: OUTBOX_WORKER_INTERVAL debe ser positivo")
	}
	if c.Outbox.WorkerBatchSize < 1 {
		r.fail("config: OUTBOX_WORKER_BATCH_SIZE debe ser al menos 1")
	}

	c.validateEmail(r)
	c.validateTerms(r)

	if c.Consumer.Prefetch < 1 || c.Consumer.Prefetch > maxConsumerPrefetch {
		r.fail("config: RABBITMQ_PREFETCH debe estar entre 1 y %d, se recibió %d", maxConsumerPrefetch, c.Consumer.Prefetch)
	}
	if c.Consumer.MaxRetries < 0 {
		r.fail("config: MAX_RETRIES no puede ser negativo, se recibió %d", c.Consumer.MaxRetries)
	}

	if c.Reputation.FraudPenalty < 0 {
		r.fail("config: FRAUD_PENALTY no puede ser negativa, se recibió %d", c.Reputation.FraudPenalty)
	}

	if c.Reputation.ReviewThreshold < 1 {
		r.fail("config: REPORT_REVIEW_THRESHOLD debe ser al menos 1, se recibió %d", c.Reputation.ReviewThreshold)
	}

	if c.Sanction.CarryoverDays < 1 {
		r.fail("config: SANCTION_CARRYOVER_DAYS debe ser al menos 1, se recibió %d", c.Sanction.CarryoverDays)
	}
	if c.Sanction.SweepInterval <= 0 {
		r.fail("config: SANCTION_CARRYOVER_SWEEP_INTERVAL debe ser positivo")
	}
	if c.Sanction.SweepBatchSize < 1 {
		r.fail("config: SANCTION_CARRYOVER_SWEEP_BATCH_SIZE debe ser al menos 1, se recibió %d", c.Sanction.SweepBatchSize)
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

// validateEmail valida los parámetros de US-13. La clave de los desafíos es la
// única que tiene una regla de independencia: una clave por mecanismo, nunca
// reutilizada, así que no puede ser igual a AES_KEY ni a HMAC_SECRET.
func (c *Config) validateEmail(r *reader) {
	e := c.Email

	key := e.CodeHMACKey.Reveal()
	if raw, err := base64.StdEncoding.DecodeString(key); err != nil {
		if key != "" { // vacía ya la informó r.required.
			r.fail("config: EMAIL_CODE_HMAC_KEY no es base64 estándar válido")
		}
	} else {
		if len(raw) < minEmailCodeHMACKeyLength {
			r.fail("config: EMAIL_CODE_HMAC_KEY mide %d bytes, se requieren al menos %d", len(raw), minEmailCodeHMACKeyLength)
		}
		clear(raw)
		if key == c.Crypto.AESKey.Reveal() || key == c.Crypto.HMACSecret.Reveal() {
			r.fail("config: EMAIL_CODE_HMAC_KEY no puede reutilizar AES_KEY ni HMAC_SECRET: una clave por mecanismo")
		}
	}

	if e.CodeTTL <= 0 {
		r.fail("config: EMAIL_CODE_TTL_MINUTES debe ser positivo")
	}
	if e.CodeMaxAttempts < 1 {
		r.fail("config: EMAIL_CODE_MAX_ATTEMPTS debe ser al menos 1, se recibió %d", e.CodeMaxAttempts)
	}
	if e.CodeResendInterval <= 0 {
		r.fail("config: EMAIL_CODE_RESEND_SECONDS debe ser positivo")
	}
	if e.CodeMaxSendsPerDay < 1 {
		r.fail("config: EMAIL_CODE_MAX_SENDS_PER_DAY debe ser al menos 1, se recibió %d", e.CodeMaxSendsPerDay)
	}
	if e.VerificationGrantTTL <= 0 {
		r.fail("config: EMAIL_VERIFICATION_GRANT_TTL_MINUTES debe ser positivo")
	}
	if e.ResetGrantTTL <= 0 {
		r.fail("config: PASSWORD_RESET_GRANT_TTL_MINUTES debe ser positivo")
	}
	if e.ResetMaxIdentityAttempts < 1 {
		r.fail("config: PASSWORD_RESET_MAX_IDENTITY_ATTEMPTS debe ser al menos 1, se recibió %d", e.ResetMaxIdentityAttempts)
	}
	if e.SweepInterval <= 0 {
		r.fail("config: EMAIL_CHALLENGE_SWEEP_INTERVAL debe ser positivo")
	}
	if e.SweepBatchSize < 1 {
		r.fail("config: EMAIL_CHALLENGE_SWEEP_BATCH_SIZE debe ser al menos 1, se recibió %d", e.SweepBatchSize)
	}

	if c.IsProduction() && !e.RequireVerificationOnSignup {
		// Sin el token, cualquiera da de alta una cuenta con un email ajeno y esa
		// cuenta no podría recuperarse nunca. Existe solo para desarrollo.
		r.fail("config: SIGNUP_REQUIRE_EMAIL_VERIFICATION=false no es admisible con APP_ENV=production")
	}
}

// validateTerms valida los parámetros de US-19.
func (c *Config) validateTerms(r *reader) {
	t := c.Terms

	// Una variable vacía o en blanco no llega acá vacía: el lector la reemplaza por
	// el default.
	if len(t.CurrentVersion) > maxTermsVersionLength {
		r.fail("config: TERMS_CURRENT_VERSION mide %d caracteres, el máximo es %d (largo de users.terms_version)",
			len(t.CurrentVersion), maxTermsVersionLength)
	}

	if c.IsProduction() && !t.RequireOnSignup {
		// Sin el campo, el alta no deja consentimiento registrado (art. 5 de la Ley
		// 25.326). Existe solo para la transición entre los merges de Identity y del
		// Frontend.
		r.fail("config: SIGNUP_REQUIRE_TERMS=false no es admisible con APP_ENV=production")
	}
}

// unescapeNewlines revierte el escapado de saltos de línea de un PEM
// almacenado en una sola línea de .env: "\n" literal (barra invertida + ene)
// vuelve a ser un salto de línea real. El parser de .env de este servicio no
// soporta valores multilínea, así que el material PEM viaja escapado —el
// mismo truco que usan las variables de entorno de servicio de GCP/Firebase
// para lo mismo— y cmd/genkeys ya lo imprime en este formato.
func unescapeNewlines(raw string) string {
	return strings.ReplaceAll(raw, `\n`, "\n")
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
		slog.Int("internal_port", c.Internal.Port),
		slog.String("postgres_host", c.Postgres.Host),
		slog.Int("postgres_port", c.Postgres.Port),
		slog.String("postgres_db", c.Postgres.Database),
		slog.String("postgres_sslmode", c.Postgres.SSLMode),
		slog.Bool("postgres_ephemeral_db", c.Postgres.EphemeralDB),
		slog.Duration("postgres_statement_timeout", c.Postgres.StatementTimeout),
		slog.Bool("events_enabled", c.Events.Enabled),
		slog.String("events_exchange", c.Events.Exchange),
		slog.Int("rabbitmq_prefetch", c.Consumer.Prefetch),
		slog.Int("max_retries", c.Consumer.MaxRetries),
		slog.String("alert_rejected_queue", c.Consumer.AlertRejectedQueue),
		slog.String("alert_reported_queue", c.Consumer.AlertReportedQueue),
		slog.Int("fraud_penalty", c.Reputation.FraudPenalty),
		slog.Int("report_review_threshold", c.Reputation.ReviewThreshold),
		slog.String("audit_key_id", c.Audit.KeyID),
		slog.Int("sanction_carryover_days", c.Sanction.CarryoverDays),
		slog.Duration("sanction_carryover_sweep_interval", c.Sanction.SweepInterval),
		slog.Int("sanction_carryover_sweep_batch_size", c.Sanction.SweepBatchSize),
		slog.Duration("renaper_timeout", c.Renaper.Timeout),
		slog.Int("renaper_breaker_failure_threshold", c.Renaper.BreakerFailureThreshold),
		slog.Duration("renaper_breaker_window", c.Renaper.BreakerWindow),
		slog.Duration("renaper_breaker_open_duration", c.Renaper.BreakerOpenDuration),
		slog.Duration("outbox_worker_interval", c.Outbox.WorkerInterval),
		slog.Int("outbox_worker_batch_size", c.Outbox.WorkerBatchSize),
		slog.Int("argon2_memory_kib", c.Crypto.Argon2MemoryKiB),
		slog.Duration("access_token_ttl", c.Token.AccessTokenTTL),
		slog.Duration("refresh_token_ttl", c.Token.RefreshTokenTTL),
		slog.Duration("session_max_lifetime", c.Token.SessionMaxLifetime),
		slog.String("jwt_issuer", c.Token.Issuer),
		slog.Duration("email_code_ttl", c.Email.CodeTTL),
		slog.Int("email_code_max_attempts", c.Email.CodeMaxAttempts),
		slog.Duration("email_code_resend_interval", c.Email.CodeResendInterval),
		slog.Int("email_code_max_sends_per_day", c.Email.CodeMaxSendsPerDay),
		slog.Duration("email_verification_grant_ttl", c.Email.VerificationGrantTTL),
		slog.Duration("password_reset_grant_ttl", c.Email.ResetGrantTTL),
		slog.Int("password_reset_max_identity_attempts", c.Email.ResetMaxIdentityAttempts),
		slog.Bool("signup_require_email_verification", c.Email.RequireVerificationOnSignup),
		slog.String("terms_current_version", c.Terms.CurrentVersion),
		slog.Bool("signup_require_terms", c.Terms.RequireOnSignup),
		slog.Duration("email_challenge_sweep_interval", c.Email.SweepInterval),
		slog.Int("email_challenge_sweep_batch_size", c.Email.SweepBatchSize),
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
