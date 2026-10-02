// Command api levanta el microservicio de identidad.
//
// Es el único lugar del proyecto donde se conocen todas las implementaciones
// concretas: acá se resuelven las dependencias de los puertos de domain y se
// arma el servidor. Todo lo demás depende de interfaces.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/blindindex"
	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/hpke"
	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/password"
	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/symmetric"
	"github.com/matiasfelau/vinculo-vial-identity/internal/delivery/events"
	delivery "github.com/matiasfelau/vinculo-vial-identity/internal/delivery/http"
	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/renaper"
	"github.com/matiasfelau/vinculo-vial-identity/internal/repository/postgres"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/outbox"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/ownership"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/session"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/signin"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/signup"
	"github.com/matiasfelau/vinculo-vial-identity/internal/token"
	"github.com/matiasfelau/vinculo-vial-identity/pkg/config"
)

func main() {
	if err := run(); err != nil {
		// El logger estructurado puede no existir todavía si el fallo fue al
		// cargar la configuración, así que el último recurso es stderr.
		slog.Error("el servicio no pudo continuar", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func run() error {
	// El .env es una comodidad de desarrollo; en contenedor las variables las
	// inyecta el orquestador y este archivo no existe.
	if err := config.LoadDotEnv(".env"); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	logger := newLogger(cfg)
	slog.SetDefault(logger)

	// El contexto se cancela con SIGINT o SIGTERM, que es como Kubernetes y
	// Docker piden el apagado.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("iniciando vinculo-vial-identity", slog.Any("config", cfg))

	decryptor, indexer, cipher, hasher, err := buildCrypto(cfg)
	if err != nil {
		return err
	}

	db, err := postgres.Open(ctx, postgres.Config{
		DSN:             cfg.Postgres.DSN(),
		MaxOpenConns:    cfg.Postgres.MaxOpenConns,
		MaxIdleConns:    cfg.Postgres.MaxIdleConns,
		ConnMaxLifetime: cfg.Postgres.ConnMaxLifetime,
		ConnMaxIdleTime: cfg.Postgres.ConnMaxIdleTime,
		LogSQL:          cfg.Postgres.LogSQL,
		EphemeralDB:     cfg.Postgres.EphemeralDB,
	})
	if err != nil {
		return err
	}
	defer func() {
		if err := postgres.Close(db); err != nil {
			logger.Error("no se pudo cerrar la conexión con la base", slog.String("error", err.Error()))
		}
	}()

	users, err := postgres.NewUserRepository(ctx, db)
	if err != nil {
		return err
	}

	// Requiere que la tabla users ya exista: sessions declara la clave foránea
	// hacia ella.
	sessions, err := postgres.NewSessionRepository(ctx, db)
	if err != nil {
		return err
	}

	// outbox_events no depende de users ni de sessions: es la tabla del
	// patrón Transactional Outbox de la Defensa Activa (US-06), ver
	// domain.OutboxEvent.
	outboxRepo, err := postgres.NewOutboxRepository(ctx, db)
	if err != nil {
		return err
	}

	tokens, err := buildTokenGenerator(cfg)
	if err != nil {
		return err
	}

	publisher, closePublisher, err := buildPublisher(cfg, logger)
	if err != nil {
		return err
	}
	defer func() {
		if err := closePublisher(); err != nil {
			logger.Error("no se pudo cerrar el publisher", slog.String("error", err.Error()))
		}
	}()

	// El worker de outbox publica en background: RefreshService ya no
	// depende de domain.EventPublisher en absoluto, así que /refresh no se
	// ve afectado por la disponibilidad del broker al ejecutar la Defensa
	// Activa (más allá de que el evento tarde en salir mientras el worker
	// reintenta). Comparte el ctx cancelable por SIGTERM de run(): al apagar
	// el servicio dejan de programarse nuevos ciclos, en vez de que el
	// worker sobreviva al resto del proceso.
	outboxWorker := outbox.NewWorker(outboxRepo, publisher, cfg.Outbox.WorkerBatchSize, logger)
	go outboxWorker.Run(ctx, cfg.Outbox.WorkerInterval)

	renaperSvc := buildRenaper(cfg, logger)

	signUpService, err := signup.New(signup.Deps{
		Decryptor: decryptor,
		Indexer:   indexer,
		Cipher:    cipher,
		Hasher:    hasher,
		Renaper:   renaperSvc,
		Users:     users,
		Logger:    logger,
	})
	if err != nil {
		return err
	}

	signInService, err := signin.New(signin.Deps{
		Decryptor: decryptor,
		Indexer:   indexer,
		Hasher:    hasher,
		Users:     users,
		Sessions:  sessions,
		Tokens:    tokens,
		Logger:    logger,
	})
	if err != nil {
		return err
	}

	refreshService, err := session.NewRefreshService(session.RefreshDeps{
		Sessions: sessions,
		Tokens:   tokens,
		Logger:   logger,
	})
	if err != nil {
		return err
	}

	logoutService, err := session.NewLogoutService(session.LogoutDeps{
		Sessions: sessions,
		Tokens:   tokens,
		Logger:   logger,
	})
	if err != nil {
		return err
	}

	verifyOwnershipService, err := ownership.New(ownership.Deps{
		Decryptor: decryptor,
		Indexer:   indexer,
		Users:     users,
		Logger:    logger,
	})
	if err != nil {
		return err
	}

	router, err := delivery.NewRouter(delivery.RouterConfig{
		SignUp:       signUpService,
		SignIn:       signInService,
		Refresh:      refreshService,
		Logout:       logoutService,
		Logger:       logger,
		MaxBodyBytes: cfg.HTTP.MaxBodyBytes,
		Debug:        cfg.HTTP.Debug,
		// Readiness apoyada en la base: si no responde, ni un alta ni un login
		// podrían persistirse y el orquestador no debería mandar tráfico acá.
		ReadinessCheck: func(ctx context.Context) error { return postgres.Ping(ctx, db) },
	})
	if err != nil {
		return err
	}

	internalRouter, err := delivery.NewInternalRouter(delivery.InternalRouterConfig{
		VerifyOwnership: verifyOwnershipService,
		Logger:          logger,
		ServiceToken:    cfg.Internal.ServiceToken.Reveal(),
		MaxBodyBytes:    cfg.HTTP.MaxBodyBytes,
		Debug:           cfg.HTTP.Debug,
	})
	if err != nil {
		return err
	}

	return serve(ctx, cfg, router, internalRouter, logger)
}

func newLogger(cfg *config.Config) *slog.Logger {
	// JSON siempre, también en desarrollo: que el formato del log sea el mismo
	// en todos los entornos evita descubrir en producción que un campo no se
	// serializaba como se esperaba.
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
}

// buildCrypto construye los cuatro primitivos. Cada clave se valida acá —largo,
// codificación, política— y no en la primera petición.
func buildCrypto(cfg *config.Config) (domain.HPKEDecryptor, domain.BlindIndexer, domain.SymmetricCipher, domain.PasswordHasher, error) {
	decryptor, err := hpke.NewDecryptorFromBase64(cfg.Crypto.HPKEPrivateKey.Reveal(), []byte(cfg.Crypto.HPKEInfo))
	if err != nil {
		return nil, nil, nil, nil, err
	}

	indexer, err := blindindex.NewFromBase64(cfg.Crypto.HMACSecret.Reveal())
	if err != nil {
		return nil, nil, nil, nil, err
	}

	cipher, err := symmetric.NewFromBase64(cfg.Crypto.AESKey.Reveal())
	if err != nil {
		return nil, nil, nil, nil, err
	}

	params := password.DefaultParams()
	params.MemoryKiB = uint32(cfg.Crypto.Argon2MemoryKiB)
	params.Iterations = uint32(cfg.Crypto.Argon2Iterations)
	params.Parallelism = uint8(cfg.Crypto.Argon2Parallelism)

	hasher, err := password.New(params)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return decryptor, indexer, cipher, hasher, nil
}

// buildTokenGenerator construye el emisor de tokens de sesión (US-02). La
// clave se valida acá —formato PEM, algoritmo, largo mínimo— y no en el primer
// login.
func buildTokenGenerator(cfg *config.Config) (domain.TokenGenerator, error) {
	return token.New(cfg.Crypto.JWTPrivateKey.Reveal(), cfg.Token.AccessTokenTTL, cfg.Token.RefreshTokenTTL, cfg.Token.Issuer)
}

// buildPublisher elige entre el publisher real y el inerte.
//
// El broker es un recurso global de la plataforma y no está en el compose de
// este servicio; la configuración ya impide que el modo inerte llegue a
// producción.
func buildPublisher(cfg *config.Config, logger *slog.Logger) (domain.EventPublisher, func() error, error) {
	if !cfg.Events.Enabled {
		p := events.NewNoopPublisher(logger)
		logger.Warn("publisher de eventos deshabilitado: las altas no se publicarán")
		return p, p.Close, nil
	}

	p, err := events.NewPublisher(events.Config{
		URL:            cfg.Events.URL.Reveal(),
		Exchange:       cfg.Events.Exchange,
		Producer:       cfg.Events.Producer,
		PublishTimeout: cfg.Events.PublishTimeout,
		DialTimeout:    cfg.Events.DialTimeout,
		Heartbeat:      cfg.Events.Heartbeat,
	}, logger)
	if err != nil {
		return nil, nil, err
	}

	return p, p.Close, nil
}

// buildRenaper construye el verificador de identidad.
//
// Hoy solo existe el Mock: no hay credenciales ni contrato acordado con la API
// real de RENAPER. A diferencia de buildPublisher, esto no es una decisión de
// configuración —no hay un RENAPER_ENABLED que alternar— porque no hay todavía
// una alternativa real que cablear. El WARN en cada arranque es la única
// salvaguarda: que quede imposible de ignorar que ninguna identidad se está
// verificando de verdad.
//
// Se envuelve con renaper.WithTimeout y renaper.WithCircuitBreaker incluso
// sobre el Mock: así ambos mecanismos quedan probados de punta a punta antes
// de que exista un cliente real que los necesite de verdad. El breaker es la
// capa más externa: con el circuito abierto, ValidateIdentity no debe
// intentar nada, ni siquiera esperar el timeout.
func buildRenaper(cfg *config.Config, logger *slog.Logger) domain.RenaperService {
	logger.Warn("RenaperService en modo mock: ninguna identidad se verifica realmente; no usar en producción")

	svc := renaper.WithTimeout(&renaper.Mock{}, cfg.Renaper.Timeout)
	return renaper.WithCircuitBreaker(svc, renaper.BreakerConfig{
		FailureThreshold: cfg.Renaper.BreakerFailureThreshold,
		Window:           cfg.Renaper.BreakerWindow,
		OpenDuration:     cfg.Renaper.BreakerOpenDuration,
	}, logger)
}

// serve levanta el servidor público y el interno (US-04) a la vez, cada uno
// en su propio puerto, y los apaga juntos: son dos superficies del mismo
// proceso y ninguna tiene sentido sin la otra en pie.
func serve(ctx context.Context, cfg *config.Config, publicHandler, internalHandler http.Handler, logger *slog.Logger) error {
	newServer := func(addr string, handler http.Handler) *http.Server {
		return &http.Server{
			Addr:    addr,
			Handler: handler,
			// Sin estos plazos, un cliente lento puede retener una conexión
			// indefinidamente y agotar el servidor con muy poco esfuerzo.
			ReadTimeout:       cfg.HTTP.ReadTimeout,
			ReadHeaderTimeout: cfg.HTTP.ReadTimeout,
			WriteTimeout:      cfg.HTTP.WriteTimeout,
			IdleTimeout:       cfg.HTTP.IdleTimeout,
		}
	}

	servers := map[string]*http.Server{
		"público": newServer(cfg.HTTP.Addr(), publicHandler),
		"interno": newServer(cfg.Internal.Addr(), internalHandler),
	}

	errCh := make(chan error, len(servers))
	for name, srv := range servers {
		name, srv := name, srv
		go func() {
			logger.Info("servidor escuchando", slog.String("servidor", name), slog.String("addr", srv.Addr))
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("el servidor http %s falló: %w", name, err)
				return
			}
			errCh <- nil
		}()
	}

	select {
	case err := <-errCh:
		if err != nil {
			shutdown(servers, cfg.HTTP.ShutdownTimeout, logger)
			return err
		}
	case <-ctx.Done():
		logger.Info("apagado solicitado, drenando peticiones en curso")
	}

	if err := shutdown(servers, cfg.HTTP.ShutdownTimeout, logger); err != nil {
		return err
	}

	logger.Info("servicio detenido")
	return nil
}

// shutdown apaga ordenadamente todos los servidores dados, con un único
// plazo compartido. Apagar el que ya falló es seguro: sin un listener activo,
// Shutdown vuelve de inmediato.
func shutdown(servers map[string]*http.Server, timeout time.Duration, logger *slog.Logger) error {
	// Contexto nuevo: el original ya puede estar cancelado y no serviría para
	// acotar el drenaje.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var errs []error
	for name, srv := range servers {
		if err := srv.Shutdown(shutdownCtx); err != nil {
			errs = append(errs, fmt.Errorf("el apagado del servidor %s no terminó a tiempo: %w", name, err))
		}
	}
	return errors.Join(errs...)
}
