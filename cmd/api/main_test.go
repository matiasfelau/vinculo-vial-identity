package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/renaper"
	"github.com/matiasfelau/vinculo-vial-identity/pkg/config"
)

func loggerDescartado() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// registroDeLog acumula todo lo que se loguea, para afirmar sobre qué se
// dijo y sobre qué no.
type registroDeLog struct{ sb strings.Builder }

func (r *registroDeLog) Write(p []byte) (int, error) { return r.sb.Write(p) }

func loggerConRegistro() (*slog.Logger, *registroDeLog) {
	r := &registroDeLog{}
	return slog.New(slog.NewTextHandler(r, &slog.HandlerOptions{Level: slog.LevelDebug})), r
}

// --- execute ---

func TestExecuteFallaSinConfiguracionYNoArrancaNada(t *testing.T) {
	for _, k := range variablesDelServicio {
		t.Setenv(k, "")
	}

	err := execute()

	if err == nil {
		t.Fatal("sin variables de entorno el servicio no debería arrancar")
	}
}

func TestExecuteRechazaUnDotenvMalFormado(t *testing.T) {
	// El .env se busca en el directorio de trabajo: uno ilegible o mal formado
	// frena el arranque en lugar de seguir con valores a medias.
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(".env", []byte("ESTO NO ES UNA ASIGNACION\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := execute()

	if err == nil {
		t.Fatal("un .env mal formado debería hacer fallar el arranque")
	}
}

// --- run: fallas de configuración que se detectan antes de tocar la base ---

func TestRunRechazaClavesInutilizablesSinTocarLaBase(t *testing.T) {
	casos := []struct {
		nombre   string
		override map[string]string
	}{
		{"HPKE corrupta", map[string]string{"IDENTITY_HPKE_PRIVATE_KEY": "no-es-base64-ni-32-bytes"}},
		{"HMAC corta", map[string]string{"HMAC_SECRET": "AAAA"}},
		{"AES de largo incorrecto", map[string]string{"AES_KEY": "AAAA"}},
	}
	for _, tc := range casos {
		t.Run(tc.nombre, func(t *testing.T) {
			// La base apunta a un puerto cerrado: si run llegara a abrirla, el
			// error sería otro. Falla antes por la clave.
			override := map[string]string{"POSTGRES_PORT": "1"}
			for k, v := range tc.override {
				override[k] = v
			}
			cfg := entornoValido(t, override)

			err := run(context.Background(), cfg)

			if err == nil {
				t.Fatal("run debería fallar con una clave inutilizable")
			}
			if strings.Contains(err.Error(), "no se pudo abrir") || strings.Contains(err.Error(), "no responde") {
				t.Errorf("el error llegó a la base, se esperaba que fallara antes: %v", err)
			}
		})
	}
}

func TestRunFallaSiLaBaseNoResponde(t *testing.T) {
	cfg := entornoValido(t, map[string]string{"POSTGRES_HOST": "127.0.0.1", "POSTGRES_PORT": puertoCerrado(t)})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := run(ctx, cfg)

	if err == nil {
		t.Fatal("run debería fallar si la base no responde")
	}
	if strings.Contains(err.Error(), contrasenaDeLaBaseFalsa) {
		t.Errorf("el error de arranque filtra la contraseña de la base: %v", err)
	}
}

// --- buildCrypto / buildTokenGenerator ---

func TestBuildCryptoConClavesValidasDevuelveLosCuatroPrimitivos(t *testing.T) {
	cfg := entornoValido(t, nil)

	decryptor, indexer, cipher, hasher, err := buildCrypto(cfg)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if decryptor == nil || indexer == nil || cipher == nil || hasher == nil {
		t.Fatal("buildCrypto devolvió un primitivo nulo")
	}

	// El cifrador y el hasher se ejercitan de verdad: que estén construidos no
	// prueba que usen los parámetros de la configuración.
	cifrado, err := cipher.Encrypt([]byte("dato"))
	if err != nil {
		t.Fatalf("el cifrador no cifra: %v", err)
	}
	claro, err := cipher.Decrypt(cifrado)
	if err != nil || string(claro) != "dato" {
		t.Errorf("ida y vuelta del cifrador = %q, %v; se esperaba \"dato\"", claro, err)
	}
}

func TestBuildCryptoRechazaCadaClaveInvalida(t *testing.T) {
	casos := []struct {
		nombre   string
		override map[string]string
	}{
		{"HPKE", map[string]string{"IDENTITY_HPKE_PRIVATE_KEY": "###"}},
		{"HMAC", map[string]string{"HMAC_SECRET": "AAAA"}},
		{"AES", map[string]string{"AES_KEY": "AAAA"}},
	}
	for _, tc := range casos {
		t.Run(tc.nombre, func(t *testing.T) {
			cfg := entornoValido(t, tc.override)

			if _, _, _, _, err := buildCrypto(cfg); err == nil {
				t.Errorf("buildCrypto aceptó una configuración inválida (%s)", tc.nombre)
			}
		})
	}
}

// La configuración ya impone un piso a los parámetros de Argon2, pero buildCrypto
// no puede asumirlo: si el hasher los rechaza, el arranque tiene que fallar.
func TestBuildCryptoRechazaParametrosDeArgon2QueElHasherNoAcepta(t *testing.T) {
	cfg := entornoValido(t, nil)
	cfg.Crypto.Argon2Iterations = 0

	if _, _, _, _, err := buildCrypto(cfg); err == nil {
		t.Error("buildCrypto aceptó Argon2 con cero iteraciones")
	}
}

func TestBuildTokenGeneratorEmiteConLaClaveConfigurada(t *testing.T) {
	cfg := entornoValido(t, nil)

	gen, err := buildTokenGenerator(cfg)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if gen == nil {
		t.Fatal("el generador es nulo")
	}
}

func TestBuildTokenGeneratorRechazaUnaClaveQueNoEsPEM(t *testing.T) {
	cfg := entornoValido(t, map[string]string{"JWT_PRIVATE_KEY": "esto-no-es-un-pem"})

	if _, err := buildTokenGenerator(cfg); err == nil {
		t.Fatal("se esperaba un error con una clave JWT que no es PEM")
	}
}

// --- buildPublisher ---

func TestBuildPublisherDeshabilitadoDevuelveElInerteYAvisa(t *testing.T) {
	cfg := entornoValido(t, nil) // RABBITMQ_ENABLED=false por defecto
	logger, registro := loggerConRegistro()

	pub, cerrar, err := buildPublisher(cfg, logger)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if _, ok := pub.(interface{ Status() (string, bool) }); !ok {
		t.Error("el publisher no informa su estado para /health/deps")
	}
	if !strings.Contains(registro.sb.String(), "publisher de eventos deshabilitado") {
		t.Errorf("el modo inerte tiene que dejar constancia en el log, se vio: %q", registro.sb.String())
	}
	if err := cerrar(); err != nil {
		t.Errorf("cerrar el publisher inerte falló: %v", err)
	}
}

func TestBuildPublisherHabilitadoFallaRapidoSinBrokerYNoFiltraLaURL(t *testing.T) {
	const secreto = "s3cr3to-del-broker"
	cfg := entornoValido(t, map[string]string{
		"APP_ENV":              "development",
		"RABBITMQ_ENABLED":     "true",
		"RABBITMQ_URL":         "amqp://usuario:" + secreto + "@127.0.0.1:" + puertoCerrado(t) + "/",
		"RABBITMQ_DIAL_TIMEOUT": "1s",
	})

	pub, cerrar, err := buildPublisher(cfg, loggerDescartado())

	if err == nil {
		t.Fatal("con el broker caído el arranque tiene que fallar, no seguir sin publisher")
	}
	if pub != nil || cerrar != nil {
		t.Error("ante el error no debería devolverse un publisher ni un cierre")
	}
	if strings.Contains(err.Error(), secreto) {
		t.Errorf("el error filtra las credenciales del broker: %v", err)
	}
}

// --- startConsumers ---

type repoReputacionVacio struct{ domain.ReputationRepository }

func TestStartConsumersDeshabilitadoNoLanzaNadaYAvisa(t *testing.T) {
	cfg := entornoValido(t, nil)
	logger, registro := loggerConRegistro()

	stop, err := startConsumers(context.Background(), cfg, repoReputacionVacio{}, logger)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	stop() // no debe bloquear ni entrar en pánico

	if !strings.Contains(registro.sb.String(), "consumo de eventos deshabilitado") {
		t.Errorf("tiene que quedar constancia del modo deshabilitado, se vio: %q", registro.sb.String())
	}
}

func TestStartConsumersHabilitadoSeApagaAunConElBrokerCaido(t *testing.T) {
	cfg := entornoValido(t, map[string]string{
		"RABBITMQ_ENABLED":      "true",
		"RABBITMQ_URL":          "amqp://guest:guest@127.0.0.1:" + puertoCerrado(t) + "/",
		"RABBITMQ_DIAL_TIMEOUT": "500ms",
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop, err := startConsumers(ctx, cfg, repoReputacionVacio{}, loggerDescartado())
	if err != nil {
		t.Fatalf("el broker caído no debería impedir el arranque de los consumidores (reintentan solos): %v", err)
	}

	hecho := make(chan struct{})
	go func() { stop(); close(hecho) }()
	select {
	case <-hecho:
	case <-time.After(10 * time.Second):
		t.Fatal("stop no volvió: los consumidores no respetan la cancelación")
	}
}

func TestStartConsumersRechazaUnaConfiguracionInvalidaSinLanzarNada(t *testing.T) {
	cfg := entornoValido(t, map[string]string{
		"RABBITMQ_ENABLED": "true",
		"RABBITMQ_URL":     "amqp://guest:guest@127.0.0.1:5672/",
	})
	cfg.Consumer.AlertRejectedQueue = "" // una cola sin nombre no es consumible

	stop, err := startConsumers(context.Background(), cfg, repoReputacionVacio{}, loggerDescartado())

	if err == nil {
		stop()
		t.Fatal("se esperaba un error con una cola sin nombre")
	}
}

// --- buildRenaper ---

func TestBuildRenaperArrancaConElCircuitoCerradoYAdvierteDelMock(t *testing.T) {
	cfg := entornoValido(t, nil)
	logger, registro := loggerConRegistro()

	svc := buildRenaper(cfg, logger)

	if svc.State() != renaper.BreakerStateClosed {
		t.Errorf("estado inicial = %q, se esperaba cerrado", svc.State())
	}
	if !strings.Contains(registro.sb.String(), "modo mock") {
		t.Errorf("el mock tiene que advertirse en el log, se vio: %q", registro.sb.String())
	}
}

// --- buildAdminRouter ---

type repoRevisionVacio struct{ domain.ReviewRepository }

func TestBuildAdminRouterSinClaveNoLevantaSuperficieDeAdministracion(t *testing.T) {
	cfg := entornoValido(t, map[string]string{"ADMIN_API_KEY": ""})
	logger, registro := loggerConRegistro()

	h, err := buildAdminRouter(cfg, repoRevisionVacio{}, logger)

	if err != nil || h != nil {
		t.Fatalf("sin ADMIN_API_KEY se esperaba (nil, nil), se obtuvo (%v, %v)", h, err)
	}
	if !strings.Contains(registro.sb.String(), "ADMIN_API_KEY vacía") {
		t.Errorf("tiene que quedar constancia en el log, se vio: %q", registro.sb.String())
	}
}

func TestBuildAdminRouterRechazaUnaClaveCorta(t *testing.T) {
	cfg := entornoValido(t, nil)
	cfg.Admin.APIKey = config.Secret("corta")

	h, err := buildAdminRouter(cfg, repoRevisionVacio{}, loggerDescartado())

	if err == nil || h != nil {
		t.Fatalf("una clave de menos de 32 caracteres tiene que rechazarse, se obtuvo (%v, %v)", h, err)
	}
	if strings.Contains(err.Error(), "corta") {
		t.Errorf("el error no debería repetir el valor de la clave: %v", err)
	}
}

func TestBuildAdminRouterConClaveValidaExigeLaCabeceraEnTodaRuta(t *testing.T) {
	cfg := entornoValido(t, nil)

	h, err := buildAdminRouter(cfg, repoRevisionVacio{}, loggerDescartado())
	if err != nil || h == nil {
		t.Fatalf("se esperaba un router, se obtuvo (%v, %v)", h, err)
	}

	for _, ruta := range []string{"/admin/v1/review-cases", "/ruta-que-no-existe"} {
		req := httptest.NewRequest(http.MethodGet, ruta, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s sin clave respondió %d, se esperaba 401", ruta, rec.Code)
		}
	}
}

// --- newLogger ---

func TestNewLoggerRespetaElNivelConfigurado(t *testing.T) {
	cfg := entornoValido(t, map[string]string{"LOG_LEVEL": "error"})

	l := newLogger(cfg)

	if l.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("con LOG_LEVEL=error no debería emitirse info")
	}
	if !l.Enabled(context.Background(), slog.LevelError) {
		t.Error("con LOG_LEVEL=error sí debería emitirse error")
	}
}

// --- serve y shutdown ---

func esperarRespuesta(t *testing.T, url string) *http.Response {
	t.Helper()
	limite := time.Now().Add(5 * time.Second)
	for {
		resp, err := http.Get(url)
		if err == nil {
			return resp
		}
		if time.Now().After(limite) {
			t.Fatalf("el servidor no respondió en %s: %v", url, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func manejadorQueResponde(codigo int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(codigo) })
}

func TestServeLevantaLosTresServidoresYSeApagaAlCancelarElContexto(t *testing.T) {
	cfg := entornoValido(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	terminado := make(chan error, 1)
	go func() {
		terminado <- serve(ctx, cfg, manejadorQueResponde(http.StatusOK), manejadorQueResponde(http.StatusAccepted), manejadorQueResponde(http.StatusTeapot), loggerDescartado())
	}()

	casos := map[string]int{
		"http://127.0.0.1" + cfg.HTTP.Addr():     http.StatusOK,
		"http://127.0.0.1" + cfg.Internal.Addr(): http.StatusAccepted,
		"http://127.0.0.1" + cfg.Admin.Addr():    http.StatusTeapot,
	}
	for url, esperado := range casos {
		resp := esperarRespuesta(t, url)
		resp.Body.Close()
		if resp.StatusCode != esperado {
			t.Errorf("%s respondió %d, se esperaba %d: cada puerto tiene que servir su propio router", url, resp.StatusCode, esperado)
		}
	}

	cancel()
	select {
	case err := <-terminado:
		if err != nil {
			t.Errorf("un apagado ordenado no debería devolver error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve no volvió tras cancelar el contexto")
	}
}

func TestServeSinRouterDeAdministracionNoAbreSuPuerto(t *testing.T) {
	cfg := entornoValido(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	terminado := make(chan error, 1)
	go func() {
		terminado <- serve(ctx, cfg, manejadorQueResponde(http.StatusOK), manejadorQueResponde(http.StatusOK), nil, loggerDescartado())
	}()
	esperarRespuesta(t, "http://127.0.0.1"+cfg.HTTP.Addr()).Body.Close()

	conn, err := net.DialTimeout("tcp", "127.0.0.1"+cfg.Admin.Addr(), 300*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Error("el puerto de administración está abierto aunque no hay router de administración")
	}

	cancel()
	if err := <-terminado; err != nil {
		t.Errorf("error inesperado al apagar: %v", err)
	}
}

func TestServeDevuelveElErrorSiUnPuertoEstaOcupadoYApagaLosDemas(t *testing.T) {
	cfg := entornoValido(t, nil)
	ocupado, err := net.Listen("tcp", cfg.Internal.Addr())
	if err != nil {
		t.Skipf("no se pudo ocupar el puerto de prueba: %v", err)
	}
	defer ocupado.Close()
	// Mismo bind que usa serve (todas las interfaces): ocupar solo loopback no
	// alcanza para que falle en todos los sistemas.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = serve(ctx, cfg, manejadorQueResponde(http.StatusOK), manejadorQueResponde(http.StatusOK), nil, loggerDescartado())

	if ctx.Err() != nil {
		t.Fatal("serve no reaccionó al puerto ocupado: solo volvió al vencer el contexto")
	}
	if err == nil {
		t.Fatal("con un puerto ocupado serve tiene que devolver error")
	}
	if !strings.Contains(err.Error(), "interno") {
		t.Errorf("el error debería nombrar el servidor que falló: %v", err)
	}
	// Los demás servidores quedaron apagados: su puerto vuelve a estar libre. El
	// listener se cierra desde la goroutine del servidor, así que puede tardar un
	// instante después de que serve volvió.
	limite := time.Now().Add(3 * time.Second)
	for {
		l, lerr := net.Listen("tcp", cfg.HTTP.Addr())
		if lerr == nil {
			l.Close()
			break
		}
		if time.Now().After(limite) {
			t.Fatalf("el servidor público quedó en pie tras la falla: %v", lerr)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestShutdownReportaElServidorQueNoTerminoADiempo(t *testing.T) {
	liberar := make(chan struct{})
	var entro atomic.Bool
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entro.Store(true)
		<-liberar
	})}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	defer close(liberar)

	go http.Get("http://" + l.Addr().String())
	for !entro.Load() {
		time.Sleep(5 * time.Millisecond)
	}

	err = shutdown(map[string]*http.Server{"lento": srv}, 50*time.Millisecond, loggerDescartado())

	if err == nil {
		t.Fatal("con una petición colgada y un plazo de 50ms el apagado tendría que informar el vencimiento")
	}
	if !strings.Contains(err.Error(), "lento") || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("el error debería nombrar el servidor y envolver el vencimiento: %v", err)
	}
}

func TestShutdownSinServidoresActivosNoFalla(t *testing.T) {
	srv := &http.Server{}

	if err := shutdown(map[string]*http.Server{"inactivo": srv}, time.Second, loggerDescartado()); err != nil {
		t.Errorf("apagar un servidor que nunca arrancó no debería fallar: %v", err)
	}
}

// puertoCerrado devuelve un puerto en el que no escucha nadie.
func puertoCerrado(t *testing.T) string { return puertoLibre(t) }
