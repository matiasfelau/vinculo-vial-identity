package consumer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

const backoffDePrueba = 5 * time.Millisecond

type cierreFalso struct {
	mu      sync.Mutex
	cerrada int
}

func (c *cierreFalso) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cerrada++
	return nil
}

func specDePrueba() Spec {
	return Spec{Queue: colaDePrueba, EventType: tipoDePrueba, MaxRetries: 1, Handler: &handlerFalso{}}
}

func TestConfigureChannelAplicaPrefetchYModoConfirm(t *testing.T) {
	canal := nuevoCanalFalso()

	if err := configureChannel(canal, 10, loggerMudo()); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if !canal.qosLlamado || canal.qosPrefetch != 10 {
		t.Errorf("Qos llamado=%v prefetch=%d, se esperaba prefetch 10", canal.qosLlamado, canal.qosPrefetch)
	}
	if !canal.confirmado {
		t.Errorf("el canal debe pasar a modo confirm: la dlq espera la confirmación del broker")
	}
	if canal.retornos == nil {
		t.Errorf("debe registrarse el listener de mensajes devueltos")
	}
}

func TestConfigureChannelPropagaLosErrores(t *testing.T) {
	t.Run("qos", func(t *testing.T) {
		canal := nuevoCanalFalso()
		canal.qosErr = errors.New("qos rechazado")
		if err := configureChannel(canal, 10, loggerMudo()); !errors.Is(err, canal.qosErr) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("confirm", func(t *testing.T) {
		canal := nuevoCanalFalso()
		canal.confirmErr = errors.New("confirm rechazado")
		if err := configureChannel(canal, 10, loggerMudo()); !errors.Is(err, canal.confirmErr) {
			t.Errorf("err = %v", err)
		}
	})
}

// Los mensajes devueltos por el broker se loguean sin su cuerpo.
func TestLogUnroutableNoLogueaElCuerpo(t *testing.T) {
	var registro bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&registro, nil))

	returns := make(chan amqp.Return, 1)
	returns <- amqp.Return{
		Exchange: DLQExchange, RoutingKey: colaDePrueba, ReplyCode: 312, ReplyText: "NO_ROUTE",
		Body: []byte("cuerpo-que-no-debe-aparecer"),
	}
	close(returns)

	logUnroutable(returns, logger)

	out := registro.String()
	if !strings.Contains(out, colaDePrueba) || !strings.Contains(out, "NO_ROUTE") {
		t.Errorf("el log debería nombrar el destino y el motivo: %s", out)
	}
	if strings.Contains(out, "cuerpo-que-no-debe-aparecer") {
		t.Errorf("el log no debe incluir el cuerpo del mensaje: %s", out)
	}
}

// Ante un error de conexión se espera un backoff y se reintenta, sin terminar.
func TestRunWithReconnectReintentaTrasUnErrorDeConexion(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var (
		mu       sync.Mutex
		intentos int
	)
	canal := nuevoCanalFalso()
	dial := func() (io.Closer, Channel, error) {
		mu.Lock()
		defer mu.Unlock()
		intentos++
		if intentos < 3 {
			return nil, nil, errors.New("conexión rechazada")
		}
		return &cierreFalso{}, canal, nil
	}

	hecho := make(chan error, 1)
	go func() {
		hecho <- runWithReconnect(ctx, dial, time.Second, specDePrueba(), loggerMudo(), backoffDePrueba, 4*backoffDePrueba)
	}()

	esperar(t, func() bool { canal.mu.Lock(); defer canal.mu.Unlock(); return len(canal.consumidas) == 1 })
	cancel()

	if err := <-hecho; err != nil {
		t.Errorf("un apagado pedido no es un error: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if intentos != 3 {
		t.Errorf("intentos de conexión = %d, se esperaba 3", intentos)
	}
}

// Si el canal se cae, se cierra lo abierto y se vuelve a conectar.
func TestRunWithReconnectReabreTrasPerderElCanal(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var (
		mu       sync.Mutex
		canales  []*canalFalso
		cierres  []*cierreFalso
		abriendo int
	)
	dial := func() (io.Closer, Channel, error) {
		mu.Lock()
		defer mu.Unlock()
		abriendo++
		canal, cierre := nuevoCanalFalso(), &cierreFalso{}
		if abriendo == 1 {
			close(canal.entregas) // el primer canal se cae enseguida
		}
		canales, cierres = append(canales, canal), append(cierres, cierre)
		return cierre, canal, nil
	}

	hecho := make(chan error, 1)
	go func() {
		hecho <- runWithReconnect(ctx, dial, time.Second, specDePrueba(), loggerMudo(), backoffDePrueba, 4*backoffDePrueba)
	}()

	esperar(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(canales) == 2
	})
	cancel()
	if err := <-hecho; err != nil {
		t.Errorf("un apagado pedido no es un error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if !canales[0].cerrado || cierres[0].cerrada != 1 {
		t.Errorf("el canal y la conexión caídos deben cerrarse antes de reconectar")
	}
}

func TestRunWithReconnectTerminaSiSeCancelaDurantElBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	dial := func() (io.Closer, Channel, error) { return nil, nil, errors.New("sin broker") }

	hecho := make(chan error, 1)
	go func() {
		hecho <- runWithReconnect(ctx, dial, time.Second, specDePrueba(), loggerMudo(), time.Hour, time.Hour)
	}()

	cancel()
	select {
	case err := <-hecho:
		if err != nil {
			t.Errorf("err = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no terminó: un apagado no puede esperar el backoff completo")
	}
}

func TestRunRechazaConfiguracionInvalidaAntesDeConectar(t *testing.T) {
	valida := Settings{URL: "amqp://localhost:1", Prefetch: 10, DialTimeout: time.Second, Heartbeat: time.Second, PublishTimeout: time.Second}

	casos := map[string]func(s *Settings, sp *Spec){
		"sin url":                 func(s *Settings, _ *Spec) { s.URL = "" },
		"prefetch cero":           func(s *Settings, _ *Spec) { s.Prefetch = 0 },
		"prefetch fuera de rango": func(s *Settings, _ *Spec) { s.Prefetch = 70000 },
		"sin timeout de conexión": func(s *Settings, _ *Spec) { s.DialTimeout = 0 },
		"sin heartbeat":           func(s *Settings, _ *Spec) { s.Heartbeat = 0 },
		"sin timeout de dlq":      func(s *Settings, _ *Spec) { s.PublishTimeout = 0 },
		"spec sin handler":        func(_ *Settings, sp *Spec) { sp.Handler = nil },
	}
	for nombre, rota := range casos {
		t.Run(nombre, func(t *testing.T) {
			s, sp := valida, specDePrueba()
			rota(&s, &sp)

			if err := Run(t.Context(), s, sp, loggerMudo()); err == nil {
				t.Errorf("se esperaba un error de configuración")
			}
		})
	}
}

func TestScrubURLOcultaLasCredenciales(t *testing.T) {
	const url = "amqp://usuario:clave-secreta@broker:5672/"

	err := scrubURL(errors.New("fallo al conectar con "+url), url)
	if strings.Contains(err.Error(), "clave-secreta") {
		t.Errorf("el error filtra las credenciales: %v", err)
	}

	sinURL := errors.New("connection refused")
	if got := scrubURL(sinURL, url); !errors.Is(got, sinURL) {
		t.Errorf("un error sin la URL debe devolverse intacto")
	}
}
