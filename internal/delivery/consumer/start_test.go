package consumer

import (
	"testing"
	"time"
)

func ajustesDePrueba() Settings {
	return Settings{
		// Puerto 1: nadie escucha, la conexión se rechaza de inmediato.
		URL:         "amqp://usuario:clave@127.0.0.1:1/",
		Prefetch:    10,
		DialTimeout: 100 * time.Millisecond,
		Heartbeat:   time.Second, PublishTimeout: time.Second,
	}
}

// Una configuración inválida aborta el arranque antes de lanzar nada.
func TestStartFallaDeInmediatoConConfiguracionInvalida(t *testing.T) {
	sinHandler := specDePrueba()
	sinHandler.Handler = nil

	casos := map[string]struct {
		settings func() Settings
		specs    []Spec
	}{
		"ajustes inválidos": {func() Settings { s := ajustesDePrueba(); s.Prefetch = 0; return s }, []Spec{specDePrueba()}},
		"spec inválido":     {ajustesDePrueba, []Spec{specDePrueba(), sinHandler}},
	}
	for nombre, caso := range casos {
		t.Run(nombre, func(t *testing.T) {
			stop, err := Start(t.Context(), caso.settings(), caso.specs, loggerMudo())
			if err == nil {
				stop()
				t.Fatal("se esperaba un error de configuración")
			}
			if stop != nil {
				t.Errorf("sin arranque no debería haber stop")
			}
		})
	}
}

// El stop corta los reintentos de conexión y espera a los consumidores: un
// broker caído no puede trabar el apagado.
func TestStartSeDetieneAunConElBrokerCaido(t *testing.T) {
	stop, err := Start(t.Context(), ajustesDePrueba(), []Spec{specDePrueba()}, loggerMudo())
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	hecho := make(chan struct{})
	go func() {
		stop()
		close(hecho)
	}()

	select {
	case <-hecho:
	case <-time.After(5 * time.Second):
		t.Fatal("stop no volvió: el apagado quedó esperando al broker")
	}
}

func TestStartSinSpecsNoLanzaNada(t *testing.T) {
	stop, err := Start(t.Context(), ajustesDePrueba(), nil, loggerMudo())
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	stop()
}
