package config_test

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/matiasfelau/vinculo-vial-identity/pkg/config"
)

// claveDeAdminDePrueba mide 40 caracteres: sobre el mínimo de 32 y distinta del
// INTERNAL_SERVICE_TOKEN de entornoMinimo.
const claveDeAdminDePrueba = "clave-de-administracion-de-prueba-0001"

// Sin ADMIN_API_KEY el servicio levanta con el router de administración
// apagado, y el puerto tiene su valor por defecto.
func TestLoadSinClaveDeAdministracionDejaElRouterApagado(t *testing.T) {
	aplicar(t, entornoMinimo())

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if cfg.Admin.Enabled() {
		t.Error("el router de administración no debería estar habilitado sin clave")
	}
	if cfg.Admin.Port != 8082 {
		t.Errorf("puerto = %d, se esperaba 8082", cfg.Admin.Port)
	}
	if cfg.Admin.Addr() != ":8082" {
		t.Errorf("Addr = %q, se esperaba :8082", cfg.Admin.Addr())
	}
}

func TestLoadAceptaLaClaveYElPuertoDeAdministracion(t *testing.T) {
	env := entornoMinimo()
	env["ADMIN_API_KEY"] = claveDeAdminDePrueba
	env["HTTP_ADMIN_PORT"] = "9092"
	aplicar(t, env)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if !cfg.Admin.Enabled() {
		t.Error("con clave, el router de administración debería estar habilitado")
	}
	if cfg.Admin.Port != 9092 {
		t.Errorf("puerto = %d, se esperaba 9092", cfg.Admin.Port)
	}
	if cfg.Admin.APIKey.Reveal() != claveDeAdminDePrueba {
		t.Error("Reveal debería devolver la clave en claro")
	}
}

func TestLoadRechazaElPuertoDeAdministracionMalConfigurado(t *testing.T) {
	cases := map[string]map[string]string{
		"fuera de rango por arriba": {"HTTP_ADMIN_PORT": "70000"},
		"cero":                      {"HTTP_ADMIN_PORT": "0"},
		"igual al público":          {"HTTP_ADMIN_PORT": "8080"},
		"igual al interno":          {"HTTP_ADMIN_PORT": "8081"},
	}
	for name, override := range cases {
		t.Run(name, func(t *testing.T) {
			env := entornoMinimo()
			for k, v := range override {
				env[k] = v
			}
			aplicar(t, env)

			_, err := config.Load()
			if err == nil {
				t.Fatalf("se esperaba un error por HTTP_ADMIN_PORT (%s)", name)
			}
			if !strings.Contains(err.Error(), "HTTP_ADMIN_PORT") {
				t.Errorf("el error no nombra la variable: %v", err)
			}
		})
	}
}

// Con APP_ENV=production, una clave de menos de 32 caracteres impide arrancar.
func TestProduccionRechazaUnaClaveDeAdministracionCorta(t *testing.T) {
	env := entornoMinimo()
	env["APP_ENV"] = "production"
	env["POSTGRES_SSLMODE"] = "require"
	env["RABBITMQ_ENABLED"] = "true"
	env["RABBITMQ_URL"] = "amqps://broker:5671/"
	env["ADMIN_API_KEY"] = strings.Repeat("c", 31)
	aplicar(t, env)

	_, err := config.Load()
	if err == nil {
		t.Fatal("se esperaba que una clave de 31 caracteres fuera rechazada en producción")
	}
	if !strings.Contains(err.Error(), "ADMIN_API_KEY") {
		t.Errorf("el error no nombra la variable: %v", err)
	}
}

// En producción una clave de 32 caracteres levanta, y la clave vacía también: el
// router simplemente no arranca.
func TestProduccionAceptaLaClaveDeAdministracionLargaOVacia(t *testing.T) {
	for name, clave := range map[string]string{"32 caracteres": strings.Repeat("c", 32), "vacía": ""} {
		t.Run(name, func(t *testing.T) {
			env := entornoMinimo()
			env["APP_ENV"] = "production"
			env["POSTGRES_SSLMODE"] = "require"
			env["RABBITMQ_ENABLED"] = "true"
			env["RABBITMQ_URL"] = "amqps://broker:5671/"
			env["ADMIN_API_KEY"] = clave
			aplicar(t, env)

			cfg, err := config.Load()
			if err != nil {
				t.Fatalf("error inesperado: %v", err)
			}
			if got, want := cfg.Admin.Enabled(), clave != ""; got != want {
				t.Errorf("Enabled = %v, se esperaba %v", got, want)
			}
		})
	}
}

// Una clave por mecanismo: la de administración no puede ser el secreto del
// router interno, en ningún entorno.
func TestLoadRechazaLaClaveDeAdministracionIgualAlSecretoInterno(t *testing.T) {
	for _, appEnv := range []string{"development", "production"} {
		t.Run(appEnv, func(t *testing.T) {
			env := entornoMinimo()
			env["APP_ENV"] = appEnv
			if appEnv == "production" {
				env["POSTGRES_SSLMODE"] = "require"
				env["RABBITMQ_ENABLED"] = "true"
				env["RABBITMQ_URL"] = "amqps://broker:5671/"
			}
			env["ADMIN_API_KEY"] = env["INTERNAL_SERVICE_TOKEN"]
			aplicar(t, env)

			_, err := config.Load()
			if err == nil {
				t.Fatal("se esperaba que reutilizar INTERNAL_SERVICE_TOKEN fuera rechazado")
			}
			if !strings.Contains(err.Error(), "INTERNAL_SERVICE_TOKEN") {
				t.Errorf("el error no explica el motivo: %v", err)
			}
		})
	}
}

// La clave no se imprime por ningún camino de formateo, y el log de arranque dice
// si el router está habilitado y en qué puerto.
func TestLaClaveDeAdministracionNoSeImprime(t *testing.T) {
	env := entornoMinimo()
	env["ADMIN_API_KEY"] = claveDeAdminDePrueba
	aplicar(t, env)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	logs := &strings.Builder{}
	slog.New(slog.NewTextHandler(logs, nil)).Info("arranque", slog.Any("config", cfg))

	if strings.Contains(logs.String(), claveDeAdminDePrueba) {
		t.Errorf("se filtró ADMIN_API_KEY en el log: %s", logs.String())
	}
	if strings.Contains(cfg.Admin.APIKey.String(), claveDeAdminDePrueba) {
		t.Error("String() de la clave no está redactado")
	}
	for _, want := range []string{"admin_port=8082", "admin_enabled=true"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("el log de arranque no contiene %q: %s", want, logs.String())
		}
	}
}
