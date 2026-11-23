package config_test

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/matiasfelau/vinculo-vial-identity/pkg/config"
)

// Configuración de la aceptación de los términos (US-19).

func TestLoadUsaLosDefaultsDelContratoDeUS19(t *testing.T) {
	aplicar(t, entornoMinimo())

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if cfg.Terms.CurrentVersion != "1.0" {
		t.Errorf("TERMS_CURRENT_VERSION = %q, se esperaba \"1.0\"", cfg.Terms.CurrentVersion)
	}
	if !cfg.Terms.RequireOnSignup {
		t.Error("SIGNUP_REQUIRE_TERMS debería exigir por defecto")
	}
}

func TestLoadAceptaLaConfiguracionDeUS19Personalizada(t *testing.T) {
	env := entornoMinimo()
	env["TERMS_CURRENT_VERSION"] = "  2.1  "
	env["SIGNUP_REQUIRE_TERMS"] = "false"
	aplicar(t, env)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if cfg.Terms.CurrentVersion != "2.1" {
		t.Errorf("TERMS_CURRENT_VERSION = %q, se esperaba \"2.1\" sin espacios", cfg.Terms.CurrentVersion)
	}
	if cfg.Terms.RequireOnSignup {
		t.Error("SIGNUP_REQUIRE_TERMS=false no se cargó")
	}
}

func TestLoadRechazaLaConfiguracionDeTerminosInvalida(t *testing.T) {
	casos := map[string]struct {
		env  map[string]string
		want string
	}{
		"versión más larga que 16":   {map[string]string{"TERMS_CURRENT_VERSION": strings.Repeat("9", 17)}, "TERMS_CURRENT_VERSION"},
		"booleano inválido del flag": {map[string]string{"SIGNUP_REQUIRE_TERMS": "quizás"}, "SIGNUP_REQUIRE_TERMS"},
	}
	for name, c := range casos {
		t.Run(name, func(t *testing.T) {
			env := entornoMinimo()
			for k, v := range c.env {
				env[k] = v
			}
			aplicar(t, env)

			_, err := config.Load()
			if err == nil {
				t.Fatal("se esperaba un error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("el error debería nombrar %s: %v", c.want, err)
			}
		})
	}

	// Como el resto de las variables, una en blanco cuenta como no definida: nunca
	// llega una versión vacía al servicio de alta.
	t.Run("versión en blanco usa el default", func(t *testing.T) {
		env := entornoMinimo()
		env["TERMS_CURRENT_VERSION"] = "   "
		aplicar(t, env)
		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("error inesperado: %v", err)
		}
		if cfg.Terms.CurrentVersion != "1.0" {
			t.Errorf("TERMS_CURRENT_VERSION = %q, se esperaba el default \"1.0\"", cfg.Terms.CurrentVersion)
		}
	})

	t.Run("16 caracteres es el máximo admitido", func(t *testing.T) {
		env := entornoMinimo()
		env["TERMS_CURRENT_VERSION"] = strings.Repeat("9", 16)
		aplicar(t, env)
		if _, err := config.Load(); err != nil {
			t.Errorf("error inesperado: %v", err)
		}
	})
}

// Con APP_ENV=production, SIGNUP_REQUIRE_TERMS=false se rechaza: sin el campo, el
// alta no deja consentimiento registrado.
func TestProduccionRechazaNoExigirLosTerminos(t *testing.T) {
	prod := func() map[string]string {
		env := entornoMinimo()
		env["APP_ENV"] = "production"
		env["POSTGRES_SSLMODE"] = "require"
		env["RABBITMQ_ENABLED"] = "true"
		env["RABBITMQ_URL"] = "amqps://broker:5671/"
		return env
	}

	t.Run("false en producción", func(t *testing.T) {
		env := prod()
		env["SIGNUP_REQUIRE_TERMS"] = "false"
		aplicar(t, env)

		_, err := config.Load()
		if err == nil {
			t.Fatal("se esperaba un error")
		}
		if !strings.Contains(err.Error(), "SIGNUP_REQUIRE_TERMS") {
			t.Errorf("el error debería nombrar la variable: %v", err)
		}
	})
	t.Run("sin definir en producción exige", func(t *testing.T) {
		aplicar(t, prod())
		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("error inesperado: %v", err)
		}
		if !cfg.Terms.RequireOnSignup {
			t.Error("el default tiene que exigir")
		}
	})
	t.Run("false fuera de producción se admite", func(t *testing.T) {
		env := entornoMinimo()
		env["SIGNUP_REQUIRE_TERMS"] = "false"
		aplicar(t, env)
		if _, err := config.Load(); err != nil {
			t.Errorf("error inesperado: %v", err)
		}
	})
}

func TestElLogDeArranqueIncluyeLaConfiguracionDeTerminos(t *testing.T) {
	aplicar(t, entornoMinimo())
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	logs := &strings.Builder{}
	slog.New(slog.NewTextHandler(logs, nil)).Info("arranque", slog.Any("config", cfg))
	for _, campo := range []string{"terms_current_version", "signup_require_terms"} {
		if !strings.Contains(logs.String(), campo) {
			t.Errorf("el log de arranque no incluye %s", campo)
		}
	}
}
