package config_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/matiasfelau/vinculo-vial-identity/pkg/config"
)

// Configuración de la verificación de email y la recuperación de contraseña
// (US-13).

func claveDeCodigos(relleno byte, largo int) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{relleno}, largo))
}

func TestLoadUsaLosDefaultsDelContratoDeUS13(t *testing.T) {
	aplicar(t, entornoMinimo())

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	e := cfg.Email
	checks := []struct {
		name      string
		got, want any
	}{
		{"EMAIL_CODE_TTL_MINUTES", e.CodeTTL, 10 * time.Minute},
		{"EMAIL_CODE_MAX_ATTEMPTS", e.CodeMaxAttempts, 5},
		{"EMAIL_CODE_RESEND_SECONDS", e.CodeResendInterval, 60 * time.Second},
		{"EMAIL_CODE_MAX_SENDS_PER_DAY", e.CodeMaxSendsPerDay, 5},
		{"EMAIL_VERIFICATION_GRANT_TTL_MINUTES", e.VerificationGrantTTL, 30 * time.Minute},
		{"PASSWORD_RESET_GRANT_TTL_MINUTES", e.ResetGrantTTL, 15 * time.Minute},
		{"PASSWORD_RESET_MAX_IDENTITY_ATTEMPTS", e.ResetMaxIdentityAttempts, 3},
		{"SIGNUP_REQUIRE_EMAIL_VERIFICATION", e.RequireVerificationOnSignup, true},
		{"EMAIL_CHALLENGE_SWEEP_INTERVAL", e.SweepInterval, time.Hour},
		{"EMAIL_CHALLENGE_SWEEP_BATCH_SIZE", e.SweepBatchSize, 500},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, se esperaba %v", c.name, c.got, c.want)
		}
	}
	if e.CodeHMACKey.Reveal() != entornoMinimo()["EMAIL_CODE_HMAC_KEY"] {
		t.Error("EMAIL_CODE_HMAC_KEY no se cargó")
	}
}

func TestLoadAceptaLaConfiguracionDeUS13Personalizada(t *testing.T) {
	env := entornoMinimo()
	env["EMAIL_CODE_TTL_MINUTES"] = "3"
	env["EMAIL_CODE_MAX_ATTEMPTS"] = "2"
	env["EMAIL_CODE_RESEND_SECONDS"] = "15"
	env["EMAIL_CODE_MAX_SENDS_PER_DAY"] = "8"
	env["EMAIL_VERIFICATION_GRANT_TTL_MINUTES"] = "45"
	env["PASSWORD_RESET_GRANT_TTL_MINUTES"] = "5"
	env["PASSWORD_RESET_MAX_IDENTITY_ATTEMPTS"] = "4"
	env["SIGNUP_REQUIRE_EMAIL_VERIFICATION"] = "false"
	env["EMAIL_CHALLENGE_SWEEP_INTERVAL"] = "10m"
	env["EMAIL_CHALLENGE_SWEEP_BATCH_SIZE"] = "50"
	aplicar(t, env)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	e := cfg.Email
	if e.CodeTTL != 3*time.Minute || e.CodeMaxAttempts != 2 || e.CodeResendInterval != 15*time.Second ||
		e.CodeMaxSendsPerDay != 8 || e.VerificationGrantTTL != 45*time.Minute || e.ResetGrantTTL != 5*time.Minute ||
		e.ResetMaxIdentityAttempts != 4 || e.RequireVerificationOnSignup || e.SweepInterval != 10*time.Minute ||
		e.SweepBatchSize != 50 {
		t.Errorf("configuración = %+v", e)
	}
}

func TestLoadRechazaLaConfiguracionDeUS13MalFormada(t *testing.T) {
	casos := map[string]struct {
		env      map[string]string
		variable string
	}{
		"TTL del código en cero":        {map[string]string{"EMAIL_CODE_TTL_MINUTES": "0"}, "EMAIL_CODE_TTL_MINUTES"},
		"TTL del código negativo":       {map[string]string{"EMAIL_CODE_TTL_MINUTES": "-1"}, "EMAIL_CODE_TTL_MINUTES"},
		"sin intentos":                  {map[string]string{"EMAIL_CODE_MAX_ATTEMPTS": "0"}, "EMAIL_CODE_MAX_ATTEMPTS"},
		"reenvío en cero":               {map[string]string{"EMAIL_CODE_RESEND_SECONDS": "0"}, "EMAIL_CODE_RESEND_SECONDS"},
		"tope diario en cero":           {map[string]string{"EMAIL_CODE_MAX_SENDS_PER_DAY": "0"}, "EMAIL_CODE_MAX_SENDS_PER_DAY"},
		"vida del token de email":       {map[string]string{"EMAIL_VERIFICATION_GRANT_TTL_MINUTES": "0"}, "EMAIL_VERIFICATION_GRANT_TTL_MINUTES"},
		"vida del reset token":          {map[string]string{"PASSWORD_RESET_GRANT_TTL_MINUTES": "0"}, "PASSWORD_RESET_GRANT_TTL_MINUTES"},
		"intentos de identidad en cero": {map[string]string{"PASSWORD_RESET_MAX_IDENTITY_ATTEMPTS": "0"}, "PASSWORD_RESET_MAX_IDENTITY_ATTEMPTS"},
		"intervalo del barrido en cero": {map[string]string{"EMAIL_CHALLENGE_SWEEP_INTERVAL": "0s"}, "EMAIL_CHALLENGE_SWEEP_INTERVAL"},
		"lote del barrido en cero":      {map[string]string{"EMAIL_CHALLENGE_SWEEP_BATCH_SIZE": "0"}, "EMAIL_CHALLENGE_SWEEP_BATCH_SIZE"},
		"número inválido":               {map[string]string{"EMAIL_CODE_MAX_ATTEMPTS": "cinco"}, "EMAIL_CODE_MAX_ATTEMPTS"},
		"duración inválida":             {map[string]string{"EMAIL_CHALLENGE_SWEEP_INTERVAL": "una hora"}, "EMAIL_CHALLENGE_SWEEP_INTERVAL"},
		"booleano inválido":             {map[string]string{"SIGNUP_REQUIRE_EMAIL_VERIFICATION": "quizás"}, "SIGNUP_REQUIRE_EMAIL_VERIFICATION"},
	}
	for name, tc := range casos {
		t.Run(name, func(t *testing.T) {
			env := entornoMinimo()
			for k, v := range tc.env {
				env[k] = v
			}
			aplicar(t, env)

			_, err := config.Load()
			if err == nil {
				t.Fatal("se esperaba un error")
			}
			if !strings.Contains(err.Error(), tc.variable) {
				t.Errorf("el error debería nombrar %s: %v", tc.variable, err)
			}
		})
	}
}

// La clave de los desafíos tiene que ser base64, de al menos 32 bytes y propia de
// este mecanismo: una clave por mecanismo, nunca reutilizada.
func TestLoadValidaLaClaveDeLosDesafios(t *testing.T) {
	aesYHMAC := entornoMinimo()["AES_KEY"]

	casos := map[string]struct {
		clave string
		want  string
	}{
		"no es base64":                  {"esto no es base64 !!!", "base64"},
		"menos de 32 bytes":             {claveDeCodigos(7, 31), "al menos 32"},
		"igual a AES_KEY y HMAC_SECRET": {aesYHMAC, "una clave por mecanismo"},
	}
	for name, tc := range casos {
		t.Run(name, func(t *testing.T) {
			env := entornoMinimo()
			env["EMAIL_CODE_HMAC_KEY"] = tc.clave
			aplicar(t, env)

			_, err := config.Load()
			if err == nil {
				t.Fatal("se esperaba un error")
			}
			if !strings.Contains(err.Error(), "EMAIL_CODE_HMAC_KEY") || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("el error debería nombrar la variable y el motivo (%q): %v", tc.want, err)
			}
			if strings.Contains(err.Error(), tc.clave) {
				t.Errorf("el error incluye la clave: %v", err)
			}
		})
	}

	t.Run("más de 32 bytes se acepta", func(t *testing.T) {
		env := entornoMinimo()
		env["EMAIL_CODE_HMAC_KEY"] = claveDeCodigos(9, 48)
		aplicar(t, env)
		if _, err := config.Load(); err != nil {
			t.Errorf("error inesperado: %v", err)
		}
	})
}

// Con APP_ENV=production, SIGNUP_REQUIRE_EMAIL_VERIFICATION=false se rechaza: sin
// el token, una cuenta con un email ajeno no podría recuperarse nunca.
func TestProduccionRechazaNoExigirLaVerificacionDeEmail(t *testing.T) {
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
		env["SIGNUP_REQUIRE_EMAIL_VERIFICATION"] = "false"
		aplicar(t, env)

		_, err := config.Load()
		if err == nil {
			t.Fatal("se esperaba un error")
		}
		if !strings.Contains(err.Error(), "SIGNUP_REQUIRE_EMAIL_VERIFICATION") {
			t.Errorf("el error debería nombrar la variable: %v", err)
		}
	})
	t.Run("true en producción", func(t *testing.T) {
		env := prod()
		env["SIGNUP_REQUIRE_EMAIL_VERIFICATION"] = "true"
		aplicar(t, env)
		if _, err := config.Load(); err != nil {
			t.Errorf("error inesperado: %v", err)
		}
	})
	t.Run("sin definir en producción exige", func(t *testing.T) {
		aplicar(t, prod())
		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("error inesperado: %v", err)
		}
		if !cfg.Email.RequireVerificationOnSignup {
			t.Error("el default tiene que ser exigir la verificación")
		}
	})
	t.Run("false en desarrollo", func(t *testing.T) {
		env := entornoMinimo()
		env["SIGNUP_REQUIRE_EMAIL_VERIFICATION"] = "false"
		aplicar(t, env)
		if _, err := config.Load(); err != nil {
			t.Errorf("error inesperado: %v", err)
		}
	})
}

// La clave no se imprime por ningún camino, y los parámetros no secretos sí
// quedan en el log de arranque.
func TestLaConfiguracionDeUS13NoImprimeLaClave(t *testing.T) {
	env := entornoMinimo()
	clave := claveDeCodigos(5, 32)
	env["EMAIL_CODE_HMAC_KEY"] = clave
	aplicar(t, env)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	logs := &strings.Builder{}
	slog.New(slog.NewTextHandler(logs, nil)).Info("arranque", slog.Any("config", cfg))
	rendered := []string{logs.String(), fmt.Sprintf("%v %#v %s", cfg.Email.CodeHMACKey, cfg.Email.CodeHMACKey, cfg.Email.CodeHMACKey)}
	for _, salida := range rendered {
		if strings.Contains(salida, clave) {
			t.Errorf("se filtró la clave en: %s", salida)
		}
	}
	if cfg.Email.CodeHMACKey.Reveal() != clave {
		t.Error("la clave tiene que poder recuperarse explícitamente")
	}

	for _, campo := range []string{
		"email_code_ttl", "email_code_max_attempts", "email_code_resend_interval", "email_code_max_sends_per_day",
		"email_verification_grant_ttl", "password_reset_grant_ttl", "password_reset_max_identity_attempts",
		"signup_require_email_verification", "email_challenge_sweep_interval", "email_challenge_sweep_batch_size",
	} {
		if !strings.Contains(logs.String(), campo) {
			t.Errorf("el log de arranque no incluye %s", campo)
		}
	}
}
