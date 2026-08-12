package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// LoadDotEnv carga variables desde un archivo .env sin pisar las que ya existen
// en el entorno.
//
// Es una comodidad para `go run ./cmd/api` en desarrollo; en contenedor las
// variables llegan del orquestador. La precedencia es deliberada: lo que ya está
// definido gana, para que un .env olvidado en el disco no altere un despliegue.
//
// Si el archivo no existe no es un error: el caso normal en producción.
func LoadDotEnv(path string) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("config: no se pudo abrir %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for line := 1; scanner.Scan(); line++ {
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}

		key, value, found := strings.Cut(raw, "=")
		if !found {
			return fmt.Errorf("config: %s:%d no tiene la forma CLAVE=valor", path, line)
		}

		key = strings.TrimSpace(strings.TrimPrefix(key, "export "))
		value = strings.Trim(strings.TrimSpace(value), `"'`)

		if _, definida := os.LookupEnv(key); definida {
			continue
		}
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("config: no se pudo definir %s: %w", key, err)
		}
	}

	return scanner.Err()
}

// reader acumula los errores de lectura en lugar de cortar en el primero, para
// que un arranque mal configurado informe todo lo que falta de una sola vez en
// vez de obligar a descubrirlo de a un despliegue por variable.
type reader struct {
	errs []error
}

func (r *reader) fail(format string, args ...any) {
	r.errs = append(r.errs, fmt.Errorf(format, args...))
}

func (r *reader) err() error {
	return errors.Join(r.errs...)
}

// required devuelve el valor de una variable obligatoria.
func (r *reader) required(key string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		r.fail("config: falta la variable obligatoria %s", key)
	}
	return v
}

func (r *reader) str(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func (r *reader) integer(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}

	v, err := strconv.Atoi(raw)
	if err != nil {
		r.fail("config: %s debe ser un número entero, se recibió %q", key, raw)
		return fallback
	}
	return v
}

func (r *reader) duration(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}

	v, err := time.ParseDuration(raw)
	if err != nil {
		r.fail("config: %s debe ser una duración como 30s o 5m, se recibió %q", key, raw)
		return fallback
	}
	return v
}

func (r *reader) boolean(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}

	v, err := strconv.ParseBool(raw)
	if err != nil {
		r.fail("config: %s debe ser true o false, se recibió %q", key, raw)
		return fallback
	}
	return v
}
