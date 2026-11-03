// Command legalhold-keygen genera el par de claves X25519 del responsable legal
// de la retención por baja de cuenta (US-11).
//
// Imprime la clave pública en base64 por la salida estándar, lista para
// LEGAL_HOLD_PUBLIC_KEY, y escribe la privada en el archivo que indica -out. La
// privada nunca se imprime y nunca debe entrar al repositorio ni cargarla
// ningún servicio: se guarda fuera de línea y solo se usa con
// cmd/legalhold-open ante un requerimiento judicial. Por eso la herramienta
// rechaza una ruta de salida dentro de un repositorio, antes de generar nada.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/hpke"
)

// privateKeyMode son los permisos del archivo de la clave privada: solo su
// dueño la lee. En Windows no tienen efecto, ahí vale el ACL del directorio.
const privateKeyMode os.FileMode = 0o600

// repoMarkers son los archivos cuya presencia marca la raíz de un repositorio
// (o de un módulo Go): una ruta con alguno en un ancestro está "dentro del repo".
var repoMarkers = []string{".git", "go.mod"}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "legalhold-keygen:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("legalhold-keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "ruta del archivo donde escribir la clave privada (fuera de cualquier repositorio; no debe existir)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("argumentos inesperados: %v", fs.Args())
	}
	if *out == "" {
		return errors.New("falta -out: la ruta donde escribir la clave privada")
	}

	// Se valida la ruta antes de generar la clave: una ruta rechazada no deja
	// ninguna clave generada en memoria ni en disco.
	path, err := filepath.Abs(*out)
	if err != nil {
		return fmt.Errorf("ruta de salida inválida: %w", err)
	}
	inside, root, err := insideRepo(path)
	if err != nil {
		return fmt.Errorf("no se pudo verificar la ruta de salida: %w", err)
	}
	if inside {
		return fmt.Errorf("la ruta de salida cae dentro de un repositorio (%s): la clave privada no puede entrar al repo; usá una ruta fuera de él", root)
	}

	private, public, err := hpke.GenerateKeyPair()
	if err != nil {
		return err
	}

	if err := writePrivateKey(path, private); err != nil {
		return err
	}

	fmt.Fprintln(stderr, "clave privada escrita en", path)
	fmt.Fprintln(stderr, "guardala fuera de línea: sin ella no se puede abrir ningún hold; la pública va en LEGAL_HOLD_PUBLIC_KEY")
	fmt.Fprintln(stdout, public)
	return nil
}

// writePrivateKey crea el archivo con O_EXCL: nunca pisa una clave existente,
// porque perderla es perder el acceso a todos los holds sellados con su pública.
func writePrivateKey(path, private string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, privateKeyMode)
	if err != nil {
		return fmt.Errorf("no se pudo crear el archivo de la clave privada (¿ya existe, o falta el directorio?): %w", err)
	}

	if _, err := f.WriteString(private + "\n"); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("no se pudo escribir la clave privada: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("no se pudo cerrar el archivo de la clave privada: %w", err)
	}
	return nil
}

// insideRepo informa si algún ancestro de path contiene un marcador de
// repositorio, y cuál es esa raíz. Resuelve los enlaces simbólicos del tramo
// que ya existe, para que un enlace que apunta al repo no burle la regla.
func insideRepo(path string) (bool, string, error) {
	resolved, err := resolveExisting(path)
	if err != nil {
		return false, "", err
	}

	for dir := filepath.Dir(resolved); ; dir = filepath.Dir(dir) {
		for _, marker := range repoMarkers {
			if _, err := os.Lstat(filepath.Join(dir, marker)); err == nil {
				return true, dir, nil
			} else if !errors.Is(err, os.ErrNotExist) {
				return false, "", err
			}
		}
		if parent := filepath.Dir(dir); parent == dir {
			return false, "", nil
		}
	}
}

// resolveExisting resuelve los enlaces simbólicos del ancestro más profundo de
// path que existe y le vuelve a agregar el resto: path mismo todavía no existe.
func resolveExisting(path string) (string, error) {
	rest := ""
	for current := path; ; current = filepath.Dir(current) {
		real, err := filepath.EvalSymlinks(current)
		if err == nil {
			return filepath.Join(real, rest), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}

		parent := filepath.Dir(current)
		if parent == current {
			return path, nil
		}
		rest = filepath.Join(filepath.Base(current), rest)
	}
}
