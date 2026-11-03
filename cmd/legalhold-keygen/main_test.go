package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/hpke"
	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/legalhold"
)

// fueraDelRepo devuelve un directorio temporal sin ningún marcador de
// repositorio en sus ancestros. t.TempDir cae bajo el directorio temporal del
// sistema, que no es parte de ningún repo.
func fueraDelRepo(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

func ejecutar(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()

	var out, errOut bytes.Buffer
	err = run(args, &out, &errOut)
	return out.String(), errOut.String(), err
}

func TestGeneraElParYEscribeLaPrivadaFueraDelRepo(t *testing.T) {
	ruta := filepath.Join(fueraDelRepo(t), "legal-hold.key")

	stdout, stderr, err := ejecutar(t, "-out", ruta)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	publica := strings.TrimSpace(stdout)
	rawPublica, err := base64.StdEncoding.DecodeString(publica)
	if err != nil || len(rawPublica) != 32 {
		t.Fatalf("la salida no es una clave pública X25519 en base64 (err %v, %d bytes): %q", err, len(rawPublica), stdout)
	}

	contenido, err := os.ReadFile(ruta)
	if err != nil {
		t.Fatalf("no se escribió la clave privada: %v", err)
	}
	privada := strings.TrimSpace(string(contenido))
	if raw, err := base64.StdEncoding.DecodeString(privada); err != nil || len(raw) != 32 {
		t.Fatalf("el archivo no tiene una clave privada X25519 en base64 (err %v, %d bytes)", err, len(raw))
	}

	// La pública que se imprimió es la de la privada que se guardó.
	dec, err := hpke.NewDecryptorFromBase64(privada, nil)
	if err != nil {
		t.Fatalf("la privada escrita no es utilizable: %v", err)
	}
	if dec.PublicKey() != publica {
		t.Errorf("la pública impresa no corresponde a la privada escrita")
	}

	// Y el par funciona de punta a punta con el sellado del servicio.
	usuario := uuid.New()
	sellador, err := legalhold.New(publica)
	if err != nil {
		t.Fatalf("el servicio no acepta la pública generada: %v", err)
	}
	sellado, err := sellador.Seal(usuario, []byte("30123456"))
	if err != nil {
		t.Fatalf("Seal falló: %v", err)
	}
	dni, err := legalhold.Open(privada, usuario, sellado)
	if err != nil || string(dni) != "30123456" {
		t.Errorf("el par generado no abre lo sellado: %q, %v", dni, err)
	}

	if strings.Contains(stdout, privada) || strings.Contains(stderr, privada) {
		t.Error("la clave privada no debe imprimirse ni por la salida estándar ni por stderr")
	}
}

// Por la salida estándar sale solo la pública, y una sola línea: se puede
// capturar directo con $(...) para LEGAL_HOLD_PUBLIC_KEY.
func TestLaSalidaEstandarEsSoloLaPublica(t *testing.T) {
	stdout, _, err := ejecutar(t, "-out", filepath.Join(fueraDelRepo(t), "k.key"))
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if lineas := strings.Split(strings.TrimRight(stdout, "\n"), "\n"); len(lineas) != 1 {
		t.Errorf("la salida tiene %d líneas, se esperaba 1: %q", len(lineas), stdout)
	}
}

func TestLaPrivadaQuedaSoloParaSuDueno(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("en Windows los permisos de archivo no se expresan con el modo POSIX")
	}
	ruta := filepath.Join(fueraDelRepo(t), "k.key")

	if _, _, err := ejecutar(t, "-out", ruta); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	info, err := os.Stat(ruta)
	if err != nil {
		t.Fatalf("no se pudo leer el archivo: %v", err)
	}
	if modo := info.Mode().Perm(); modo != 0o600 {
		t.Errorf("permisos = %o, se esperaba 600", modo)
	}
}

// El contrato: si la ruta cae dentro del repo, rechaza. Y lo rechaza antes de
// generar: no queda archivo, ni directorio, ni clave pública impresa.
func TestRechazaUnaRutaDentroDeUnRepositorio(t *testing.T) {
	casos := map[string]string{
		".git":   ".git",
		"go.mod": "go.mod",
	}

	for nombre, marcador := range casos {
		t.Run(nombre, func(t *testing.T) {
			repo := fueraDelRepo(t)
			ruta := filepath.Join(repo, "secretos", "legal-hold.key")
			if marcador == ".git" {
				if err := os.Mkdir(filepath.Join(repo, ".git"), 0o755); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(filepath.Join(repo, "go.mod"), []byte("module x\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(repo, "secretos"), 0o755); err != nil {
				t.Fatal(err)
			}

			stdout, _, err := ejecutar(t, "-out", ruta)

			if err == nil {
				t.Fatal("se esperaba un error: la ruta cae dentro del repo")
			}
			if !strings.Contains(err.Error(), "repositorio") {
				t.Errorf("el error debería explicar el motivo: %v", err)
			}
			if stdout != "" {
				t.Errorf("no debe imprimirse ninguna clave: %q", stdout)
			}
			if _, statErr := os.Stat(ruta); !os.IsNotExist(statErr) {
				t.Errorf("no debe quedar ningún archivo escrito (%v)", statErr)
			}
		})
	}
}

// Un .git que es un archivo (worktrees y submódulos) también marca el repo.
func TestRechazaUnWorktreeConGitComoArchivo(t *testing.T) {
	repo := fueraDelRepo(t)
	if err := os.WriteFile(filepath.Join(repo, ".git"), []byte("gitdir: /otro/lugar\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, _, err := ejecutar(t, "-out", filepath.Join(repo, "k.key")); err == nil {
		t.Fatal("se esperaba un error")
	}
}

// Una ruta con ".." que sale del repo hacia afuera es válida; una que entra, no.
func TestResuelveLosPuntosPuntosAntesDeJuzgarLaRuta(t *testing.T) {
	base := fueraDelRepo(t)
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	afuera := filepath.Join(base, "afuera")
	if err := os.Mkdir(afuera, 0o755); err != nil {
		t.Fatal(err)
	}

	t.Run("sale del repo", func(t *testing.T) {
		ruta := filepath.Join(repo, "..", "afuera", "k.key")
		if _, _, err := ejecutar(t, "-out", ruta); err != nil {
			t.Errorf("la ruta efectiva está fuera del repo, debería aceptarse: %v", err)
		}
	})

	t.Run("entra al repo", func(t *testing.T) {
		ruta := filepath.Join(afuera, "..", "repo", "k.key")
		if _, _, err := ejecutar(t, "-out", ruta); err == nil {
			t.Error("la ruta efectiva está dentro del repo, debería rechazarse")
		}
	})
}

// Un enlace simbólico que apunta al repo no burla la regla.
func TestRechazaUnEnlaceSimbolicoQueApuntaAlRepo(t *testing.T) {
	base := fueraDelRepo(t)
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	enlace := filepath.Join(base, "enlace")
	if err := os.Symlink(repo, enlace); err != nil {
		t.Skipf("no se pueden crear enlaces simbólicos en este entorno: %v", err)
	}

	if _, _, err := ejecutar(t, "-out", filepath.Join(enlace, "k.key")); err == nil {
		t.Fatal("se esperaba un error: el enlace apunta al repo")
	}
	if _, err := os.Stat(filepath.Join(repo, "k.key")); !os.IsNotExist(err) {
		t.Errorf("no debe haberse escrito nada en el repo (%v)", err)
	}
}

// Y la del repo de verdad: el directorio de este paquete cuelga del repo de
// vinculo-vial-identity.
func TestRechazaUnaRutaEnElRepoReal(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	ruta := filepath.Join(cwd, "legal-hold-no-debe-existir.key")

	if _, _, err := ejecutar(t, "-out", ruta); err == nil {
		t.Fatal("se esperaba un error")
	}
	if _, err := os.Stat(ruta); !os.IsNotExist(err) {
		_ = os.Remove(ruta)
		t.Errorf("se escribió la clave dentro del repo (%v)", err)
	}
}

// Perder la clave es perder el acceso a todos los holds: no pisa una existente.
func TestNoPisaUnaClaveExistente(t *testing.T) {
	ruta := filepath.Join(fueraDelRepo(t), "k.key")
	if err := os.WriteFile(ruta, []byte("clave-que-no-se-puede-perder\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := ejecutar(t, "-out", ruta)

	if err == nil {
		t.Fatal("se esperaba un error")
	}
	if stdout != "" {
		t.Errorf("no debe imprimirse ninguna clave: %q", stdout)
	}
	contenido, _ := os.ReadFile(ruta)
	if string(contenido) != "clave-que-no-se-puede-perder\n" {
		t.Errorf("se pisó la clave existente: %q", contenido)
	}
}

func TestExigeUnDirectorioExistente(t *testing.T) {
	ruta := filepath.Join(fueraDelRepo(t), "no-existe", "k.key")

	if _, _, err := ejecutar(t, "-out", ruta); err == nil {
		t.Fatal("se esperaba un error")
	}
	if _, err := os.Stat(filepath.Dir(ruta)); !os.IsNotExist(err) {
		t.Errorf("la herramienta no debe crear directorios por su cuenta (%v)", err)
	}
}

func TestExigeLaFlagOut(t *testing.T) {
	stdout, _, err := ejecutar(t)
	if err == nil {
		t.Fatal("se esperaba un error sin -out")
	}
	if stdout != "" {
		t.Errorf("no debe imprimirse ninguna clave: %q", stdout)
	}
}

func TestRechazaArgumentosSobrantes(t *testing.T) {
	if _, _, err := ejecutar(t, "-out", filepath.Join(fueraDelRepo(t), "k.key"), "sobrante"); err == nil {
		t.Fatal("se esperaba un error")
	}
}

// Dos corridas generan pares distintos.
func TestCadaCorridaGeneraUnParNuevo(t *testing.T) {
	dir := fueraDelRepo(t)

	a, _, err := ejecutar(t, "-out", filepath.Join(dir, "a.key"))
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := ejecutar(t, "-out", filepath.Join(dir, "b.key"))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("dos corridas generaron la misma clave pública")
	}
}
