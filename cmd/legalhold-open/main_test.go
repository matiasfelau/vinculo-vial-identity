package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/hpke"
	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/legalhold"
)

const dniDePrueba = "30123456"

type escenario struct {
	privada string
	usuario uuid.UUID
	sellado string
}

func nuevoEscenario(t *testing.T) escenario {
	t.Helper()

	privada, publica, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatalf("no se pudo generar el par: %v", err)
	}
	sellador, err := legalhold.New(publica)
	if err != nil {
		t.Fatalf("no se pudo construir el sellador: %v", err)
	}
	usuario := uuid.New()
	sellado, err := sellador.Seal(usuario, []byte(dniDePrueba))
	if err != nil {
		t.Fatalf("no se pudo sellar: %v", err)
	}
	return escenario{privada: privada, usuario: usuario, sellado: sellado}
}

func ejecutar(t *testing.T, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()

	var out, errOut bytes.Buffer
	err = run(args, strings.NewReader(stdin), &out, &errOut)
	return out.String(), errOut.String(), err
}

// El procedimiento del README: la clave por stdin, el usuario y el sellado por
// flags, y el DNI por stdout.
func TestAbreElHoldConLaClavePrivada(t *testing.T) {
	e := nuevoEscenario(t)

	stdout, stderr, err := ejecutar(t, e.privada+"\n", "-user-id", e.usuario.String(), "-sealed", e.sellado)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if stdout != dniDePrueba+"\n" {
		t.Errorf("stdout = %q, se esperaba el DNI", stdout)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, se esperaba vacío", stderr)
	}
}

// La clave puede venir de un archivo con o sin salto de línea final, y con
// espacios alrededor.
func TestToleraLosEspaciosDeLaClave(t *testing.T) {
	e := nuevoEscenario(t)

	for nombre, entrada := range map[string]string{
		"sin salto final": e.privada,
		"con salto final": e.privada + "\n",
		"con CRLF":        e.privada + "\r\n",
		"con espacios":    "  " + e.privada + "  \n",
	} {
		t.Run(nombre, func(t *testing.T) {
			stdout, _, err := ejecutar(t, entrada, "-user-id", e.usuario.String(), "-sealed", e.sellado)
			if err != nil || stdout != dniDePrueba+"\n" {
				t.Errorf("stdout=%q err=%v", stdout, err)
			}
		})
	}
}

// Sin la clave privada correcta no se abre, y no sale nada por stdout.
func TestNoAbreSinLaClaveCorrecta(t *testing.T) {
	e := nuevoEscenario(t)
	otraPrivada, _, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	stdout, _, err := ejecutar(t, otraPrivada, "-user-id", e.usuario.String(), "-sealed", e.sellado)

	if err == nil {
		t.Fatal("se abrió con una clave privada ajena")
	}
	if stdout != "" {
		t.Errorf("no debe salir nada por stdout: %q", stdout)
	}
}

// El hold está atado al usuario: con otro user_id no abre.
func TestNoAbreConOtroUsuario(t *testing.T) {
	e := nuevoEscenario(t)

	stdout, _, err := ejecutar(t, e.privada, "-user-id", uuid.NewString(), "-sealed", e.sellado)

	if err == nil {
		t.Fatal("se abrió con el user_id de otro usuario")
	}
	if stdout != "" {
		t.Errorf("no debe salir nada por stdout: %q", stdout)
	}
}

func TestRechazaEntradasInvalidas(t *testing.T) {
	e := nuevoEscenario(t)
	usuario, sellado := e.usuario.String(), e.sellado

	casos := map[string]struct {
		stdin string
		args  []string
	}{
		"sin user-id":         {e.privada, []string{"-sealed", sellado}},
		"user-id no es uuid":  {e.privada, []string{"-user-id", "no-es-uuid", "-sealed", sellado}},
		"user-id nulo":        {e.privada, []string{"-user-id", uuid.Nil.String(), "-sealed", sellado}},
		"sin sealed":          {e.privada, []string{"-user-id", usuario}},
		"sealed no es base64": {e.privada, []string{"-user-id", usuario, "-sealed", "###"}},
		"sin clave por stdin": {"", []string{"-user-id", usuario, "-sealed", sellado}},
		"clave solo espacios": {"  \n", []string{"-user-id", usuario, "-sealed", sellado}},
		"clave no es base64":  {"###", []string{"-user-id", usuario, "-sealed", sellado}},
		"clave de largo malo": {"Y29ydGE=", []string{"-user-id", usuario, "-sealed", sellado}},
		"stdin desmesurado":   {strings.Repeat("A", 4<<10), []string{"-user-id", usuario, "-sealed", sellado}},
		"argumento sobrante":  {e.privada, []string{"-user-id", usuario, "-sealed", sellado, "sobrante"}},
		"flag desconocida":    {e.privada, []string{"-user-id", usuario, "-sealed", sellado, "-clave", e.privada}},
	}

	for nombre, caso := range casos {
		t.Run(nombre, func(t *testing.T) {
			stdout, _, err := ejecutar(t, caso.stdin, caso.args...)

			if err == nil {
				t.Fatal("se esperaba un error")
			}
			if stdout != "" {
				t.Errorf("no debe salir nada por stdout: %q", stdout)
			}
		})
	}
}

// Ni la clave privada ni el DNI aparecen en los mensajes de error.
func TestLosErroresNoFiltranLaClaveNiElDNI(t *testing.T) {
	e := nuevoEscenario(t)
	otraPrivada, _, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	casos := map[string][]string{
		"clave ajena":     {otraPrivada, "-user-id", e.usuario.String(), "-sealed", e.sellado},
		"otro usuario":    {e.privada, "-user-id", uuid.NewString(), "-sealed", e.sellado},
		"sealed inválido": {e.privada, "-user-id", e.usuario.String(), "-sealed", "###"},
	}

	for nombre, caso := range casos {
		t.Run(nombre, func(t *testing.T) {
			stdout, stderr, err := ejecutar(t, caso[0], caso[1:]...)
			if err == nil {
				t.Fatal("se esperaba un error")
			}

			todo := stdout + stderr + err.Error()
			for _, secreto := range []string{e.privada, otraPrivada, dniDePrueba} {
				if strings.Contains(todo, secreto) {
					t.Errorf("la salida de error contiene material secreto: %q", todo)
				}
			}
		})
	}
}
