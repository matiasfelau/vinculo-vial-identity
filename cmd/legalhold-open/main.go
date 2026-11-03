// Command legalhold-open abre el DNI sellado de un hold de baja de cuenta
// (US-11). Existe para un único caso: un requerimiento judicial que exige el
// DNI de un usuario dado de baja dentro del plazo de retención.
//
// Funciona fuera de línea, en la máquina del responsable legal. Lee la clave
// privada X25519 por la entrada estándar —nunca por una flag ni por una
// variable de entorno, que quedarían en el historial del shell y en la lista de
// procesos— y recibe por flags el user_id y el dni_sealed del hold. Escribe el
// DNI por la salida estándar.
//
//	legalhold-open -user-id <uuid> -sealed <base64> < clave-privada.key
//
// El servicio nunca invoca esta herramienta ni carga la clave privada.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/legalhold"
	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/secure"
)

// maxPrivateKeyInput acota lo que se lee de la entrada estándar: una clave
// X25519 en base64 mide 44 caracteres, así que esto sobra y evita que un pipe
// equivocado cargue memoria sin límite.
const maxPrivateKeyInput = 1 << 10

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "legalhold-open:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("legalhold-open", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rawUserID := fs.String("user-id", "", "user_id del hold (uuid)")
	sealed := fs.String("sealed", "", "dni_sealed del hold (base64)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("argumentos inesperados: %v", fs.Args())
	}

	userID, err := uuid.Parse(*rawUserID)
	if err != nil || userID == uuid.Nil {
		return errors.New("falta -user-id, o no es un uuid válido")
	}
	if *sealed == "" {
		return errors.New("falta -sealed: el dni_sealed del hold")
	}

	raw, err := io.ReadAll(io.LimitReader(stdin, maxPrivateKeyInput+1))
	if err != nil {
		return fmt.Errorf("no se pudo leer la clave privada de la entrada estándar: %w", err)
	}
	defer secure.Wipe(raw)
	if len(raw) > maxPrivateKeyInput {
		return errors.New("la entrada estándar es demasiado larga para ser una clave privada")
	}
	private := strings.TrimSpace(string(raw))
	if private == "" {
		return errors.New("la clave privada debe llegar por la entrada estándar (por ejemplo: < clave-privada.key)")
	}

	dni, err := legalhold.Open(private, userID, *sealed)
	if err != nil {
		return err
	}
	defer secure.Wipe(dni)

	fmt.Fprintln(stdout, string(dni))
	return nil
}
