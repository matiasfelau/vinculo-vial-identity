// Command genkeys genera el material criptográfico que el servicio necesita.
//
// Sin esta herramienta, poner en marcha el entorno local exigiría fabricar a
// mano cuatro claves con el largo y la codificación exactos, que es justo el
// tipo de paso donde se termina reutilizando una clave para dos propósitos.
//
//	go run ./cmd/genkeys
//
// Imprime las cuatro claves privadas —una por mecanismo, nunca compartidas—
// más las dos públicas que sí se distribuyen: la HPKE, que embebe el frontend
// para cifrar el payload del registro, y la de verificación de JWT, que
// consume el Gateway para validar los Access Token que firma este servicio.
//
// La salida es material sensible: no debe quedar en el historial de la terminal
// ni versionarse. En producción las claves las emite y rota el gestor de
// secretos, no esta herramienta.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/blindindex"
	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/hpke"
	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/symmetric"
	"github.com/matiasfelau/vinculo-vial-identity/internal/token"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "genkeys: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	hpkePrivate, hpkePublic, err := hpke.GenerateKeyPair()
	if err != nil {
		return err
	}

	aesKey, err := randomBase64(symmetric.KeyLength)
	if err != nil {
		return fmt.Errorf("no se pudo generar AES_KEY: %w", err)
	}

	hmacSecret, err := randomBase64(blindindex.MinSecretLength)
	if err != nil {
		return fmt.Errorf("no se pudo generar HMAC_SECRET: %w", err)
	}

	jwtPrivate, jwtPublic, err := token.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("no se pudo generar el par de JWT: %w", err)
	}

	fmt.Println("# Claves privadas del servicio — no versionar, no compartir.")
	fmt.Printf("IDENTITY_HPKE_PRIVATE_KEY=%s\n", hpkePrivate)
	fmt.Printf("AES_KEY=%s\n", aesKey)
	fmt.Printf("HMAC_SECRET=%s\n", hmacSecret)
	// El PEM viaja en una sola línea: el parser de .env de este servicio no
	// soporta valores multilínea, así que los saltos de línea reales se
	// escapan como \n literal. config.Load los deshace antes de guardar la
	// clave.
	fmt.Printf("JWT_PRIVATE_KEY=%s\n", escapeNewlines(jwtPrivate))
	fmt.Println()
	fmt.Println("# Claves públicas — las dos que se distribuyen fuera de este servicio.")
	fmt.Println("# HPKE va embebida en el frontend, para cifrar el payload del registro.")
	fmt.Printf("IDENTITY_HPKE_PUBLIC_KEY=%s\n", hpkePublic)
	fmt.Println("# JWT va al Gateway y al resto de la plataforma, como JWT_PUBLIC_KEY, para")
	fmt.Println("# verificar los Access Token que firma este servicio. Escapada por el mismo")
	fmt.Println("# motivo que la privada, aunque el Gateway no tenga la misma restricción: se")
	fmt.Println("# mantiene el mismo formato para copiar y pegar sin transformarla.")
	fmt.Printf("JWT_PUBLIC_KEY=%s\n", escapeNewlines(jwtPublic))

	return nil
}

// escapeNewlines convierte los saltos de línea reales de un PEM en \n
// literal, para que quepa en una sola línea de .env.
func escapeNewlines(pem string) string {
	return strings.ReplaceAll(strings.TrimRight(pem, "\n"), "\n", `\n`) + `\n`
}

func randomBase64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	defer clear(b)

	return base64.StdEncoding.EncodeToString(b), nil
}
