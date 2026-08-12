// Command genkeys genera el material criptográfico que el servicio necesita.
//
// Sin esta herramienta, poner en marcha el entorno local exigiría fabricar a
// mano tres claves con el largo y la codificación exactos, que es justo el tipo
// de paso donde se termina reutilizando una clave para dos propósitos.
//
//	go run ./cmd/genkeys
//
// Imprime las tres claves privadas —una por mecanismo, nunca compartidas— más
// la clave pública HPKE, que es la única que sale de acá: es la que embebe la
// app Android para cifrar el payload del registro.
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

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/blindindex"
	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/hpke"
	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/symmetric"
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

	fmt.Println("# Claves privadas del servicio — no versionar, no compartir.")
	fmt.Printf("HPKE_PRIVATE_KEY=%s\n", hpkePrivate)
	fmt.Printf("AES_KEY=%s\n", aesKey)
	fmt.Printf("HMAC_SECRET=%s\n", hmacSecret)
	fmt.Println()
	fmt.Println("# Clave pública HPKE — la única que se distribuye; va embebida en la app.")
	fmt.Printf("HPKE_PUBLIC_KEY=%s\n", hpkePublic)

	return nil
}

func randomBase64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	defer clear(b)

	return base64.StdEncoding.EncodeToString(b), nil
}
