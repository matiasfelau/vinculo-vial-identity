package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/emailcode"
)

// salidaDeRun ejecuta run() y devuelve lo que imprimió, como mapa NOMBRE=valor.
func salidaDeRun(t *testing.T) map[string]string {
	t.Helper()

	original := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("no se pudo crear el pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = original }()

	runErr := run()
	w.Close()
	os.Stdout = original

	if runErr != nil {
		t.Fatalf("run: %v", runErr)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}

	vars := map[string]string{}
	sc := bufio.NewScanner(&buf)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, found := strings.Cut(line, "=")
		if !found {
			t.Fatalf("línea sin la forma NOMBRE=valor: %q", line)
		}
		vars[name] = value
	}
	return vars
}

// genkeys imprime EMAIL_CODE_HMAC_KEY: base64 de 32 bytes, lista para pegar en el
// .env.
func TestGenkeysImprimeLaClaveDeLosCodigosDeEmail(t *testing.T) {
	vars := salidaDeRun(t)

	clave, ok := vars["EMAIL_CODE_HMAC_KEY"]
	if !ok {
		t.Fatal("genkeys no imprimió EMAIL_CODE_HMAC_KEY")
	}
	raw, err := base64.StdEncoding.DecodeString(clave)
	if err != nil {
		t.Fatalf("EMAIL_CODE_HMAC_KEY no es base64 estándar: %v", err)
	}
	if len(raw) != emailcode.KeyLength {
		t.Errorf("EMAIL_CODE_HMAC_KEY mide %d bytes, se esperaban %d", len(raw), emailcode.KeyLength)
	}
	if _, err := emailcode.NewFromBase64(clave); err != nil {
		t.Errorf("la clave impresa no sirve para el codec: %v", err)
	}
}

// Una clave por mecanismo: la de los códigos de email no puede coincidir con
// ninguna de las otras privadas, y cada corrida da una distinta.
func TestGenkeysNoReutilizaLaClaveDeLosCodigosDeEmail(t *testing.T) {
	vars := salidaDeRun(t)
	clave := vars["EMAIL_CODE_HMAC_KEY"]

	for _, otra := range []string{"AES_KEY", "HMAC_SECRET", "IDENTITY_HPKE_PRIVATE_KEY"} {
		if vars[otra] == "" {
			t.Fatalf("falta %s en la salida", otra)
		}
		if vars[otra] == clave {
			t.Errorf("EMAIL_CODE_HMAC_KEY coincide con %s", otra)
		}
	}

	if segunda := salidaDeRun(t)["EMAIL_CODE_HMAC_KEY"]; segunda == clave {
		t.Error("dos corridas dieron la misma clave")
	}
}

// Las claves que ya imprimía siguen ahí.
func TestGenkeysSigueImprimiendoLasDemasClaves(t *testing.T) {
	vars := salidaDeRun(t)
	for _, nombre := range []string{
		"IDENTITY_HPKE_PRIVATE_KEY", "AES_KEY", "HMAC_SECRET", "JWT_PRIVATE_KEY",
		"IDENTITY_HPKE_PUBLIC_KEY", "JWT_PUBLIC_KEY",
	} {
		if vars[nombre] == "" {
			t.Errorf("genkeys no imprimió %s", nombre)
		}
	}
}
