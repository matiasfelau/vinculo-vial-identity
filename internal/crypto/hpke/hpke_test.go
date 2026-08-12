package hpke_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/hpke"
	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// Contexto de derivación acordado con el cliente Android. Tink lo pasa como
// `contextInfo` en HybridEncrypt y acá viaja como `info` de RFC 9180.
const testInfo = "vinculo-vial/identity/signup/v1"

// Vector fijo: par de claves y criptograma generados una única vez con la suite
// X25519_HKDF_SHA256 / HKDF_SHA256 / AES256GCM. Congelarlo detecta cualquier
// cambio de wire format que rompería la compatibilidad con los clientes ya
// publicados, algo que un test de round-trip contra sí mismo no vería.
const (
	fixturePrivateKey = "HlNNN8JdepXTytlFpPcOWLvAupVsUQl3AuD++aMuUWw="
	fixturePublicKey  = "v823019zDilxbuUzUBYenCqimwFa06cpIImE964mKQY="
	fixtureCryptogram = "lrlPTVVDmYBwOhgf/O42kKl+DldidwbnKUBTiOIaSj2dcLaiF7cBj2S48SfRD97BTrElLemx1G1vsLcZqjipMXI9MnRFNIKd0DD9M5Jch4RjDMQ/VhyrJ/g7p/ebacZYZTSIchsjc0I5BKW/CVbSgoG1KgmSuDeqZftaiSHktbeN/98="
	fixturePlaintext  = `{"email":"vecino@vinculovial.ar","password":"Rosario-2026!seguro","dni":"30123456"}`
)

func decodeFixtureCryptogram(t *testing.T) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(fixtureCryptogram)
	if err != nil {
		t.Fatalf("el criptograma del vector no es base64 válido: %v", err)
	}
	return raw
}

func TestDecryptKnownVector(t *testing.T) {
	d, err := hpke.NewDecryptorFromBase64(fixturePrivateKey, []byte(testInfo))
	if err != nil {
		t.Fatalf("no se pudo construir el descifrador: %v", err)
	}

	plaintext, err := d.Decrypt(decodeFixtureCryptogram(t))
	if err != nil {
		t.Fatalf("el vector conocido debería descifrar: %v", err)
	}
	if got := string(plaintext); got != fixturePlaintext {
		t.Errorf("plaintext = %q, se esperaba %q", got, fixturePlaintext)
	}
}

func TestPublicKeyDerivadaCoincideConElVector(t *testing.T) {
	d, err := hpke.NewDecryptorFromBase64(fixturePrivateKey, []byte(testInfo))
	if err != nil {
		t.Fatalf("no se pudo construir el descifrador: %v", err)
	}

	pub, err := d.PublicKey()
	if err != nil {
		t.Fatalf("no se pudo derivar la clave pública: %v", err)
	}
	if pub != fixturePublicKey {
		t.Errorf("clave pública = %q, se esperaba %q", pub, fixturePublicKey)
	}
}

func TestDecryptRoundTrip(t *testing.T) {
	priv, pub, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatalf("no se pudo generar el par: %v", err)
	}

	d, err := hpke.NewDecryptorFromBase64(priv, []byte(testInfo))
	if err != nil {
		t.Fatalf("no se pudo construir el descifrador: %v", err)
	}

	for _, payload := range []string{"", "a", strings.Repeat("payload sensible ", 512)} {
		cryptogram, err := hpke.Seal(pub, []byte(testInfo), []byte(payload))
		if err != nil {
			t.Fatalf("no se pudo sellar: %v", err)
		}

		plaintext, err := d.Decrypt(cryptogram)
		if err != nil {
			t.Fatalf("no se pudo descifrar (largo %d): %v", len(payload), err)
		}
		if string(plaintext) != payload {
			t.Errorf("plaintext = %q, se esperaba %q", plaintext, payload)
		}
	}
}

func TestDecryptCriptogramasInvalidos(t *testing.T) {
	priv, pub, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatalf("no se pudo generar el par: %v", err)
	}
	otroPriv, _, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatalf("no se pudo generar el segundo par: %v", err)
	}

	valido, err := hpke.Seal(pub, []byte(testInfo), []byte(`{"dni":"30123456"}`))
	if err != nil {
		t.Fatalf("no se pudo sellar: %v", err)
	}

	tampered := append([]byte(nil), valido...)
	tampered[len(tampered)-1] ^= 0xFF

	encAlterado := append([]byte(nil), valido...)
	encAlterado[0] ^= 0xFF

	cases := []struct {
		name       string
		privateKey string
		info       string
		cryptogram []byte
	}{
		{"clave privada de otro par", otroPriv, testInfo, valido},
		{"info distinto al del emisor", priv, "otro-contexto", valido},
		{"criptograma vacío", priv, testInfo, nil},
		{"solo el encapsulado, sin ciphertext", priv, testInfo, valido[:32]},
		{"criptograma truncado", priv, testInfo, valido[:len(valido)-1]},
		{"tag del AEAD manipulado", priv, testInfo, tampered},
		{"encapsulado manipulado", priv, testInfo, encAlterado},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := hpke.NewDecryptorFromBase64(tc.privateKey, []byte(tc.info))
			if err != nil {
				t.Fatalf("no se pudo construir el descifrador: %v", err)
			}

			plaintext, err := d.Decrypt(tc.cryptogram)
			if !errors.Is(err, domain.ErrInvalidCryptogram) {
				t.Fatalf("error = %v, se esperaba ErrInvalidCryptogram", err)
			}
			if plaintext != nil {
				t.Error("no debe devolverse plaintext ante un fallo de descifrado")
			}
		})
	}
}

func TestNewDecryptorRechazaClavesInvalidas(t *testing.T) {
	cases := map[string]string{
		"no es base64": "no-es-base64-!!!",
		"clave corta":  base64.StdEncoding.EncodeToString(make([]byte, 16)),
		"clave larga":  base64.StdEncoding.EncodeToString(make([]byte, 64)),
		"clave vacía":  "",
	}

	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := hpke.NewDecryptorFromBase64(key, nil); err == nil {
				t.Error("se esperaba un error al construir el descifrador")
			}
		})
	}
}

func TestErrorDeClaveNoFiltraMaterialSensible(t *testing.T) {
	secreto := base64.StdEncoding.EncodeToString(make([]byte, 16))

	_, err := hpke.NewDecryptorFromBase64(secreto, nil)
	if err == nil {
		t.Fatal("se esperaba un error")
	}
	if strings.Contains(err.Error(), secreto) {
		t.Errorf("el error filtra la clave: %q", err)
	}
}

func TestDecryptEsConcurrente(t *testing.T) {
	priv, pub, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatalf("no se pudo generar el par: %v", err)
	}
	d, err := hpke.NewDecryptorFromBase64(priv, []byte(testInfo))
	if err != nil {
		t.Fatalf("no se pudo construir el descifrador: %v", err)
	}

	// Cada Decrypt debe crear su propio Receiver: el estado de nonce del opener
	// no puede compartirse entre peticiones concurrentes.
	const goroutines = 32
	errs := make(chan error, goroutines)
	for i := range goroutines {
		go func(i int) {
			payload := []byte{byte(i)}
			cryptogram, err := hpke.Seal(pub, []byte(testInfo), payload)
			if err != nil {
				errs <- err
				return
			}
			plaintext, err := d.Decrypt(cryptogram)
			if err != nil {
				errs <- err
				return
			}
			if len(plaintext) != 1 || plaintext[0] != byte(i) {
				errs <- errors.New("plaintext incorrecto")
				return
			}
			errs <- nil
		}(i)
	}
	for range goroutines {
		if err := <-errs; err != nil {
			t.Fatalf("fallo en ejecución concurrente: %v", err)
		}
	}
}
