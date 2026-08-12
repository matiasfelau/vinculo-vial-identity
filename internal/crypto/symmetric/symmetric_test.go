package symmetric_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/symmetric"
)

func key(t *testing.T, fill byte) []byte {
	t.Helper()
	k := make([]byte, symmetric.KeyLength)
	for i := range k {
		k[i] = fill
	}
	return k
}

func newCipher(t *testing.T, fill byte) *symmetric.Cipher {
	t.Helper()
	c, err := symmetric.New(key(t, fill))
	if err != nil {
		t.Fatalf("no se pudo construir el cifrador: %v", err)
	}
	return c
}

func TestRoundTrip(t *testing.T) {
	c := newCipher(t, 0x01)

	cases := map[string]string{
		"DNI típico":     "30123456",
		"DNI de 7":       "7654321",
		"vacío":          "",
		"con acentos":    "Ñandú áéíóú",
		"payload grande": strings.Repeat("dato sensible ", 1024),
	}

	for name, plaintext := range cases {
		t.Run(name, func(t *testing.T) {
			ciphertext, err := c.Encrypt([]byte(plaintext))
			if err != nil {
				t.Fatalf("no se pudo cifrar: %v", err)
			}

			got, err := c.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("no se pudo descifrar: %v", err)
			}
			if string(got) != plaintext {
				t.Errorf("plaintext = %q, se esperaba %q", got, plaintext)
			}
		})
	}
}

// Con GCM, repetir un nonce bajo la misma clave rompe la confidencialidad y
// permite forjar mensajes. Que dos cifrados del mismo dato difieran es la
// evidencia observable de que el nonce se genera por operación.
func TestEncryptNoEsDeterministico(t *testing.T) {
	c := newCipher(t, 0x02)

	vistos := make(map[string]struct{}, 128)
	for range 128 {
		ciphertext, err := c.Encrypt([]byte("30123456"))
		if err != nil {
			t.Fatalf("no se pudo cifrar: %v", err)
		}
		if _, repetido := vistos[ciphertext]; repetido {
			t.Fatal("se repitió un criptograma: el nonce se está reutilizando")
		}
		vistos[ciphertext] = struct{}{}
	}
}

func TestEncryptDevuelveBase64EstandarSinFiltrarElPlaintext(t *testing.T) {
	c := newCipher(t, 0x03)
	const dni = "30123456"

	ciphertext, err := c.Encrypt([]byte(dni))
	if err != nil {
		t.Fatalf("no se pudo cifrar: %v", err)
	}

	if _, err := base64.StdEncoding.DecodeString(ciphertext); err != nil {
		t.Errorf("el criptograma no es base64 estándar válido: %v", err)
	}
	if strings.Contains(ciphertext, dni) {
		t.Error("el criptograma contiene el plaintext")
	}
}

func TestDecryptRechazaCriptogramasInvalidos(t *testing.T) {
	c := newCipher(t, 0x04)

	valido, err := c.Encrypt([]byte("30123456"))
	if err != nil {
		t.Fatalf("no se pudo cifrar: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(valido)
	if err != nil {
		t.Fatalf("no se pudo decodificar: %v", err)
	}

	manipulado := append([]byte(nil), raw...)
	manipulado[len(manipulado)-1] ^= 0xFF

	nonceAlterado := append([]byte(nil), raw...)
	nonceAlterado[0] ^= 0xFF

	cases := map[string]string{
		"no es base64":     "no-es-base64-!!!",
		"vacío":            "",
		"solo el nonce":    base64.StdEncoding.EncodeToString(raw[:12]),
		"truncado":         base64.StdEncoding.EncodeToString(raw[:len(raw)-1]),
		"tag manipulado":   base64.StdEncoding.EncodeToString(manipulado),
		"nonce manipulado": base64.StdEncoding.EncodeToString(nonceAlterado),
	}

	for name, ciphertext := range cases {
		t.Run(name, func(t *testing.T) {
			plaintext, err := c.Decrypt(ciphertext)
			if !errors.Is(err, symmetric.ErrInvalidCiphertext) {
				t.Fatalf("error = %v, se esperaba ErrInvalidCiphertext", err)
			}
			if plaintext != nil {
				t.Error("no debe devolverse plaintext ante un fallo")
			}
		})
	}
}

func TestDecryptRechazaCriptogramasDeOtraClave(t *testing.T) {
	origen := newCipher(t, 0x05)
	otro := newCipher(t, 0x06)

	ciphertext, err := origen.Encrypt([]byte("30123456"))
	if err != nil {
		t.Fatalf("no se pudo cifrar: %v", err)
	}

	if _, err := otro.Decrypt(ciphertext); !errors.Is(err, symmetric.ErrInvalidCiphertext) {
		t.Errorf("error = %v, se esperaba ErrInvalidCiphertext", err)
	}
}

func TestNewExigeAES256(t *testing.T) {
	cases := map[string][]byte{
		"clave nil":   nil,
		"clave de 16": make([]byte, 16),
		"clave de 24": make([]byte, 24),
		"clave de 33": make([]byte, 33),
	}

	for name, k := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := symmetric.New(k); err == nil {
				t.Error("se esperaba un error: solo se admite AES-256")
			}
		})
	}
}

func TestNewFromBase64(t *testing.T) {
	t.Run("acepta una clave válida", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString(key(t, 0x07))
		if _, err := symmetric.NewFromBase64(encoded); err != nil {
			t.Errorf("error inesperado: %v", err)
		}
	})

	t.Run("rechaza entradas inválidas", func(t *testing.T) {
		cases := map[string]string{
			"no es base64":  "no-es-base64-!!!",
			"vacía":         "",
			"largo erróneo": base64.StdEncoding.EncodeToString(make([]byte, 16)),
		}
		for name, encoded := range cases {
			t.Run(name, func(t *testing.T) {
				if _, err := symmetric.NewFromBase64(encoded); err == nil {
					t.Error("se esperaba un error")
				}
			})
		}
	})
}

func TestCipherEsConcurrente(t *testing.T) {
	c := newCipher(t, 0x08)

	const goroutines = 32
	errs := make(chan error, goroutines)
	for range goroutines {
		go func() {
			ciphertext, err := c.Encrypt([]byte("30123456"))
			if err != nil {
				errs <- err
				return
			}
			plaintext, err := c.Decrypt(ciphertext)
			if err != nil {
				errs <- err
				return
			}
			if string(plaintext) != "30123456" {
				errs <- errors.New("plaintext incorrecto")
				return
			}
			errs <- nil
		}()
	}
	for range goroutines {
		if err := <-errs; err != nil {
			t.Fatalf("fallo en ejecución concurrente: %v", err)
		}
	}
}
