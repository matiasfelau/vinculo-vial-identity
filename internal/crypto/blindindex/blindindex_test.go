package blindindex_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/blindindex"
)

func secret(t *testing.T, fill byte) []byte {
	t.Helper()
	s := make([]byte, blindindex.MinSecretLength)
	for i := range s {
		s[i] = fill
	}
	return s
}

func newIndexer(t *testing.T, fill byte) *blindindex.Indexer {
	t.Helper()
	idx, err := blindindex.New(secret(t, fill))
	if err != nil {
		t.Fatalf("no se pudo construir el indexador: %v", err)
	}
	return idx
}

func TestIndexEsDeterministico(t *testing.T) {
	idx := newIndexer(t, 0x01)

	primero := idx.Index([]byte("30123456"))
	segundo := idx.Index([]byte("30123456"))

	if primero != segundo {
		t.Errorf("el índice no es determinístico: %q != %q", primero, segundo)
	}
}

// El índice se persiste en dni_hashed y está bajo una restricción UNIQUE:
// cambiar el algoritmo o la codificación invalidaría toda la tabla.
func TestIndexCoincideConHMACSHA256Hex(t *testing.T) {
	s := secret(t, 0x02)
	idx, err := blindindex.New(s)
	if err != nil {
		t.Fatalf("no se pudo construir el indexador: %v", err)
	}

	mac := hmac.New(sha256.New, s)
	mac.Write([]byte("30123456"))
	esperado := hex.EncodeToString(mac.Sum(nil))

	if got := idx.Index([]byte("30123456")); got != esperado {
		t.Errorf("índice = %q, se esperaba %q", got, esperado)
	}
}

func TestIndexTieneFormatoEstable(t *testing.T) {
	idx := newIndexer(t, 0x03)

	got := idx.Index([]byte("7654321"))

	if len(got) != sha256.Size*2 {
		t.Errorf("largo = %d, se esperaban %d caracteres hexadecimales", len(got), sha256.Size*2)
	}
	if got != strings.ToLower(got) {
		t.Errorf("el índice debe ser hexadecimal en minúscula: %q", got)
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Errorf("el índice no es hexadecimal válido: %v", err)
	}
}

func TestIndexDistingueEntradas(t *testing.T) {
	idx := newIndexer(t, 0x04)

	if idx.Index([]byte("30123456")) == idx.Index([]byte("30123457")) {
		t.Error("dos DNI distintos no pueden compartir índice")
	}
	// Sin este chequeo, un HMAC mal construido sobre un buffer reutilizado
	// podría colapsar prefijos.
	if idx.Index([]byte("3012345")) == idx.Index([]byte("30123450")) {
		t.Error("un DNI y su prefijo no pueden compartir índice")
	}
}

func TestIndexDependeDelSecreto(t *testing.T) {
	a := newIndexer(t, 0x05)
	b := newIndexer(t, 0x06)

	if a.Index([]byte("30123456")) == b.Index([]byte("30123456")) {
		t.Error("el índice debe depender del secreto: dos secretos distintos dieron el mismo valor")
	}
}

// El indexador guarda copia del secreto; si apuntara al slice del llamador,
// limpiarlo tras la construcción cambiaría los índices en caliente.
func TestIndexerCopiaElSecreto(t *testing.T) {
	s := secret(t, 0x07)
	idx, err := blindindex.New(s)
	if err != nil {
		t.Fatalf("no se pudo construir el indexador: %v", err)
	}

	antes := idx.Index([]byte("30123456"))
	clear(s)
	despues := idx.Index([]byte("30123456"))

	if antes != despues {
		t.Error("limpiar el buffer del llamador no debe alterar el índice")
	}
}

func TestNewRechazaSecretosDebiles(t *testing.T) {
	cases := map[string][]byte{
		"secreto nil":   nil,
		"secreto vacío": {},
		"un byte menos": make([]byte, blindindex.MinSecretLength-1),
	}

	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := blindindex.New(s); err == nil {
				t.Error("se esperaba un error por secreto insuficiente")
			}
		})
	}
}

func TestNewFromBase64(t *testing.T) {
	t.Run("acepta un secreto válido", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString(secret(t, 0x08))
		if _, err := blindindex.NewFromBase64(encoded); err != nil {
			t.Errorf("error inesperado: %v", err)
		}
	})

	t.Run("rechaza entradas inválidas", func(t *testing.T) {
		cases := map[string]string{
			"no es base64": "no-es-base64-!!!",
			"vacío":        "",
			"muy corto":    base64.StdEncoding.EncodeToString(make([]byte, 16)),
		}
		for name, encoded := range cases {
			t.Run(name, func(t *testing.T) {
				if _, err := blindindex.NewFromBase64(encoded); err == nil {
					t.Error("se esperaba un error")
				}
			})
		}
	})
}
