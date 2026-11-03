package legalhold_test

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/hpke"
	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/legalhold"
)

const dniDePrueba = "30123456"

func parDeClaves(t *testing.T) (privada, publica string) {
	t.Helper()

	privada, publica, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatalf("no se pudo generar el par de claves: %v", err)
	}
	return privada, publica
}

func sellador(t *testing.T, publica string) *legalhold.Sealer {
	t.Helper()

	s, err := legalhold.New(publica)
	if err != nil {
		t.Fatalf("error inesperado al construir el sellador: %v", err)
	}
	return s
}

// El `info` es el que fija el contrato: UTF-8 de "vv-legal-hold:" + user_id.
func TestInfoEsElDelContrato(t *testing.T) {
	usuario := uuid.MustParse("6f2a4c1e-9d3b-4f5a-8c7d-1e2f3a4b5c6d")

	if got, want := string(legalhold.Info(usuario)), "vv-legal-hold:6f2a4c1e-9d3b-4f5a-8c7d-1e2f3a4b5c6d"; got != want {
		t.Errorf("info = %q, se esperaba %q", got, want)
	}
}

// Lo sellado se abre con la clave privada y devuelve el DNI canónico.
func TestSealSeAbreConLaClavePrivada(t *testing.T) {
	privada, publica := parDeClaves(t)
	usuario := uuid.New()

	sellado, err := sellador(t, publica).Seal(usuario, []byte(dniDePrueba))
	if err != nil {
		t.Fatalf("Seal falló: %v", err)
	}

	dni, err := legalhold.Open(privada, usuario, sellado)
	if err != nil {
		t.Fatalf("Open falló con la clave correcta: %v", err)
	}
	if string(dni) != dniDePrueba {
		t.Errorf("DNI = %q, se esperaba %q", dni, dniDePrueba)
	}
}

// El formato es base64 estándar de enc‖ct: 32 bytes de enc (X25519) más el
// ciphertext con su tag de 16 bytes.
func TestSealDevuelveBase64DeEncMasCt(t *testing.T) {
	_, publica := parDeClaves(t)

	sellado, err := sellador(t, publica).Seal(uuid.New(), []byte(dniDePrueba))
	if err != nil {
		t.Fatalf("Seal falló: %v", err)
	}

	raw, err := base64.StdEncoding.DecodeString(sellado)
	if err != nil {
		t.Fatalf("el sellado no es base64 estándar: %v", err)
	}
	const encLen, tagLen = 32, 16
	if want := encLen + len(dniDePrueba) + tagLen; len(raw) != want {
		t.Errorf("el sellado mide %d bytes, se esperaban %d (enc + ct + tag)", len(raw), want)
	}
}

// El sellado nunca contiene el DNI en claro, ni en binario ni en base64.
func TestSealNoContieneElDNIEnClaro(t *testing.T) {
	_, publica := parDeClaves(t)

	sellado, err := sellador(t, publica).Seal(uuid.New(), []byte(dniDePrueba))
	if err != nil {
		t.Fatalf("Seal falló: %v", err)
	}

	raw, _ := base64.StdEncoding.DecodeString(sellado)
	if strings.Contains(sellado, dniDePrueba) || bytes.Contains(raw, []byte(dniDePrueba)) {
		t.Error("el sellado contiene el DNI en claro")
	}
}

// Sin la clave privada no se abre: ni con otra clave, ni con una clave
// inventada, y siempre con el mismo error, sin detalle criptográfico.
func TestOpenFallaSinLaClavePrivadaCorrecta(t *testing.T) {
	_, publica := parDeClaves(t)
	otraPrivada, _ := parDeClaves(t)
	usuario := uuid.New()

	sellado, err := sellador(t, publica).Seal(usuario, []byte(dniDePrueba))
	if err != nil {
		t.Fatalf("Seal falló: %v", err)
	}

	dni, err := legalhold.Open(otraPrivada, usuario, sellado)
	if err == nil {
		t.Fatalf("se abrió con una clave privada ajena: %q", dni)
	}
	if strings.Contains(err.Error(), dniDePrueba) {
		t.Errorf("el error filtra el DNI: %v", err)
	}
}

// El `info` ata el criptograma al usuario: copiado a la fila de otro, no abre.
func TestOpenFallaConOtroUsuario(t *testing.T) {
	privada, publica := parDeClaves(t)
	dueno, otro := uuid.New(), uuid.New()

	sellado, err := sellador(t, publica).Seal(dueno, []byte(dniDePrueba))
	if err != nil {
		t.Fatalf("Seal falló: %v", err)
	}

	if dni, err := legalhold.Open(privada, otro, sellado); err == nil {
		t.Fatalf("se abrió con el user_id de otro usuario: %q", dni)
	}
	if _, err := legalhold.Open(privada, dueno, sellado); err != nil {
		t.Errorf("con el user_id correcto debía abrir: %v", err)
	}
}

func TestOpenRechazaEntradasInvalidas(t *testing.T) {
	privada, publica := parDeClaves(t)
	usuario := uuid.New()
	sellado, err := sellador(t, publica).Seal(usuario, []byte(dniDePrueba))
	if err != nil {
		t.Fatalf("Seal falló: %v", err)
	}
	raw, _ := base64.StdEncoding.DecodeString(sellado)
	manipulado := append([]byte(nil), raw...)
	manipulado[len(manipulado)-1] ^= 0xff

	casos := map[string]struct {
		privada string
		sellado string
	}{
		"criptograma no es base64": {privada, "###"},
		"criptograma vacío":        {privada, ""},
		"criptograma truncado":     {privada, base64.StdEncoding.EncodeToString(raw[:10])},
		"criptograma manipulado":   {privada, base64.StdEncoding.EncodeToString(manipulado)},
		"clave no es base64":       {"###", sellado},
		"clave de largo inválido":  {base64.StdEncoding.EncodeToString([]byte("corta")), sellado},
		"clave vacía":              {"", sellado},
	}

	for nombre, caso := range casos {
		t.Run(nombre, func(t *testing.T) {
			if dni, err := legalhold.Open(caso.privada, usuario, caso.sellado); err == nil {
				t.Errorf("se esperaba un error, se abrió: %q", dni)
			}
		})
	}
}

// Dos sellados del mismo DNI no se parecen: HPKE usa una clave efímera nueva por
// mensaje, así que el hold no permite saber que dos bajas son del mismo DNI.
func TestSealEsNoDeterministico(t *testing.T) {
	_, publica := parDeClaves(t)
	s := sellador(t, publica)
	usuario := uuid.New()

	a, err := s.Seal(usuario, []byte(dniDePrueba))
	if err != nil {
		t.Fatalf("Seal falló: %v", err)
	}
	b, err := s.Seal(usuario, []byte(dniDePrueba))
	if err != nil {
		t.Fatalf("Seal falló: %v", err)
	}
	if a == b {
		t.Error("dos sellados del mismo DNI son idénticos")
	}
}

func TestSealRechazaEntradasInvalidas(t *testing.T) {
	_, publica := parDeClaves(t)
	s := sellador(t, publica)

	if _, err := s.Seal(uuid.Nil, []byte(dniDePrueba)); err == nil {
		t.Error("se esperaba un error sin usuario")
	}
	if _, err := s.Seal(uuid.New(), nil); err == nil {
		t.Error("se esperaba un error sin DNI")
	}
	if _, err := s.Seal(uuid.New(), []byte{}); err == nil {
		t.Error("se esperaba un error con DNI vacío")
	}
}

// Una clave pública inutilizable hace fallar el arranque, no la primera baja.
func TestNewRechazaUnaClavePublicaInutilizable(t *testing.T) {
	casos := map[string]string{
		"vacía":          "",
		"no es base64":   "###",
		"largo inválido": base64.StdEncoding.EncodeToString([]byte("corta")),
		"largo de más":   base64.StdEncoding.EncodeToString(make([]byte, 64)),
	}

	for nombre, clave := range casos {
		t.Run(nombre, func(t *testing.T) {
			if _, err := legalhold.New(clave); err == nil {
				t.Error("se esperaba un error")
			}
		})
	}
}
