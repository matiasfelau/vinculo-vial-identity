package auditseal_test

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/auditseal"
	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/hpke"
)

const (
	dniDePrueba = "30123456"
	idDeClave   = "2026-11"
)

func parDeClaves(t *testing.T) (privada, publica string) {
	t.Helper()

	privada, publica, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatalf("no se pudo generar el par de claves: %v", err)
	}
	return privada, publica
}

func sellador(t *testing.T, publica string) *auditseal.Sealer {
	t.Helper()

	s, err := auditseal.New(publica, idDeClave)
	if err != nil {
		t.Fatalf("error inesperado al construir el sellador: %v", err)
	}
	return s
}

// abrir hace lo que hará audit-open, fuera de este servicio: abre con la clave
// privada y el `info` que se le indique.
func abrir(privada string, info []byte, sellado string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(sellado)
	if err != nil {
		return nil, err
	}
	dec, err := hpke.NewDecryptorFromBase64(privada, info)
	if err != nil {
		return nil, err
	}
	return dec.DecryptCombined(raw)
}

// El `info` es el que fija el contrato: UTF-8 de "vv-audit:dni:" + alert_id.
func TestInfoEsElDelContrato(t *testing.T) {
	alerta := uuid.MustParse("6f2a4c1e-9d3b-4f5a-8c7d-1e2f3a4b5c6d")

	if got, want := string(auditseal.Info(alerta)), "vv-audit:dni:6f2a4c1e-9d3b-4f5a-8c7d-1e2f3a4b5c6d"; got != want {
		t.Errorf("info = %q, se esperaba %q", got, want)
	}
}

// Lo sellado se abre con la clave privada y el `info` de su alerta, y devuelve
// el DNI canónico.
func TestSealDNISeAbreConLaClavePrivada(t *testing.T) {
	privada, publica := parDeClaves(t)
	alerta := uuid.New()

	sellado, err := sellador(t, publica).SealDNI(alerta, []byte(dniDePrueba))
	if err != nil {
		t.Fatalf("SealDNI falló: %v", err)
	}

	dni, err := abrir(privada, auditseal.Info(alerta), sellado.Sealed)
	if err != nil {
		t.Fatalf("no abrió con la clave correcta: %v", err)
	}
	if string(dni) != dniDePrueba {
		t.Errorf("DNI = %q, se esperaba %q", dni, dniDePrueba)
	}
}

func TestSealDNIDevuelveElIDDeLaClave(t *testing.T) {
	_, publica := parDeClaves(t)

	sellado, err := sellador(t, publica).SealDNI(uuid.New(), []byte(dniDePrueba))
	if err != nil {
		t.Fatalf("SealDNI falló: %v", err)
	}

	if sellado.KeyID != idDeClave {
		t.Errorf("KeyID = %q, se esperaba %q", sellado.KeyID, idDeClave)
	}
}

// El formato es base64 estándar de enc‖ct: 32 bytes de enc (X25519) más el
// ciphertext con su tag de 16 bytes.
func TestSealDNIDevuelveBase64DeEncMasCt(t *testing.T) {
	_, publica := parDeClaves(t)

	sellado, err := sellador(t, publica).SealDNI(uuid.New(), []byte(dniDePrueba))
	if err != nil {
		t.Fatalf("SealDNI falló: %v", err)
	}

	raw, err := base64.StdEncoding.DecodeString(sellado.Sealed)
	if err != nil {
		t.Fatalf("el sellado no es base64 estándar: %v", err)
	}
	const encLen, tagLen = 32, 16
	if want := encLen + len(dniDePrueba) + tagLen; len(raw) != want {
		t.Errorf("el sellado mide %d bytes, se esperaban %d (enc + ct + tag)", len(raw), want)
	}
}

// El sellado nunca contiene el DNI en claro, ni en binario ni en base64.
func TestSealDNINoContieneElDNIEnClaro(t *testing.T) {
	_, publica := parDeClaves(t)

	sellado, err := sellador(t, publica).SealDNI(uuid.New(), []byte(dniDePrueba))
	if err != nil {
		t.Fatalf("SealDNI falló: %v", err)
	}

	raw, _ := base64.StdEncoding.DecodeString(sellado.Sealed)
	if strings.Contains(sellado.Sealed, dniDePrueba) || bytes.Contains(raw, []byte(dniDePrueba)) {
		t.Error("el sellado contiene el DNI en claro")
	}
}

// Sin la clave privada no se abre: con otra clave no hay forma de recuperar el
// DNI, y el error no lo filtra.
func TestSealDNINoSeAbreConOtraClavePrivada(t *testing.T) {
	_, publica := parDeClaves(t)
	otraPrivada, _ := parDeClaves(t)
	alerta := uuid.New()

	sellado, err := sellador(t, publica).SealDNI(alerta, []byte(dniDePrueba))
	if err != nil {
		t.Fatalf("SealDNI falló: %v", err)
	}

	dni, err := abrir(otraPrivada, auditseal.Info(alerta), sellado.Sealed)
	if err == nil {
		t.Fatalf("se abrió con una clave privada ajena: %q", dni)
	}
	if strings.Contains(err.Error(), dniDePrueba) {
		t.Errorf("el error filtra el DNI: %v", err)
	}
}

// El `info` ata el criptograma a su alerta: movido al registro de otra, no abre.
func TestSealDNINoSeAbreConOtroAlertID(t *testing.T) {
	privada, publica := parDeClaves(t)
	propia, otra := uuid.New(), uuid.New()

	sellado, err := sellador(t, publica).SealDNI(propia, []byte(dniDePrueba))
	if err != nil {
		t.Fatalf("SealDNI falló: %v", err)
	}

	if dni, err := abrir(privada, auditseal.Info(otra), sellado.Sealed); err == nil {
		t.Fatalf("se abrió con el alert_id de otra alerta: %q", dni)
	}
	if _, err := abrir(privada, auditseal.Info(propia), sellado.Sealed); err != nil {
		t.Errorf("con el alert_id correcto debía abrir: %v", err)
	}
}

// El `info` también ata el criptograma a su campo: hecho pasar por la patente
// ("vv-audit:pat:"), no abre.
func TestSealDNINoSeAbreComoPatente(t *testing.T) {
	privada, publica := parDeClaves(t)
	alerta := uuid.New()

	sellado, err := sellador(t, publica).SealDNI(alerta, []byte(dniDePrueba))
	if err != nil {
		t.Fatalf("SealDNI falló: %v", err)
	}

	infoDePatente := []byte("vv-audit:pat:" + alerta.String())
	if dni, err := abrir(privada, infoDePatente, sellado.Sealed); err == nil {
		t.Fatalf("el DNI se abrió con el info de la patente: %q", dni)
	}
}

// Un sellado manipulado no abre.
func TestSealDNIManipuladoNoSeAbre(t *testing.T) {
	privada, publica := parDeClaves(t)
	alerta := uuid.New()
	sellado, err := sellador(t, publica).SealDNI(alerta, []byte(dniDePrueba))
	if err != nil {
		t.Fatalf("SealDNI falló: %v", err)
	}
	raw, _ := base64.StdEncoding.DecodeString(sellado.Sealed)
	raw[len(raw)-1] ^= 0xff

	if dni, err := abrir(privada, auditseal.Info(alerta), base64.StdEncoding.EncodeToString(raw)); err == nil {
		t.Fatalf("se abrió un criptograma manipulado: %q", dni)
	}
}

// Dos sellados del mismo DNI no se parecen: HPKE usa una clave efímera nueva por
// mensaje, así que el registro no permite saber que dos alertas son del mismo
// emisor.
func TestSealDNIEsNoDeterministico(t *testing.T) {
	_, publica := parDeClaves(t)
	s := sellador(t, publica)
	alerta := uuid.New()

	a, err := s.SealDNI(alerta, []byte(dniDePrueba))
	if err != nil {
		t.Fatalf("SealDNI falló: %v", err)
	}
	b, err := s.SealDNI(alerta, []byte(dniDePrueba))
	if err != nil {
		t.Fatalf("SealDNI falló: %v", err)
	}
	if a.Sealed == b.Sealed {
		t.Error("dos sellados del mismo DNI son idénticos")
	}
}

func TestSealDNIRechazaEntradasInvalidas(t *testing.T) {
	_, publica := parDeClaves(t)
	s := sellador(t, publica)

	if _, err := s.SealDNI(uuid.Nil, []byte(dniDePrueba)); err == nil {
		t.Error("se esperaba un error sin alerta")
	}
	if _, err := s.SealDNI(uuid.New(), nil); err == nil {
		t.Error("se esperaba un error sin DNI")
	}
	if _, err := s.SealDNI(uuid.New(), []byte{}); err == nil {
		t.Error("se esperaba un error con DNI vacío")
	}
}

// Una clave pública inutilizable hace fallar el arranque, no la primera alerta.
func TestNewRechazaUnaClavePublicaInutilizable(t *testing.T) {
	casos := map[string]string{
		"vacía":          "",
		"no es base64":   "###",
		"largo inválido": base64.StdEncoding.EncodeToString([]byte("corta")),
		"largo de más":   base64.StdEncoding.EncodeToString(make([]byte, 64)),
	}

	for nombre, clave := range casos {
		t.Run(nombre, func(t *testing.T) {
			if _, err := auditseal.New(clave, idDeClave); err == nil {
				t.Error("se esperaba un error")
			}
		})
	}
}

// El id de la clave tiene que caber en audit_key_id (varchar(32)) y en la línea
// `audit_key_id=base64` que lee audit-open.
func TestNewRechazaUnIDDeClaveInvalido(t *testing.T) {
	_, publica := parDeClaves(t)

	casos := map[string]string{
		"vacío":           "",
		"con espacios":    "2026 11",
		"con igual":       "2026=11",
		"con salto":       "2026-11\n",
		"demasiado largo": strings.Repeat("a", auditseal.MaxKeyIDLength+1),
	}
	for nombre, id := range casos {
		t.Run(nombre, func(t *testing.T) {
			if _, err := auditseal.New(publica, id); err == nil {
				t.Errorf("se esperaba un error para el id %q", id)
			}
		})
	}

	if _, err := auditseal.New(publica, strings.Repeat("a", auditseal.MaxKeyIDLength)); err != nil {
		t.Errorf("un id de exactamente %d caracteres debía aceptarse: %v", auditseal.MaxKeyIDLength, err)
	}
}
