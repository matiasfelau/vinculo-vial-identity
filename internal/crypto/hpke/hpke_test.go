package hpke_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/hpke"
	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// Contexto de derivación (`info` de RFC 9180). El servicio lo deja vacío por
// defecto, que es lo interoperable; acá se usa uno no vacío a propósito, para
// que los tests demuestren que el valor se honra y que un info distinto hace
// fallar la autenticación.
const testInfo = "vinculo-vial/identity/signup/v1"

// Vector fijo: par de claves y mensaje generados una única vez con la suite
// X25519_HKDF_SHA256 / HKDF_SHA256 / AES256GCM en modo BASE. Congelarlo detecta
// cualquier cambio de wire format que rompería la compatibilidad con los
// clientes ya publicados, algo que un test de round-trip contra sí mismo no
// vería.
//
// Las dos piezas van por separado, como las nombra el contrato compartido:
// ephemeral_public_key (32 bytes del encapsulado X25519) y ciphertext.
const (
	fixturePrivateKey         = "HlNNN8JdepXTytlFpPcOWLvAupVsUQl3AuD++aMuUWw="
	fixturePublicKey          = "v823019zDilxbuUzUBYenCqimwFa06cpIImE964mKQY="
	fixtureEphemeralPublicKey = "lrlPTVVDmYBwOhgf/O42kKl+DldidwbnKUBTiOIaSj0="
	fixtureCiphertext         = "nXC2ohe3AY9kuPEn0Q/ewU6xJS3psdRtb7C3Gao4qTFyPTJ0RTSCndAw/TOSXIeEYwzEP1Ycqyf4O6f3m2nGWGU0iHIbI3NCOQSlvwlW0oKBtSoJkrg3qmX7Wokh5LW3jf/f"
	fixturePlaintext          = `{"email":"vecino@vinculovial.ar","password":"Rosario-2026!seguro","dni":"30123456"}`
)

func decodeFixture(t *testing.T) (ephemeralPublicKey, ciphertext []byte) {
	t.Helper()

	enc, err := base64.StdEncoding.DecodeString(fixtureEphemeralPublicKey)
	if err != nil {
		t.Fatalf("la clave efímera del vector no es base64 válido: %v", err)
	}
	ct, err := base64.StdEncoding.DecodeString(fixtureCiphertext)
	if err != nil {
		t.Fatalf("el ciphertext del vector no es base64 válido: %v", err)
	}
	return enc, ct
}

func TestDecryptKnownVector(t *testing.T) {
	d, err := hpke.NewDecryptorFromBase64(fixturePrivateKey, []byte(testInfo))
	if err != nil {
		t.Fatalf("no se pudo construir el descifrador: %v", err)
	}

	enc, ct := decodeFixture(t)

	plaintext, err := d.Decrypt(enc, ct)
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

	if pub := d.PublicKey(); pub != fixturePublicKey {
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
		enc, ct, err := hpke.Seal(pub, []byte(testInfo), []byte(payload))
		if err != nil {
			t.Fatalf("no se pudo sellar: %v", err)
		}

		plaintext, err := d.Decrypt(enc, ct)
		if err != nil {
			t.Fatalf("no se pudo descifrar (largo %d): %v", len(payload), err)
		}
		if string(plaintext) != payload {
			t.Errorf("plaintext = %q, se esperaba %q", plaintext, payload)
		}
	}
}

// Un criptograma combinado llega como un único blob, a diferencia de las dos piezas
// separadas de /signup y /signin: DecryptCombined tiene que partirlo él mismo
// y descifrar exactamente lo mismo que Decrypt con esas dos piezas ya separadas.
func TestDecryptCombinedRoundTrip(t *testing.T) {
	priv, pub, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatalf("no se pudo generar el par: %v", err)
	}

	d, err := hpke.NewDecryptorFromBase64(priv, []byte(testInfo))
	if err != nil {
		t.Fatalf("no se pudo construir el descifrador: %v", err)
	}

	for _, payload := range []string{"30123456", "", strings.Repeat("x", 512)} {
		enc, ct, err := hpke.Seal(pub, []byte(testInfo), []byte(payload))
		if err != nil {
			t.Fatalf("no se pudo sellar: %v", err)
		}

		combinado := append(append([]byte(nil), enc...), ct...)

		plaintext, err := d.DecryptCombined(combinado)
		if err != nil {
			t.Fatalf("no se pudo descifrar el combinado (largo %d): %v", len(payload), err)
		}
		if string(plaintext) != payload {
			t.Errorf("plaintext = %q, se esperaba %q", plaintext, payload)
		}
	}
}

// Un blob que ni siquiera alcanza para contener el encapsulado es verificable
// sin tocar la clave privada: se rechaza igual que Decrypt rechaza una clave
// efímera de longitud incorrecta.
func TestDecryptCombinedRechazaBlobsDemasiadoCortos(t *testing.T) {
	priv, pub, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatalf("no se pudo generar el par: %v", err)
	}
	d, err := hpke.NewDecryptorFromBase64(priv, []byte(testInfo))
	if err != nil {
		t.Fatalf("no se pudo construir el descifrador: %v", err)
	}

	enc, _, err := hpke.Seal(pub, []byte(testInfo), []byte("30123456"))
	if err != nil {
		t.Fatalf("no se pudo sellar: %v", err)
	}

	cases := map[string][]byte{
		"vacío":                            nil,
		"un byte":                          {0x00},
		"exactamente encLen menos un byte": enc[:len(enc)-1],
	}

	for name, blob := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := d.DecryptCombined(blob)
			if !errors.Is(err, domain.ErrMalformedCryptogram) {
				t.Errorf("error = %v, se esperaba ErrMalformedCryptogram", err)
			}
		})
	}
}

// Un blob que sí alcanza para el encapsulado pero cuyo ciphertext quedó vacío
// (exactamente encLen bytes) no es un caso especial de DecryptCombined: el
// mismo chequeo de Decrypt sobre un ciphertext vacío ya lo cubre.
func TestDecryptCombinedConSoloElEncapsuladoDelegaEnDecrypt(t *testing.T) {
	priv, pub, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatalf("no se pudo generar el par: %v", err)
	}
	d, err := hpke.NewDecryptorFromBase64(priv, []byte(testInfo))
	if err != nil {
		t.Fatalf("no se pudo construir el descifrador: %v", err)
	}

	enc, _, err := hpke.Seal(pub, []byte(testInfo), []byte("30123456"))
	if err != nil {
		t.Fatalf("no se pudo sellar: %v", err)
	}

	_, err = d.DecryptCombined(enc)
	if !errors.Is(err, domain.ErrMalformedCryptogram) {
		t.Errorf("error = %v, se esperaba ErrMalformedCryptogram", err)
	}
}

// DecryptCombined no introduce una tercera categoría de error: un blob bien
// formado que no abre (clave ajena) sigue siendo ErrInvalidCryptogram, igual
// que Decrypt con las piezas ya separadas.
func TestDecryptCombinedPropagaLosMismosFallosQueDecrypt(t *testing.T) {
	_, pub, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatalf("no se pudo generar el par: %v", err)
	}
	otroPriv, _, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatalf("no se pudo generar el segundo par: %v", err)
	}

	enc, ct, err := hpke.Seal(pub, []byte(testInfo), []byte("30123456"))
	if err != nil {
		t.Fatalf("no se pudo sellar: %v", err)
	}
	combinado := append(append([]byte(nil), enc...), ct...)

	d, err := hpke.NewDecryptorFromBase64(otroPriv, []byte(testInfo))
	if err != nil {
		t.Fatalf("no se pudo construir el descifrador: %v", err)
	}

	_, err = d.DecryptCombined(combinado)
	if !errors.Is(err, domain.ErrInvalidCryptogram) {
		t.Errorf("error = %v, se esperaba ErrInvalidCryptogram", err)
	}
}

// Los fallos se separan en dos categorías con destinos HTTP distintos: lo que
// está mal formado se puede verificar sin tocar la clave privada (400), y lo que
// está bien formado pero no abre es indistinguible entre clave equivocada y
// manipulación, así que sale siempre igual (500). En ningún caso hay plaintext.
func TestDecryptMensajesInvalidos(t *testing.T) {
	priv, pub, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatalf("no se pudo generar el par: %v", err)
	}
	otroPriv, _, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatalf("no se pudo generar el segundo par: %v", err)
	}

	enc, ct, err := hpke.Seal(pub, []byte(testInfo), []byte(`{"dni":"30123456"}`))
	if err != nil {
		t.Fatalf("no se pudo sellar: %v", err)
	}

	tamperedCT := append([]byte(nil), ct...)
	tamperedCT[len(tamperedCT)-1] ^= 0xFF

	tamperedEnc := append([]byte(nil), enc...)
	tamperedEnc[0] ^= 0xFF

	// Concatenar las dos piezas era el wire format anterior. Si un cliente viejo
	// lo mandara así, el encapsulado mide de más y se rechaza: la
	// incompatibilidad tiene que ser explícita y no un descifrado silenciosamente
	// erróneo.
	concatenado := append(append([]byte(nil), enc...), ct...)

	cases := []struct {
		name       string
		privateKey string
		info       string
		enc        []byte
		ct         []byte
		want       error
	}{
		{"clave privada de otro par", otroPriv, testInfo, enc, ct, domain.ErrInvalidCryptogram},
		{"info distinto al del emisor", priv, "otro-contexto", enc, ct, domain.ErrInvalidCryptogram},
		{"clave efímera manipulada", priv, testInfo, tamperedEnc, ct, domain.ErrInvalidCryptogram},
		{"ciphertext truncado", priv, testInfo, enc, ct[:len(ct)-1], domain.ErrInvalidCryptogram},
		{"tag del AEAD manipulado", priv, testInfo, enc, tamperedCT, domain.ErrInvalidCryptogram},

		{"clave efímera ausente", priv, testInfo, nil, ct, domain.ErrMalformedCryptogram},
		{"clave efímera corta", priv, testInfo, enc[:len(enc)-1], ct, domain.ErrMalformedCryptogram},
		{"clave efímera larga", priv, testInfo, append(append([]byte(nil), enc...), 0x00), ct, domain.ErrMalformedCryptogram},
		{"ciphertext ausente", priv, testInfo, enc, nil, domain.ErrMalformedCryptogram},
		{"las dos piezas intercambiadas", priv, testInfo, ct, enc, domain.ErrMalformedCryptogram},
		{"formato concatenado anterior", priv, testInfo, concatenado, ct, domain.ErrMalformedCryptogram},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := hpke.NewDecryptorFromBase64(tc.privateKey, []byte(tc.info))
			if err != nil {
				t.Fatalf("no se pudo construir el descifrador: %v", err)
			}

			plaintext, err := d.Decrypt(tc.enc, tc.ct)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, se esperaba %v", err, tc.want)
			}
			if plaintext != nil {
				t.Error("no debe devolverse plaintext ante un fallo de descifrado")
			}
		})
	}
}

// Un mensaje bien formado que no abre no puede decir por qué: distinguir "esta
// no es la clave" de "el AEAD no autentica" convertiría al endpoint en un
// oráculo sobre el estado de las claves del servicio.
func TestFallosCriptograficosNoSeDistinguenEntreSi(t *testing.T) {
	priv, pub, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatalf("no se pudo generar el par: %v", err)
	}
	otroPriv, _, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatalf("no se pudo generar el segundo par: %v", err)
	}

	enc, ct, err := hpke.Seal(pub, []byte(testInfo), []byte(`{"dni":"30123456"}`))
	if err != nil {
		t.Fatalf("no se pudo sellar: %v", err)
	}
	tampered := append([]byte(nil), ct...)
	tampered[len(tampered)-1] ^= 0xFF

	conOtraClave, err := hpke.NewDecryptorFromBase64(otroPriv, []byte(testInfo))
	if err != nil {
		t.Fatalf("no se pudo construir el descifrador: %v", err)
	}
	conLaClave, err := hpke.NewDecryptorFromBase64(priv, []byte(testInfo))
	if err != nil {
		t.Fatalf("no se pudo construir el descifrador: %v", err)
	}

	_, errClaveAjena := conOtraClave.Decrypt(enc, ct)
	_, errManipulado := conLaClave.Decrypt(enc, tampered)

	if errClaveAjena.Error() != errManipulado.Error() {
		t.Errorf("los dos fallos son distinguibles:\n  clave ajena = %v\n  manipulado  = %v",
			errClaveAjena, errManipulado)
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

// Regresión de una carrera real: circl memoiza la clave pública dentro de la
// clave privada de forma perezosa y sin sincronizar, y todo decapsulado la
// necesita para armar el kem_context. Sin la derivación anticipada del
// constructor, dos altas concurrentes sobre un Decryptor recién creado hacen que
// una lea la memoización a medio escribir y falle el AEAD con un mensaje válido.
//
// El test sella todo por adelantado y suelta las goroutines contra una barrera,
// para que el descifrado concurrente sea lo único que se ejercita y la ventana
// de la carrera —que es la primera llamada, y solo esa— quede lo más expuesta
// posible.
func TestDecryptEsConcurrente(t *testing.T) {
	priv, pub, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatalf("no se pudo generar el par: %v", err)
	}
	d, err := hpke.NewDecryptorFromBase64(priv, []byte(testInfo))
	if err != nil {
		t.Fatalf("no se pudo construir el descifrador: %v", err)
	}

	const goroutines = 64

	type mensaje struct{ enc, ct []byte }
	mensajes := make([]mensaje, goroutines)
	for i := range goroutines {
		enc, ct, err := hpke.Seal(pub, []byte(testInfo), []byte{byte(i)})
		if err != nil {
			t.Fatalf("no se pudo sellar: %v", err)
		}
		mensajes[i] = mensaje{enc: enc, ct: ct}
	}

	largada := make(chan struct{})
	errs := make(chan error, goroutines)
	for i := range goroutines {
		go func(i int) {
			<-largada

			plaintext, err := d.Decrypt(mensajes[i].enc, mensajes[i].ct)
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
	close(largada)

	for range goroutines {
		if err := <-errs; err != nil {
			t.Fatalf("fallo en ejecución concurrente: %v", err)
		}
	}
}
