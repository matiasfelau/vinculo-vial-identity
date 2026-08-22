// Package hpke descifra el mensaje de transporte que la app envía cifrado
// end-to-end con la clave pública de este servicio (RFC 9180).
//
// Suite fija, modo BASE: KEM X25519_HKDF_SHA256 / KDF HKDF_SHA256 / AEAD
// AES256GCM. El contrato compartido de US-01 transporta el mensaje en sus dos
// piezas separadas —`ephemeral_public_key` y `ciphertext`, ambas en base64—, que
// es el encoding estándar de un mensaje HPKE y lo que produce cualquier librería
// que siga el RFC sin acordar un empaquetado propio.
//
// Este mecanismo es exclusivamente de transporte. El cifrado at-rest del DNI se
// hace aparte, con otra clave, en internal/crypto/symmetric.
package hpke

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	circl "github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

const (
	kemID  = circl.KEM_X25519_HKDF_SHA256
	kdfID  = circl.KDF_HKDF_SHA256
	aeadID = circl.AEAD_AES256GCM
)

// Decryptor implementa domain.HPKEDecryptor sobre circl/hpke.
//
// Es seguro para uso concurrente, pero eso no sale gratis: ver NewDecryptor, que
// fuerza la única inicialización perezosa que circl hace sobre la clave privada
// antes de que el Decryptor se comparta entre goroutines. El Receiver, que sí
// tiene estado de nonce, se crea por mensaje.
type Decryptor struct {
	suite      circl.Suite
	privateKey kem.PrivateKey
	// publicKey se deriva y serializa una sola vez en el constructor. Ver la
	// nota de NewDecryptor: precalcularla es parte del arreglo de concurrencia,
	// no una optimización.
	publicKey string
	// encLen es el tamaño de la clave pública efímera del emisor (`enc` en RFC
	// 9180). Para X25519 son 32 bytes; se toma del esquema en vez de
	// hardcodearlo para que cambiar de KEM no rompa la validación en silencio.
	encLen int
	// info es el contexto de la derivación de claves (`info` en RFC 9180). Debe
	// coincidir byte a byte con el que usa el cliente al cifrar; si difiere, el
	// AEAD no autentica y el descifrado falla.
	info []byte
}

// NewDecryptor construye el descifrador a partir de la clave privada X25519 en
// binario (32 bytes) y el info acordado con el cliente.
//
// Deriva la clave pública acá, en el arranque, y no solo porque PublicKey() la
// necesite: es lo que hace que Decrypt sea seguro en concurrencia.
//
// El motivo está en circl. Todo decapsulado llama internamente a
// skR.Public() —la clave pública del receptor entra en el kem_context de RFC
// 9180—, y xKEMPrivKey.Public() memoiza ese valor de forma perezosa y sin
// sincronizar: primero asigna el puntero y después llena los bytes. Con dos
// altas concurrentes sobre la misma clave, la segunda goroutine puede ver el
// puntero ya no nulo pero todavía en cero, derivar un kem_context equivocado y
// fallar con "el AEAD no autentica" sobre un mensaje perfectamente válido.
//
// Forzar la memoización acá, mientras el Decryptor todavía es local a esta
// goroutine, deja el valor completo antes de publicarlo: a partir de ahí
// Public() solo lee. La alternativa —un mutex en Decrypt— serializaría todas las
// altas para proteger una escritura que ocurre una sola vez.
func NewDecryptor(privateKey, info []byte) (*Decryptor, error) {
	scheme := kemID.Scheme()
	if got, want := len(privateKey), scheme.PrivateKeySize(); got != want {
		// No se loguea ni se devuelve el material de clave, solo su longitud.
		return nil, fmt.Errorf("hpke: la clave privada mide %d bytes, se esperaban %d", got, want)
	}

	sk, err := scheme.UnmarshalBinaryPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("hpke: clave privada inválida: %w", err)
	}

	// Copia defensiva: el llamador puede reutilizar o limpiar su slice.
	ctxInfo := make([]byte, len(info))
	copy(ctxInfo, info)

	// Acá se materializa la clave pública memoizada. Ver la nota de arriba: sin
	// esto, la primera tanda de altas concurrentes corre una carrera de datos.
	rawPub, err := sk.Public().MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("hpke: no se pudo derivar la clave pública: %w", err)
	}

	return &Decryptor{
		suite:      circl.NewSuite(kemID, kdfID, aeadID),
		privateKey: sk,
		publicKey:  base64.StdEncoding.EncodeToString(rawPub),
		encLen:     scheme.CiphertextSize(),
		info:       ctxInfo,
	}, nil
}

// NewDecryptorFromBase64 es el constructor que usa la configuración: recibe la
// clave privada en base64 estándar, tal como viaja en la variable de entorno
// IDENTITY_HPKE_PRIVATE_KEY.
func NewDecryptorFromBase64(privateKey string, info []byte) (*Decryptor, error) {
	raw, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return nil, errors.New("hpke: la clave privada no es base64 estándar válido")
	}
	defer clear(raw)

	return NewDecryptor(raw, info)
}

// Decrypt revierte el sellado HPKE del mensaje.
//
// Recibe las dos piezas por separado, tal como las transporta el contrato:
// ephemeralPublicKey es el encapsulado del KEM (`enc`) y ciphertext es el
// sellado del AEAD, tag incluido. El AAD va vacío porque todo el contexto de la
// derivación viaja en `info`.
//
// Los fallos se separan en dos categorías. Un mensaje que no tiene siquiera la
// forma correcta devuelve domain.ErrMalformedCryptogram (→ 400): es verificable
// sin tocar la clave privada. Un mensaje bien formado que no abre devuelve
// domain.ErrInvalidCryptogram (→ 500), siempre con el mismo error y sin detalle
// criptográfico, para no convertir el endpoint en un oráculo de padding/claves.
func (d *Decryptor) Decrypt(ephemeralPublicKey, ciphertext []byte) ([]byte, error) {
	// La longitud del encapsulado es fija para el KEM de la suite: cualquier otra
	// cosa es un cliente que no habla el contrato, y se rechaza antes de tocar
	// material criptográfico.
	if len(ephemeralPublicKey) != d.encLen {
		return nil, fmt.Errorf("%w: clave pública efímera de longitud inválida", domain.ErrMalformedCryptogram)
	}
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("%w: ciphertext vacío", domain.ErrMalformedCryptogram)
	}

	receiver, err := d.suite.NewReceiver(d.privateKey, d.info)
	if err != nil {
		return nil, fmt.Errorf("%w: receptor inválido", domain.ErrInvalidCryptogram)
	}

	opener, err := receiver.Setup(ephemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: encapsulado inválido", domain.ErrInvalidCryptogram)
	}

	plaintext, err := opener.Open(ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: el AEAD no autentica", domain.ErrInvalidCryptogram)
	}

	return plaintext, nil
}

// DecryptCombined revierte el sellado HPKE de un criptograma que llegó como
// un único blob —`enc` seguido del ciphertext— en lugar de las dos piezas
// separadas que reciben /signup y /signin.
//
// Es el formato de dni_enc en US-04: el contrato compartido lo transporta
// como un solo campo, así que la separación ocurre acá, usando encLen —fijo
// para la suite configurada— para partir el prefijo del encapsulado del
// resto, que es el ciphertext. Comparte con Decrypt las mismas dos
// categorías de error: un blob demasiado corto para contener siquiera un
// encapsulado es domain.ErrMalformedCryptogram, verificable sin tocar la
// clave privada.
func (d *Decryptor) DecryptCombined(cryptogram []byte) ([]byte, error) {
	if len(cryptogram) < d.encLen {
		return nil, fmt.Errorf("%w: criptograma demasiado corto para contener un encapsulado", domain.ErrMalformedCryptogram)
	}

	return d.Decrypt(cryptogram[:d.encLen], cryptogram[d.encLen:])
}

// PublicKey devuelve la clave pública correspondiente, en base64 estándar.
// Es la que se publica para que la app la empotre y cifre contra ella.
//
// Se calculó en el constructor, así que acá no queda nada que pueda fallar ni
// ninguna escritura sobre estado compartido.
func (d *Decryptor) PublicKey() string { return d.publicKey }

// GenerateKeyPair genera un par X25519 para la suite del servicio y lo devuelve
// en base64 estándar. Se usa en tests y en la herramienta cmd/genkeys.
func GenerateKeyPair() (privateKey, publicKey string, err error) {
	pub, priv, err := kemID.Scheme().GenerateKeyPair()
	if err != nil {
		return "", "", fmt.Errorf("hpke: no se pudo generar el par de claves: %w", err)
	}

	rawPriv, err := priv.MarshalBinary()
	if err != nil {
		return "", "", fmt.Errorf("hpke: no se pudo serializar la clave privada: %w", err)
	}
	defer clear(rawPriv)

	rawPub, err := pub.MarshalBinary()
	if err != nil {
		return "", "", fmt.Errorf("hpke: no se pudo serializar la clave pública: %w", err)
	}

	return base64.StdEncoding.EncodeToString(rawPriv), base64.StdEncoding.EncodeToString(rawPub), nil
}

// Seal cifra un plaintext contra la clave pública en base64 y devuelve las dos
// piezas que consume Decrypt, en el mismo orden en que las nombra el contrato.
//
// Existe para los tests y para generar mensajes de prueba durante el
// desarrollo; el servicio en producción solo descifra.
func Seal(publicKey string, info, plaintext []byte) (ephemeralPublicKey, ciphertext []byte, err error) {
	raw, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, nil, errors.New("hpke: la clave pública no es base64 estándar válido")
	}

	pk, err := kemID.Scheme().UnmarshalBinaryPublicKey(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("hpke: clave pública inválida: %w", err)
	}

	sender, err := circl.NewSuite(kemID, kdfID, aeadID).NewSender(pk, info)
	if err != nil {
		return nil, nil, fmt.Errorf("hpke: no se pudo construir el emisor: %w", err)
	}

	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("hpke: no se pudo encapsular: %w", err)
	}

	ct, err := sealer.Seal(plaintext, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("hpke: no se pudo sellar: %w", err)
	}

	return enc, ct, nil
}
