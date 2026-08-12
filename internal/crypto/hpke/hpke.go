// Package hpke descifra el criptograma de transporte que la app envía cifrado
// end-to-end con la clave pública de este servicio (RFC 9180).
//
// Suite fija: KEM X25519_HKDF_SHA256 / KDF HKDF_SHA256 / AEAD AES256GCM. Es la
// misma que usa el HybridEncrypt de Tink en Android, lo que hace que el
// criptograma sea interoperable sin capas de traducción.
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
// Es seguro para uso concurrente: la clave privada y la suite son de solo
// lectura, y el Receiver (que sí tiene estado de nonce) se crea por mensaje.
type Decryptor struct {
	suite      circl.Suite
	privateKey kem.PrivateKey
	// encLen es el tamaño de la clave encapsulada que Tink antepone al
	// ciphertext. Para X25519 son 32 bytes; se toma del esquema en vez de
	// hardcodearlo para que cambiar de KEM no rompa el parseo en silencio.
	encLen int
	// info es el contexto de la derivación de claves (`info` en RFC 9180). Debe
	// coincidir byte a byte con el `contextInfo` que pasa el cliente Tink; si
	// difiere, el AEAD no autentica y el descifrado falla.
	info []byte
}

// NewDecryptor construye el descifrador a partir de la clave privada X25519 en
// binario (32 bytes) y el info/contextInfo acordado con el cliente.
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

	return &Decryptor{
		suite:      circl.NewSuite(kemID, kdfID, aeadID),
		privateKey: sk,
		encLen:     scheme.CiphertextSize(),
		info:       ctxInfo,
	}, nil
}

// NewDecryptorFromBase64 es el constructor que usa la configuración: recibe la
// clave privada en base64 estándar, tal como viaja en la variable de entorno
// HPKE_PRIVATE_KEY.
func NewDecryptorFromBase64(privateKey string, info []byte) (*Decryptor, error) {
	raw, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return nil, errors.New("hpke: la clave privada no es base64 estándar válido")
	}
	defer clear(raw)

	return NewDecryptor(raw, info)
}

// Decrypt revierte el sellado HPKE del criptograma.
//
// Formato de entrada (el que produce Tink): enc || ciphertext, donde enc es la
// clave encapsulada del KEM y ciphertext incluye el tag del AEAD. El AAD va
// vacío porque Tink transporta todo el contexto en `info`.
//
// Cualquier fallo —clave equivocada, criptograma truncado o manipulado— se
// devuelve como domain.ErrInvalidCryptogram sin detalle criptográfico, para no
// convertir el endpoint en un oráculo de padding/claves.
func (d *Decryptor) Decrypt(cryptogram []byte) ([]byte, error) {
	if len(cryptogram) <= d.encLen {
		return nil, fmt.Errorf("%w: longitud insuficiente", domain.ErrInvalidCryptogram)
	}

	enc, ciphertext := cryptogram[:d.encLen], cryptogram[d.encLen:]

	receiver, err := d.suite.NewReceiver(d.privateKey, d.info)
	if err != nil {
		return nil, fmt.Errorf("%w: receptor inválido", domain.ErrInvalidCryptogram)
	}

	opener, err := receiver.Setup(enc)
	if err != nil {
		return nil, fmt.Errorf("%w: encapsulado inválido", domain.ErrInvalidCryptogram)
	}

	plaintext, err := opener.Open(ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: el AEAD no autentica", domain.ErrInvalidCryptogram)
	}

	return plaintext, nil
}

// PublicKey devuelve la clave pública correspondiente, en base64 estándar.
// Es la que se publica para que la app la empotre y cifre contra ella.
func (d *Decryptor) PublicKey() (string, error) {
	raw, err := d.privateKey.Public().MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("hpke: no se pudo serializar la clave pública: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

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

// Seal cifra un plaintext contra la clave pública en base64, produciendo el
// mismo wire format que consume Decrypt.
//
// Existe para los tests y para generar criptogramas de prueba durante el
// desarrollo; el servicio en producción solo descifra.
func Seal(publicKey string, info, plaintext []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, errors.New("hpke: la clave pública no es base64 estándar válido")
	}

	pk, err := kemID.Scheme().UnmarshalBinaryPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("hpke: clave pública inválida: %w", err)
	}

	sender, err := circl.NewSuite(kemID, kdfID, aeadID).NewSender(pk, info)
	if err != nil {
		return nil, fmt.Errorf("hpke: no se pudo construir el emisor: %w", err)
	}

	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("hpke: no se pudo encapsular: %w", err)
	}

	ciphertext, err := sealer.Seal(plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("hpke: no se pudo sellar: %w", err)
	}

	return append(enc, ciphertext...), nil
}
