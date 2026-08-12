// Package symmetric implementa el cifrado at-rest de datos sensibles con
// AES-256-GCM.
//
// Es un mecanismo independiente del transporte: HPKE protege el payload entre
// el dispositivo y este servicio, mientras que acá se vuelve a cifrar el DNI ya
// en claro para persistirlo en dni_encrypted. La clave (AES_KEY) es distinta de
// la del par HPKE a propósito: comprometer una no debe comprometer la otra, y
// cada una tiene su propio ciclo de rotación.
package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// KeyLength es el tamaño exigido de la clave: 32 bytes ⇒ AES-256.
const KeyLength = 32

// ErrInvalidCiphertext indica que el criptograma almacenado no pudo abrirse:
// está corrupto, fue manipulado, o se cifró con otra clave.
var ErrInvalidCiphertext = errors.New("symmetric: criptograma inválido")

// Cipher implementa domain.SymmetricCipher. Es seguro para uso concurrente:
// cipher.AEAD no tiene estado mutable y el nonce se genera por operación.
type Cipher struct {
	aead cipher.AEAD
}

// New construye el cifrador a partir de la clave en binario (32 bytes).
func New(key []byte) (*Cipher, error) {
	if len(key) != KeyLength {
		return nil, fmt.Errorf("symmetric: la clave mide %d bytes, se esperaban %d", len(key), KeyLength)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("symmetric: no se pudo inicializar AES: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("symmetric: no se pudo inicializar GCM: %w", err)
	}

	return &Cipher{aead: aead}, nil
}

// NewFromBase64 es el constructor que usa la configuración: recibe la clave en
// base64 estándar, tal como viaja en la variable de entorno AES_KEY.
func NewFromBase64(key string) (*Cipher, error) {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, errors.New("symmetric: la clave no es base64 estándar válido")
	}
	defer clear(raw)

	return New(raw)
}

// Encrypt sella el plaintext y devuelve base64(nonce || ciphertext || tag),
// listo para guardar en una columna de texto.
//
// El nonce es aleatorio de 96 bits y se genera por llamada. Reutilizarlo con la
// misma clave rompería GCM por completo, así que nunca se deriva ni se recicla.
func (c *Cipher) Encrypt(plaintext []byte) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("symmetric: no se pudo generar el nonce: %w", err)
	}

	// Seal antepone el nonce al criptograma reutilizando el mismo buffer.
	sealed := c.aead.Seal(nonce, nonce, plaintext, nil)

	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt revierte Encrypt. Devuelve ErrInvalidCiphertext ante cualquier
// entrada que no autentique, sin distinguir el motivo.
func (c *Cipher) Decrypt(ciphertext string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: no es base64 estándar válido", ErrInvalidCiphertext)
	}

	nonceSize := c.aead.NonceSize()
	if len(raw) < nonceSize+c.aead.Overhead() {
		return nil, fmt.Errorf("%w: longitud insuficiente", ErrInvalidCiphertext)
	}

	plaintext, err := c.aead.Open(nil, raw[:nonceSize], raw[nonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("%w: el AEAD no autentica", ErrInvalidCiphertext)
	}

	return plaintext, nil
}
