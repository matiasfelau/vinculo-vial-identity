// Package blindindex deriva un índice ciego determinístico sobre datos
// sensibles, para poder buscarlos por igualdad exacta sin almacenarlos en claro.
//
// En US-01 se aplica al DNI: dni_hashed = HMAC-SHA256(HMAC_SECRET, dni). Al ser
// determinístico habilita la restricción UNIQUE que detecta duplicados; al ser
// un HMAC con clave, un atacante que se lleve la base no puede revertirlo por
// fuerza bruta sobre el espacio de DNIs argentinos (~10^8, trivial de recorrer
// con un hash sin clave) mientras el secreto no se filtre con ella.
package blindindex

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// MinSecretLength es el mínimo de entropía exigido al secreto del HMAC. Se fija
// en el tamaño de bloque útil de SHA-256: un secreto más corto no aporta más
// seguridad que su propia longitud.
const MinSecretLength = 32

// Indexer implementa domain.BlindIndexer. Es seguro para uso concurrente.
type Indexer struct {
	secret []byte
}

// New construye el indexador a partir del secreto en binario.
func New(secret []byte) (*Indexer, error) {
	if len(secret) < MinSecretLength {
		return nil, fmt.Errorf("blindindex: el secreto mide %d bytes, se requieren al menos %d", len(secret), MinSecretLength)
	}

	// Copia defensiva: el llamador puede limpiar o reutilizar su buffer.
	own := make([]byte, len(secret))
	copy(own, secret)

	return &Indexer{secret: own}, nil
}

// NewFromBase64 es el constructor que usa la configuración: recibe el secreto
// en base64 estándar, tal como viaja en la variable de entorno HMAC_SECRET.
func NewFromBase64(secret string) (*Indexer, error) {
	raw, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, errors.New("blindindex: el secreto no es base64 estándar válido")
	}
	defer clear(raw)

	return New(raw)
}

// Index devuelve el índice ciego en hexadecimal minúscula (64 caracteres).
//
// La representación es estable por contrato: cambiarla invalidaría todos los
// dni_hashed ya persistidos y requeriría una migración con los DNI descifrados.
func (i *Indexer) Index(value []byte) string {
	mac := hmac.New(sha256.New, i.secret)
	mac.Write(value) // hash.Hash nunca devuelve error en Write.
	return hex.EncodeToString(mac.Sum(nil))
}
