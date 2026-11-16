// Package emailcode implementa las primitivas de los desafíos por email de
// US-13: el HMAC con que se guardan el subject y el código, y la generación del
// código de 6 dígitos y del token (grant) que lo reemplaza al confirmarlo.
//
// La clave EMAIL_CODE_HMAC_KEY es propia de este mecanismo: no se reutiliza
// ninguna de las demás claves del servicio. Un HMAC con clave es lo que impide
// que quien se lleve la tabla email_challenges recupere los códigos (solo hay
// 10^6) o los emails (subject) por fuerza bruta.
package emailcode

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// KeyLength es el largo mínimo de la clave: el tamaño de salida de SHA-256.
const KeyLength = 32

// grantBytes es el largo del token del grant, en bytes aleatorios.
const grantBytes = 32

// codeSpace es la cantidad de códigos posibles: 10^EmailCodeDigits.
var codeSpace = big.NewInt(1_000_000)

// Codec implementa domain.EmailCodeCodec. Es seguro para uso concurrente.
type Codec struct {
	key []byte
}

var _ domain.EmailCodeCodec = (*Codec)(nil)

// New construye el Codec a partir de la clave en binario, de al menos KeyLength
// bytes.
func New(key []byte) (*Codec, error) {
	if len(key) < KeyLength {
		return nil, fmt.Errorf("emailcode: la clave mide %d bytes, se requieren al menos %d", len(key), KeyLength)
	}

	// Copia defensiva: el llamador puede limpiar o reutilizar su buffer.
	own := make([]byte, len(key))
	copy(own, key)
	return &Codec{key: own}, nil
}

// NewFromBase64 es el constructor que usa la configuración: recibe la clave en
// base64 estándar, tal como viaja en EMAIL_CODE_HMAC_KEY.
func NewFromBase64(key string) (*Codec, error) {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, errors.New("emailcode: la clave no es base64 estándar válido")
	}
	defer clear(raw)

	return New(raw)
}

func (c *Codec) mac(parts ...string) string {
	m := hmac.New(sha256.New, c.key)
	for i, p := range parts {
		if i > 0 {
			m.Write([]byte(":")) // hash.Hash nunca devuelve error en Write.
		}
		m.Write([]byte(p))
	}
	return hex.EncodeToString(m.Sum(nil))
}

// SubjectHMAC deriva el subject de un desafío.
func (c *Codec) SubjectHMAC(purpose domain.EmailChallengePurpose, subject string) string {
	return c.mac(string(purpose), subject)
}

// CodeHMAC deriva el HMAC del código atado al desafío: el mismo código en otro
// desafío da otro HMAC.
func (c *Codec) CodeHMAC(challengeID uuid.UUID, code string) string {
	return c.mac(challengeID.String(), code)
}

// VerifyCode compara en tiempo constante el HMAC del código recibido contra el
// guardado.
func (c *Codec) VerifyCode(challengeID uuid.UUID, code, storedHMAC string) bool {
	return subtle.ConstantTimeCompare([]byte(c.CodeHMAC(challengeID, code)), []byte(storedHMAC)) == 1
}

// NewCode genera un código de 6 dígitos con crypto/rand. rand.Int usa muestreo
// por rechazo, así que no hay sesgo de módulo.
func (c *Codec) NewCode() (string, error) {
	n, err := rand.Int(rand.Reader, codeSpace)
	if err != nil {
		return "", fmt.Errorf("emailcode: no se pudo generar el código: %w", err)
	}
	return fmt.Sprintf("%0*d", domain.EmailCodeDigits, n.Int64()), nil
}

// NewGrant genera el token del grant y su SHA-256.
func (c *Codec) NewGrant() (token, hash string, err error) {
	raw := make([]byte, grantBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("emailcode: no se pudo generar el token: %w", err)
	}
	defer clear(raw)

	token = base64.RawURLEncoding.EncodeToString(raw)
	return token, c.GrantHash(token), nil
}

// GrantHash calcula el SHA-256 del token, en hexadecimal minúscula. No lleva
// clave: el token ya tiene 256 bits de entropía, igual que el Refresh Token.
func (c *Codec) GrantHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
