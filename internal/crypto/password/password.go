// Package password deriva y verifica hashes de contraseña con Argon2id.
//
// Argon2id es la variante recomendada por OWASP para almacenamiento de
// credenciales: combina la resistencia a ataques por canal lateral de Argon2i
// con la resistencia a GPU/ASIC de Argon2d.
//
// El hash se serializa en formato PHC, el mismo que usan las implementaciones de
// referencia:
//
//	$argon2id$v=19$m=65536,t=3,p=1$<salt-b64>$<hash-b64>
//
// Llevar los parámetros dentro del hash permite endurecerlos con el tiempo sin
// invalidar las credenciales ya almacenadas: Verify usa siempre los parámetros
// con los que se derivó ese hash concreto, y NeedsRehash señala cuáles quedaron
// por debajo de la política vigente.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// MaxPasswordLength acota el costo de una sola derivación. Sin este tope, un
// cliente podría enviar megabytes de contraseña y convertir el endpoint en un
// amplificador de CPU. La validación de negocio impone un límite más estricto;
// este es la última red de seguridad del primitivo.
const MaxPasswordLength = 1024

// Errores del paquete. La capa de servicio no los distingue —una credencial que
// no verifica es simplemente inválida—, pero separarlos permite alertar cuando
// la base tiene hashes corruptos, que es un síntoma operativo distinto.
var (
	// ErrInvalidHash indica que el hash almacenado no respeta el formato PHC.
	ErrInvalidHash = errors.New("password: hash con formato inválido")
	// ErrIncompatibleVersion indica un hash producido por otra versión de Argon2.
	ErrIncompatibleVersion = errors.New("password: versión de Argon2 incompatible")
	// ErrPasswordTooLong indica que la contraseña excede MaxPasswordLength.
	ErrPasswordTooLong = errors.New("password: la contraseña excede el largo máximo")
)

// Params son los parámetros de costo de Argon2id.
type Params struct {
	// MemoryKiB es el costo en memoria, en KiB. Es la defensa principal contra
	// el crackeo masivo en GPU.
	MemoryKiB uint32
	// Iterations es el costo en tiempo (número de pasadas).
	Iterations uint32
	// Parallelism es el número de carriles.
	Parallelism uint8
	// SaltLength es el largo del salt aleatorio, en bytes.
	SaltLength uint32
	// KeyLength es el largo del hash resultante, en bytes.
	KeyLength uint32
}

// DefaultParams devuelve la política vigente del servicio.
//
// 64 MiB / 3 pasadas / 1 carril está por encima del piso que recomienda OWASP y
// deja una derivación en el orden de las decenas de milisegundos en hardware de
// servidor. Ojo con la memoria: cada derivación concurrente reserva MemoryKiB,
// así que el pico de RAM del contenedor es MemoryKiB × altas simultáneas. Si se
// sube este valor hay que acotar la concurrencia del endpoint en la misma
// proporción.
func DefaultParams() Params {
	return Params{
		MemoryKiB:   64 * 1024,
		Iterations:  3,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// Validate verifica que los parámetros sean utilizables y no degraden la
// política por debajo del piso recomendado.
func (p Params) Validate() error {
	switch {
	case p.MemoryKiB < 19*1024:
		return fmt.Errorf("password: memoria %d KiB por debajo del mínimo recomendado (19456 KiB)", p.MemoryKiB)
	case p.Iterations < 1:
		return errors.New("password: se requiere al menos una iteración")
	case p.Parallelism < 1:
		return errors.New("password: se requiere al menos un carril")
	case p.SaltLength < 16:
		return fmt.Errorf("password: salt de %d bytes, se requieren al menos 16", p.SaltLength)
	case p.KeyLength < 32:
		return fmt.Errorf("password: hash de %d bytes, se requieren al menos 32", p.KeyLength)
	}
	return nil
}

// Hasher implementa domain.PasswordHasher. Es seguro para uso concurrente.
type Hasher struct {
	params Params
}

// New construye el hasher con los parámetros dados, rechazando políticas débiles.
func New(p Params) (*Hasher, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &Hasher{params: p}, nil
}

// Hash deriva la contraseña con un salt aleatorio nuevo y devuelve la cadena PHC.
func (h *Hasher) Hash(pwd []byte) (string, error) {
	if len(pwd) > MaxPasswordLength {
		return "", ErrPasswordTooLong
	}

	salt := make([]byte, h.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: no se pudo generar el salt: %w", err)
	}

	sum := argon2.IDKey(pwd, salt, h.params.Iterations, h.params.MemoryKiB, h.params.Parallelism, h.params.KeyLength)
	defer clear(sum)

	return encode(h.params, salt, sum), nil
}

// Verify compara la contraseña contra un hash PHC en tiempo constante.
//
// Devuelve (false, nil) cuando la contraseña simplemente no coincide, y un error
// solo cuando el hash almacenado no se puede interpretar.
func (h *Hasher) Verify(pwd []byte, encodedHash string) (bool, error) {
	if len(pwd) > MaxPasswordLength {
		return false, ErrPasswordTooLong
	}

	params, salt, expected, err := decode(encodedHash)
	if err != nil {
		return false, err
	}
	defer clear(expected)

	// Se deriva con los parámetros del hash almacenado, no con los vigentes:
	// de lo contrario endurecer la política dejaría fuera a todos los usuarios.
	got := argon2.IDKey(pwd, salt, params.Iterations, params.MemoryKiB, params.Parallelism, params.KeyLength)
	defer clear(got)

	return subtle.ConstantTimeCompare(got, expected) == 1, nil
}

// NeedsRehash informa si el hash almacenado quedó por debajo de la política
// vigente. Se aplica tras un login exitoso (US-02), único momento en que la
// contraseña en claro está disponible para volver a derivarla.
func (h *Hasher) NeedsRehash(encodedHash string) (bool, error) {
	params, _, _, err := decode(encodedHash)
	if err != nil {
		return false, err
	}

	return params.MemoryKiB < h.params.MemoryKiB ||
		params.Iterations < h.params.Iterations ||
		params.KeyLength < h.params.KeyLength, nil
}

func encode(p Params, salt, sum []byte) string {
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		p.MemoryKiB, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum),
	)
}

func decode(encodedHash string) (p Params, salt, sum []byte, err error) {
	// Formato: ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash]
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return p, nil, nil, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return p, nil, nil, fmt.Errorf("%w: v=%d", ErrIncompatibleVersion, version)
	}

	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.Iterations, &p.Parallelism); err != nil {
		return p, nil, nil, ErrInvalidHash
	}

	if salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	if sum, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	if len(salt) == 0 || len(sum) == 0 {
		return p, nil, nil, ErrInvalidHash
	}

	p.SaltLength = uint32(len(salt))
	p.KeyLength = uint32(len(sum))

	return p, salt, sum, nil
}
