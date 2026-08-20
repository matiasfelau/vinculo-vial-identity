package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Los puertos se declaran acá, del lado del consumidor, y las implementaciones
// concretas viven en internal/repository, internal/delivery e internal/crypto.
// Así la capa de servicio depende solo de este paquete y es testeable con dobles.

// UserRepository persiste usuarios.
type UserRepository interface {
	// Create inserta el usuario. Debe devolver ErrDuplicateUser (envuelto o no)
	// cuando la base rechaza la inserción por violación de unicidad de email o
	// de dni_hashed; la detección del duplicado se delega a la base para evitar
	// la condición de carrera de un chequeo previo.
	Create(ctx context.Context, u *User) error

	// FindByDNIHashed busca un usuario por el Blind Index de su DNI. Es la única
	// vía de búsqueda del login (US-02): nunca se busca por DNI en claro, que no
	// se persiste. Debe devolver ErrUserNotFound (envuelto o no) cuando ningún
	// usuario tiene ese índice.
	FindByDNIHashed(ctx context.Context, dniHashed string) (*User, error)
}

// SessionRepository persiste sesiones: el registro de cada Refresh Token
// emitido, identificado por su SHA-256.
type SessionRepository interface {
	// Create inserta la sesión nueva.
	Create(ctx context.Context, s *Session) error
}

// TokenGenerator emite el par de tokens de una sesión nueva tras un login
// exitoso.
type TokenGenerator interface {
	// NewAccessToken firma un JWT RS256 de vida corta. El claim `sub` es el UUID
	// interno del usuario; nunca lleva DNI, email ni el Blind Index.
	NewAccessToken(userID uuid.UUID) (string, error)
	// NewRefreshToken genera un token opaco criptográficamente aleatorio, su
	// SHA-256 —la única forma en que se persiste— y su vencimiento absoluto.
	NewRefreshToken() (token, hash string, expiresAt time.Time, err error)
}

// EventPublisher publica eventos de dominio hacia el broker de la plataforma.
type EventPublisher interface {
	// PublishUserCreated emite el evento user.created.
	PublishUserCreated(ctx context.Context, evt UserCreated) error
}

// HPKEDecryptor descifra el criptograma de transporte que envía la app.
type HPKEDecryptor interface {
	// Decrypt devuelve el plaintext del mensaje HPKE, que el contrato transporta
	// en sus dos piezas separadas: la clave pública efímera del emisor (`enc` en
	// RFC 9180) y el ciphertext sellado por el AEAD. El llamador es responsable
	// de limpiar el buffer devuelto cuando termina de usarlo.
	Decrypt(ephemeralPublicKey, ciphertext []byte) ([]byte, error)
}

// SymmetricCipher cifra datos sensibles para persistirlos (cifrado at-rest).
// Es un mecanismo independiente de HPKE y usa su propia clave.
type SymmetricCipher interface {
	// Encrypt devuelve el criptograma en una representación textual apta para
	// almacenar en una columna de texto.
	Encrypt(plaintext []byte) (string, error)
	// Decrypt revierte Encrypt.
	Decrypt(ciphertext string) ([]byte, error)
}

// BlindIndexer deriva un índice ciego determinístico de un dato sensible, para
// poder buscarlo por igualdad sin almacenarlo en claro.
type BlindIndexer interface {
	Index(value []byte) string
}

// PasswordHasher deriva y verifica hashes de contraseña.
type PasswordHasher interface {
	// Hash devuelve el hash codificado, incluyendo parámetros y salt.
	Hash(password []byte) (string, error)
	// Verify compara en tiempo constante una contraseña contra un hash
	// codificado previamente por Hash.
	Verify(password []byte, encodedHash string) (bool, error)
}

// RenaperService verifica una identidad contra RENAPER (Registro Nacional de
// las Personas) antes del alta: confirma que el DNI, el número de trámite y el
// sexo registral corresponden a una persona real, y que la selfie coincide con
// la biometría de esa persona. Reemplaza al gate de atestación de dispositivo
// que usaba US-01 antes de esta versión del contrato.
type RenaperService interface {
	// ValidateIdentity devuelve (true, nil) cuando la identidad se confirma;
	// (false, nil) cuando RENAPER respondió pero no pudo confirmarla —dato
	// inválido o selfie que no coincide, sin distinguir cuál de las dos—; y
	// (_, error) cuando el propio servicio de RENAPER no pudo consultarse (caído,
	// timeout, credenciales rechazadas). Esta última categoría no implica nada
	// sobre la identidad: es un fallo de la dependencia externa, no un veredicto.
	//
	// El llamador es responsable de limpiar dni, tramite, sexo y selfie cuando
	// termina de usarlos.
	ValidateIdentity(ctx context.Context, dni, tramite, sexo, selfie []byte) (bool, error)
}
