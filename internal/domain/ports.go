package domain

import "context"

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
}

// EventPublisher publica eventos de dominio hacia el broker de la plataforma.
type EventPublisher interface {
	// PublishUserRegistered emite el evento user.registered.
	PublishUserRegistered(ctx context.Context, evt UserRegistered) error
}

// HPKEDecryptor descifra el criptograma de transporte que envía la app.
type HPKEDecryptor interface {
	// Decrypt devuelve el plaintext del criptograma HPKE. El llamador es
	// responsable de limpiar el buffer devuelto cuando termina de usarlo.
	Decrypt(cryptogram []byte) ([]byte, error)
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
