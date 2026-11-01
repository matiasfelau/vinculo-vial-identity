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

	// FindByOwnerAndDNIHash busca el usuario cuyo id es ownerID Y cuyo Blind
	// Index de DNI es dniHashed. La usa /internal/verify-ownership (US-04)
	// para confirmar que el DNI del QR corresponde al dueño de la sesión
	// activa, sin decir nunca cuál de las dos condiciones falló: que el
	// predicado combine ambas con AND en una sola consulta es lo que impide
	// distinguir "ese owner_id no existe" de "existe, pero ese no es su
	// DNI" — las dos devuelven, indistinguiblemente, ErrUserNotFound
	// (envuelto o no). Nunca se usa para autenticar ni para nada que no sea
	// esa comparación puntual.
	FindByOwnerAndDNIHash(ctx context.Context, ownerID uuid.UUID, dniHashed string) (*User, error)
}

// ReputationRepository aplica a los usuarios los efectos de los eventos de
// reputación de US-08.
type ReputationRepository interface {
	// ApplyRejection registra el evento como procesado y, si penalty es
	// positiva, se la resta a la reputación del usuario, todo en una única
	// transacción: el efecto y su marca de deduplicación se confirman juntos o
	// no se confirma ninguno.
	//
	// Un evento ya procesado (misma clave EventID + Consumer) no cambia nada y
	// devuelve RejectionDuplicate. Que el usuario no exista no es un error:
	// devuelve RejectionUserNotFound. Un error de base devuelve el error
	// (envuelto en ErrDatabaseUnavailable si la base no respondió) y deja la
	// transacción deshecha, para que el reintento procese el evento entero.
	ApplyRejection(ctx context.Context, event ProcessedEvent, userID uuid.UUID, penalty int) (RejectionResult, error)

	// ApplyReport registra el evento como procesado y le suma un reporte al
	// usuario. Si con ese reporte el conteo llega a threshold y el usuario
	// estaba ACTIVE, lo pasa a UNDER_REVIEW y persiste statusChanged en el
	// outbox, todo en una única transacción: el cambio de estado y el evento
	// que lo anuncia se confirman juntos o no se confirma ninguno.
	//
	// statusChanged es el user.status.changed ya armado: solo se persiste si
	// hay transición, así que un usuario que ya estaba en revisión no vuelve a
	// publicar. Un evento ya procesado (misma clave EventID + Consumer) no
	// cambia nada y devuelve ReportDuplicate. Que el usuario no exista no es
	// un error: devuelve ReportUserNotFound.
	ApplyReport(ctx context.Context, event ProcessedEvent, userID uuid.UUID, threshold int, statusChanged OutboxEvent) (ReportOutcome, error)
}

// SessionRepository persiste sesiones: el registro de cada Refresh Token
// emitido, identificado por su SHA-256.
type SessionRepository interface {
	// Create inserta la sesión nueva.
	Create(ctx context.Context, s *Session) error

	// FindByHash busca una sesión por el SHA-256 de su Refresh Token. Es el
	// único criterio de búsqueda de /refresh (US-03): nunca se busca por el
	// token en claro, que no se persiste. Debe devolver ErrSessionNotFound
	// (envuelto o no) cuando ninguna sesión tiene ese hash.
	FindByHash(ctx context.Context, refreshTokenHash string) (*Session, error)

	// RevokeByID marca como revocada una única sesión. La usa la rotación para
	// revocar la sesión vieja al emitir el par nuevo.
	RevokeByID(ctx context.Context, id uuid.UUID) error

	// RevokeByHash marca como revocada la sesión cuyo hash de Refresh Token
	// coincide. Que ninguna fila coincida no es un error: es exactamente lo
	// que permite que /logout (US-03) responda 200 siempre, exista o no la
	// sesión, sin que el repositorio tenga que distinguir los casos.
	RevokeByHash(ctx context.Context, refreshTokenHash string) error

	// RevokeAllByUserID marca como revocadas todas las sesiones de un usuario,
	// vigentes o no, y persiste outboxEvent en la misma transacción (patrón
	// Transactional Outbox). Es la Defensa Activa de US-03: se dispara al
	// detectar el reúso de un Refresh Token ya revocado, y asume que toda la
	// familia de sesiones del usuario puede estar comprometida.
	//
	// outboxEvent nunca es nil en el único llamador actual (RefreshService):
	// a diferencia de un evento con destinatarios opcionales, la Defensa
	// Activa siempre tiene un usuario al que notificar. Se acepta como
	// puntero, igual que otros puertos de este archivo, para que un futuro
	// llamador sin nada que publicar pueda pasar nil sin forzar un tipo
	// vacío.
	RevokeAllByUserID(ctx context.Context, userID uuid.UUID, outboxEvent *OutboxEvent) error

	// RotateSession revoca la sesión vieja e inserta la sesión rotada como una
	// única operación atómica: si un paso falla, el otro se deshace.
	//
	// No es una optimización: un fallo parcial dejaría al usuario sin sesión
	// válida sosteniendo un Refresh Token que el siguiente intento leería como
	// reúso, disparando la Defensa Activa sobre una cuenta legítima. Por eso
	// se modela como una única llamada de la interfaz en lugar de exponer
	// RevokeByID + Create por separado para este flujo: la atomicidad queda
	// garantizada por la forma del puerto, no por una convención que el
	// llamador podría romper sin darse cuenta.
	RotateSession(ctx context.Context, oldSessionID uuid.UUID, newSession *Session) error
}

// OutboxRepository expone las operaciones que el worker de publicación en
// background (internal/service/outbox) necesita: traer eventos pendientes y
// registrar el resultado del intento de publicarlos. Las filas las escribe
// SessionRepository.RevokeAllByUserID, dentro de su propia transacción; este
// puerto solo las lee y actualiza su estado.
type OutboxRepository interface {
	// FetchPending devuelve hasta limit eventos todavía no enviados,
	// ordenados por antigüedad, para no dejar eventos varados detrás de un
	// alud de eventos nuevos.
	FetchPending(ctx context.Context, limit int) ([]OutboxEvent, error)

	// MarkSent registra que el evento se publicó y el broker lo confirmó
	// (publisher confirms). Antes de este punto, el evento sigue pendiente.
	MarkSent(ctx context.Context, id uuid.UUID) error

	// MarkFailed registra un intento fallido sin cambiar el estado pendiente:
	// el worker lo va a reintentar en el próximo ciclo, reutilizando el mismo
	// id como EventID (ver SessionsRevoked).
	MarkFailed(ctx context.Context, id uuid.UUID, lastErr string) error
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

	// Hash calcula el SHA-256 en hexadecimal minúscula de un Refresh Token
	// opaco: la misma cuenta que persiste NewRefreshToken. La usa /refresh
	// (US-03) para recomputar el hash del token que envía el cliente y
	// buscarlo en sessions.
	Hash(refreshToken string) string
}

// EventPublisher publica eventos de dominio hacia el broker de la plataforma.
type EventPublisher interface {
	// PublishSessionsRevoked emite el evento user.sessions.revoked.
	//
	// Se dispara únicamente desde la Defensa Activa de US-03 (revocación
	// masiva de todas las sesiones de un usuario tras detectar el reúso de un
	// Refresh Token), nunca desde un logout normal de un solo dispositivo:
	// emitirlo ahí apagaría las notificaciones push de todos los dispositivos
	// del usuario por haber cerrado sesión en uno solo.
	PublishSessionsRevoked(ctx context.Context, evt SessionsRevoked) error

	// PublishUserStatusChanged emite el evento user.status.changed, con
	// actor nulo: es un hecho del sistema, no de un usuario.
	PublishUserStatusChanged(ctx context.Context, evt UserStatusChanged) error
}

// HPKEDecryptor descifra el criptograma de transporte que envía la app.
type HPKEDecryptor interface {
	// Decrypt devuelve el plaintext del mensaje HPKE, que el contrato transporta
	// en sus dos piezas separadas: la clave pública efímera del emisor (`enc` en
	// RFC 9180) y el ciphertext sellado por el AEAD. El llamador es responsable
	// de limpiar el buffer devuelto cuando termina de usarlo.
	Decrypt(ephemeralPublicKey, ciphertext []byte) ([]byte, error)

	// DecryptCombined revierte el mismo sellado HPKE que Decrypt, pero a
	// partir de un único blob (`enc` seguido del ciphertext) en lugar de las
	// dos piezas separadas. Es el formato de dni_enc en US-04: a diferencia
	// de /signup y /signin, el contrato compartido transporta ese campo como
	// un solo valor —Vehicle lo reenvía sin abrir, tal cual lo produjo la
	// app—, así que la separación en sus dos piezas ocurre de este lado. El
	// llamador es responsable de limpiar el buffer devuelto cuando termina
	// de usarlo.
	DecryptCombined(cryptogram []byte) ([]byte, error)
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
	// (_, error) cuando el propio servicio de RENAPER no pudo consultarse. Esta
	// última categoría no implica nada sobre la identidad: es un fallo de la
	// dependencia externa, no un veredicto, y el error debe envolver uno de los
	// dos centinelas de domain que lo clasifican para la capa HTTP:
	// ErrUpstreamUnavailable si RENAPER no respondió (timeout, conexión
	// rechazada, circuito abierto), o ErrUpstreamInvalidResponse si respondió
	// con un error de su lado o un cuerpo fuera de contrato.
	//
	// El llamador es responsable de limpiar dni, tramite, sexo y selfie cuando
	// termina de usarlos.
	ValidateIdentity(ctx context.Context, dni, tramite, sexo, selfie []byte) (bool, error)
}
