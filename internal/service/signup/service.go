// Package signup implementa el caso de uso CU-01: el alta de un vecino.
//
// Orquesta la secuencia completa —descifrar, validar, derivar, persistir,
// publicar— dependiendo únicamente de los puertos de domain, de modo que se
// puede ejercitar entera con dobles, sin Postgres ni RabbitMQ.
package signup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/secure"
	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/validation"
)

// payload es el contenido descifrado del mensaje HPKE, tal como lo arma la app.
//
// No se rechazan campos desconocidos: la app puede sumar campos en una versión
// futura sin que este servicio deje de aceptar los registros. Un campo mal
// escrito llega vacío y lo rechaza la validación, que es el resultado correcto.
type payload struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	DNI      string `json:"dni"`
	// Tramite es el número de trámite de la cédula, exigido junto con DNI y
	// Sexo para verificar la identidad contra RENAPER. No se persiste: es una
	// condición para registrar, no un dato del usuario, y no tiene columna en
	// `users`.
	Tramite string `json:"tramite"`
	// Sexo es el sexo registral tal como figura en el documento. Tampoco se
	// persiste, por la misma razón que Tramite.
	Sexo string `json:"sexo"`
	// Selfie va en base64. Se usa una única vez, para el contraste biométrico
	// contra RENAPER, y nunca se persiste ni siquiera cifrada: no hay un
	// requisito de auditoría que la justifique, y guardar una selfie es guardar
	// el dato biométrico más sensible que puede pedirse.
	Selfie string `json:"selfie"`
}

// Deps son las dependencias del servicio. Todas son puertos de domain.
type Deps struct {
	Decryptor domain.HPKEDecryptor
	Indexer   domain.BlindIndexer
	Cipher    domain.SymmetricCipher
	Hasher    domain.PasswordHasher
	// Renaper verifica que dni+tramite+sexo+selfie corresponden a una identidad
	// real antes de dar de alta la cuenta.
	Renaper   domain.RenaperService
	Users     domain.UserRepository
	Publisher domain.EventPublisher
	Logger    *slog.Logger
	// Now permite fijar el reloj en los tests. Si es nil se usa time.Now.
	Now func() time.Time
}

// Service es el caso de uso de registro.
type Service struct {
	deps Deps
}

// New valida que estén todas las dependencias y construye el servicio.
//
// Se falla en el arranque y no en la primera petición: una dependencia faltante
// es un error de cableado, y descubrirlo con tráfico real es mucho peor.
func New(d Deps) (*Service, error) {
	switch {
	case d.Decryptor == nil:
		return nil, errors.New("signup: falta el descifrador HPKE")
	case d.Indexer == nil:
		return nil, errors.New("signup: falta el generador de Blind Index")
	case d.Cipher == nil:
		return nil, errors.New("signup: falta el cifrador at-rest")
	case d.Hasher == nil:
		return nil, errors.New("signup: falta el hasher de contraseñas")
	case d.Renaper == nil:
		return nil, errors.New("signup: falta el servicio de verificación de identidad")
	case d.Users == nil:
		return nil, errors.New("signup: falta el repositorio de usuarios")
	case d.Publisher == nil:
		return nil, errors.New("signup: falta el publisher de eventos")
	}

	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}

	return &Service{deps: d}, nil
}

// SignUp registra un vecino a partir del mensaje HPKE que envía la app, cuyas
// dos piezas —la clave pública efímera del emisor y el ciphertext— llegan
// separadas desde la capa HTTP.
//
// Devuelve el identificador del usuario creado y, ante fallos, uno de los
// centinelas de domain: ErrInvalidCryptogram, ErrInvalidInput,
// ErrIdentityNotVerified o ErrDuplicateUser.
//
// El DNI, el trámite, el sexo, la selfie y la contraseña en claro solo existen
// dentro de esta función y se limpian antes de volver, tanto si el alta falla
// como si termina en éxito.
func (s *Service) SignUp(ctx context.Context, ephemeralPublicKey, ciphertext []byte) (uuid.UUID, error) {
	plaintext, err := s.deps.Decryptor.Decrypt(ephemeralPublicKey, ciphertext)
	if err != nil {
		return uuid.Nil, err
	}
	defer secure.Wipe(plaintext)

	var p payload
	if err := json.Unmarshal(plaintext, &p); err != nil {
		// El contenido descifrado es dato del cliente, no un fallo interno:
		// un JSON malformado es un 400, igual que un email inválido.
		return uuid.Nil, fmt.Errorf("%w: el payload descifrado no es JSON válido", domain.ErrInvalidInput)
	}

	email := validation.NormalizeEmail(p.Email)
	dni := validation.NormalizeDNI([]byte(p.DNI))
	defer secure.Wipe(dni)

	password := []byte(p.Password)
	defer secure.Wipe(password)

	tramite := []byte(p.Tramite)
	defer secure.Wipe(tramite)

	sexo := validation.NormalizeSexo([]byte(p.Sexo))
	defer secure.Wipe(sexo)

	// ValidateSignUp decodifica la selfie y la devuelve incluso cuando otro
	// campo no valida, así que el defer que la limpia se registra antes de mirar
	// el error: selfie puede ser nil (Wipe lo tolera) o los bytes reales de una
	// petición que igual se va a rechazar, y en los dos casos hay que limpiarla.
	selfie, err := validation.ValidateSignUp(validation.SignUpInput{
		Email:        email,
		Password:     password,
		DNI:          dni,
		Tramite:      tramite,
		Sexo:         sexo,
		SelfieBase64: p.Selfie,
	})
	defer secure.Wipe(selfie)
	if err != nil {
		return uuid.Nil, err
	}

	// RENAPER es la verificación más cara del flujo con margen —una llamada de
	// red a una autoridad externa, no una derivación en memoria— y corre recién
	// acá, con el payload ya validado localmente: no tiene sentido gastar un
	// llamado a una API externa (posiblemente facturada por consulta) en un
	// payload que se iba a rechazar de todos modos.
	verified, err := s.deps.Renaper.ValidateIdentity(ctx, dni, tramite, sexo, selfie)
	if err != nil {
		return uuid.Nil, fmt.Errorf("signup: no se pudo consultar RENAPER: %w", err)
	}
	if !verified {
		return uuid.Nil, domain.ErrIdentityNotVerified
	}

	// A partir de acá el DNI en claro se convierte en sus dos derivados y no
	// vuelve a usarse: el Blind Index para la unicidad y el criptograma at-rest
	// para el respaldo.
	dniHashed := s.deps.Indexer.Index(dni)

	dniEncrypted, err := s.deps.Cipher.Encrypt(dni)
	if err != nil {
		return uuid.Nil, fmt.Errorf("signup: no se pudo cifrar el DNI: %w", err)
	}

	// El hash es la operación más cara del flujo en CPU/memoria y se hace antes
	// de consultar la base a propósito. Adelantar un chequeo de duplicados para
	// ahorrárselo abriría una carrera con las altas concurrentes y, además,
	// haría que el tiempo de respuesta delatara si el DNI ya estaba registrado.
	passwordHash, err := s.deps.Hasher.Hash(password)
	if err != nil {
		return uuid.Nil, fmt.Errorf("signup: no se pudo derivar la contraseña: %w", err)
	}

	user, err := domain.NewUser(email, passwordHash, dniHashed, dniEncrypted, s.deps.Now())
	if err != nil {
		return uuid.Nil, err
	}

	if err := s.deps.Users.Create(ctx, user); err != nil {
		return uuid.Nil, err
	}

	s.publish(ctx, user)

	s.deps.Logger.InfoContext(ctx, "usuario registrado", slog.String("user_id", user.ID.String()))

	return user.ID, nil
}

// publish emite user.created sin poner en riesgo el resultado del alta.
//
// El usuario ya está persistido y confirmado: devolver un 500 acá haría que la
// app reintentara y se encontrara con un 409, dejando al vecino sin poder
// registrarse por un problema del broker. Se registra el fallo y se sigue.
//
// La contrapartida es que un evento puede perderse si RabbitMQ está caído justo
// en ese instante. La solución correcta es un outbox transaccional —persistir el
// evento en la misma transacción que el usuario y despacharlo aparte—, que queda
// fuera del alcance de US-01 y debería abordarse antes de que algún consumidor
// dependa del evento para algo crítico.
func (s *Service) publish(ctx context.Context, user *domain.User) {
	if err := s.deps.Publisher.PublishUserCreated(ctx, domain.NewUserCreated(user)); err != nil {
		s.deps.Logger.ErrorContext(ctx, "no se pudo publicar user.created; el alta se mantiene",
			slog.String("user_id", user.ID.String()),
			slog.String("error", err.Error()),
		)
	}
}
