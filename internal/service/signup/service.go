// Package signup implementa el caso de uso CU-01: el alta de un vecino.
//
// Orquesta la secuencia completa —descifrar, validar, derivar, persistir,
// publicar— dependiendo únicamente de los puertos de domain, de modo que se
// puede ejercitar entera con dobles, sin Postgres ni RabbitMQ.
package signup

import (
	"context"
	"crypto/subtle"
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
	// EmailVerificationToken es el token que emite la confirmación del código
	// enviado al email (US-13). El alta lo consume; si no se exige, puede faltar.
	EmailVerificationToken string `json:"email_verification_token"`
	// TermsVersion es la versión de los Términos y Condiciones que el usuario
	// aceptó en el formulario (US-19). Si se exige, tiene que ser la vigente.
	TermsVersion string `json:"terms_version"`
}

// maxVerificationTokenLength acota el token que se acepta antes de hashearlo: el
// legítimo mide 43 caracteres (32 bytes en base64url).
const maxVerificationTokenLength = 128

// Deps son las dependencias del servicio. Todas son puertos de domain.
type Deps struct {
	Decryptor domain.HPKEDecryptor
	Indexer   domain.BlindIndexer
	Cipher    domain.SymmetricCipher
	Hasher    domain.PasswordHasher
	// Renaper verifica que dni+tramite+sexo+selfie corresponden a una identidad
	// real antes de dar de alta la cuenta.
	Renaper domain.RenaperService
	Users   domain.UserRepository
	// Challenges y Codec validan el token de verificación de email (US-13) antes
	// de consultar RENAPER.
	Challenges domain.EmailChallengeRepository
	Codec      domain.EmailCodeCodec
	// RequireEmailVerification (SIGNUP_REQUIRE_EMAIL_VERIFICATION) exige el token
	// de verificación. En false, el alta no lo exige —solo existe para no romper
	// el alta mientras el Frontend no lo envía—, pero si llega un token se
	// valida y se consume igual.
	RequireEmailVerification bool
	// TermsCurrentVersion (TERMS_CURRENT_VERSION) es la versión vigente de los
	// Términos y Condiciones (US-19). Es obligatoria.
	TermsCurrentVersion string
	// RequireTerms (SIGNUP_REQUIRE_TERMS) exige que el alta traiga la versión
	// vigente. En false, el campo puede faltar —solo existe para no romper el alta
	// mientras el Frontend no lo envía—, pero si llega se valida igual.
	RequireTerms bool
	Logger       *slog.Logger
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
	case d.Challenges == nil:
		return nil, errors.New("signup: falta el repositorio de desafíos de email")
	case d.Codec == nil:
		return nil, errors.New("signup: falta el codec de códigos de email")
	case d.TermsCurrentVersion == "":
		return nil, errors.New("signup: falta la versión vigente de los términos")
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
// ErrTermsNotAccepted, ErrEmailNotVerified, ErrIdentityNotVerified o
// ErrDuplicateUser.
//
// La versión de los términos (US-19) se comprueba antes de todo lo que cuesta o
// consume algo —el token de email y RENAPER—, y se guarda, con la fecha, en la
// misma transacción que crea el usuario.
//
// El token de verificación de email (US-13) se valida antes de consultar RENAPER
// y se consume en la misma transacción que crea el usuario: un alta que falla no
// lo gasta, y un token no se usa en dos altas.
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

	// Los términos se miran primero entre los chequeos que no son de formato: es
	// una comparación en memoria, y rechazarlos no gasta ni el token de email ni
	// una consulta a RENAPER.
	acceptTerms, err := s.termsAcceptance(p.TermsVersion)
	if err != nil {
		return uuid.Nil, err
	}

	// El token de verificación se mira antes de RENAPER, por el mismo motivo que
	// la validación local: no se gasta una consulta externa en un alta que no
	// puede terminar.
	grant, err := s.verificationGrant(ctx, email, p.EmailVerificationToken)
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
	if grant != nil {
		verifiedAt := user.CreatedAt
		user.EmailVerifiedAt = &verifiedAt
	}
	if acceptTerms {
		user.AcceptTerms(p.TermsVersion, user.CreatedAt)
	}

	// Si el mismo DNI fue dado de baja con una sanción vigente (US-11), el
	// repositorio hace que la cuenta la herede y, si queda en revisión, persiste
	// este evento en la misma transacción. El evento se arma acá porque no
	// depende de lo que lea la base: solo del usuario nuevo.
	inheritedStatus, err := domain.NewUserStatusChangedOutboxEvent(
		user.ID, domain.AccountStatusUnderReview, domain.UserStatusReasonInheritedOnSignup)
	if err != nil {
		return uuid.Nil, fmt.Errorf("signup: no se pudo armar user.status.changed: %w", err)
	}
	inheritedStatus.CreatedAt = s.deps.Now().UTC()

	if err := s.deps.Users.Create(ctx, user, inheritedStatus, grant); err != nil {
		return uuid.Nil, err
	}

	s.deps.Logger.InfoContext(ctx, "usuario registrado",
		slog.String("user_id", user.ID.String()),
		slog.String("account_status", string(user.AccountStatus)),
	)

	return user.ID, nil
}

// termsAcceptance decide si el alta registra la aceptación de los términos.
//
// Devuelve true si el payload trae la versión vigente. Un campo vacío es
// ErrTermsNotAccepted si se exige, y "sin consentimiento registrado" si no. Una
// versión que no coincide con la vigente es siempre ErrTermsNotAccepted: con el
// flag apagado el campo es opcional, pero no se acepta un valor equivocado.
func (s *Service) termsAcceptance(version string) (bool, error) {
	if version == "" {
		if s.deps.RequireTerms {
			return false, domain.ErrTermsNotAccepted
		}
		return false, nil
	}
	if version != s.deps.TermsCurrentVersion {
		return false, domain.ErrTermsNotAccepted
	}
	return true, nil
}

// verificationGrant valida el token de verificación de email del alta y devuelve
// el grant que el repositorio va a consumir, o nil si no hay token y no se exige.
//
// Un token ausente (si se exige), desconocido, de otro propósito, de otro email,
// usado o vencido da ErrEmailNotVerified, sin distinguir el motivo. Esto es solo
// una validación temprana: el repositorio vuelve a comprobarlo al consumirlo, que
// es lo que cierra la carrera entre dos altas con el mismo token.
func (s *Service) verificationGrant(ctx context.Context, email, token string) (*domain.GrantConsumption, error) {
	if token == "" {
		if s.deps.RequireEmailVerification {
			return nil, domain.ErrEmailNotVerified
		}
		return nil, nil
	}
	if len(token) > maxVerificationTokenLength {
		return nil, domain.ErrEmailNotVerified
	}

	purpose := domain.EmailChallengePurposeEmailVerification
	hash := s.deps.Codec.GrantHash(token)
	subject := s.deps.Codec.SubjectHMAC(purpose, email)
	now := s.deps.Now()

	challenge, err := s.deps.Challenges.FindByGrantHash(ctx, hash)
	if err != nil {
		if errors.Is(err, domain.ErrChallengeNotFound) {
			return nil, domain.ErrEmailNotVerified
		}
		return nil, fmt.Errorf("signup: no se pudo buscar el token de verificación: %w", err)
	}
	if challenge.Purpose != purpose ||
		subtle.ConstantTimeCompare([]byte(challenge.SubjectHMAC), []byte(subject)) != 1 ||
		!challenge.GrantUsable(now) {
		return nil, domain.ErrEmailNotVerified
	}

	return &domain.GrantConsumption{Purpose: purpose, SubjectHMAC: subject, GrantHash: hash, Now: now}, nil
}
