// Package passwordreset implementa la recuperación de contraseña (US-13): un
// código por email, y después una revalidación de identidad (DNI escaneado,
// prueba de vida y RENAPER) para cambiar la contraseña.
//
// Anti-enumeración: el pedido responde lo mismo exista o no la cuenta, y solo
// escribe en el outbox si hay una cuenta con email verificado. Depende
// únicamente de los puertos de domain.
package passwordreset

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/secure"
	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/emailchallenge"
	"github.com/matiasfelau/vinculo-vial-identity/internal/validation"
)

// maxTokenLength acota el reset_token que se acepta antes de hashearlo: el
// legítimo mide 43 caracteres (32 bytes en base64url), así que un valor mucho más
// largo no puede ser de nadie.
const maxTokenLength = 128

type requestPayload struct {
	DNI string `json:"dni"`
}

type confirmPayload struct {
	DNI  string `json:"dni"`
	Code string `json:"code"`
}

// completePayload es el contenido descifrado de la revalidación. Tramite, Sexo y
// Selfie siguen las mismas reglas que en el alta y, como allá, no se persisten.
type completePayload struct {
	ResetToken  string `json:"reset_token"`
	DNI         string `json:"dni"`
	Tramite     string `json:"tramite"`
	Sexo        string `json:"sexo"`
	Selfie      string `json:"selfie"`
	NewPassword string `json:"new_password"`
}

// Deps son las dependencias del servicio. Todas son puertos de domain, salvo el
// motor de desafíos.
type Deps struct {
	Decryptor  domain.HPKEDecryptor
	Indexer    domain.BlindIndexer
	Hasher     domain.PasswordHasher
	Renaper    domain.RenaperService
	Users      domain.UserRepository
	Challenges domain.EmailChallengeRepository
	Codec      domain.EmailCodeCodec
	Engine     *emailchallenge.Engine
	// GrantTTL es la vida del reset_token (PASSWORD_RESET_GRANT_TTL_MINUTES).
	GrantTTL time.Duration
	// MaxIdentityAttempts es el tope de rechazos de identidad de un reset_token
	// (PASSWORD_RESET_MAX_IDENTITY_ATTEMPTS).
	MaxIdentityAttempts int
	Logger              *slog.Logger
	// Now permite fijar el reloj en los tests. Si es nil se usa time.Now.
	Now func() time.Time
}

// Service es el caso de uso de recuperación de contraseña.
type Service struct {
	deps Deps
}

// New valida que estén todas las dependencias y construye el servicio.
func New(d Deps) (*Service, error) {
	switch {
	case d.Decryptor == nil:
		return nil, errors.New("passwordreset: falta el descifrador HPKE")
	case d.Indexer == nil:
		return nil, errors.New("passwordreset: falta el generador de Blind Index")
	case d.Hasher == nil:
		return nil, errors.New("passwordreset: falta el hasher de contraseñas")
	case d.Renaper == nil:
		return nil, errors.New("passwordreset: falta el servicio de verificación de identidad")
	case d.Users == nil:
		return nil, errors.New("passwordreset: falta el repositorio de usuarios")
	case d.Challenges == nil:
		return nil, errors.New("passwordreset: falta el repositorio de desafíos")
	case d.Codec == nil:
		return nil, errors.New("passwordreset: falta el codec de códigos")
	case d.Engine == nil:
		return nil, errors.New("passwordreset: falta el motor de desafíos")
	case d.GrantTTL <= 0:
		return nil, errors.New("passwordreset: la vida del token debe ser positiva")
	case d.MaxIdentityAttempts < 1:
		return nil, errors.New("passwordreset: el tope de intentos de identidad debe ser al menos 1")
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Service{deps: d}, nil
}

// Request atiende el pedido de un código de recuperación.
//
// Devuelve nil siempre que el DNI tenga formato válido y la base responda. Solo
// si el DNI tiene cuenta con email verificado y el throttle lo permite, encola el
// email con el código; en cualquier otro caso no hace nada, y quien llama no
// puede notarlo.
func (s *Service) Request(ctx context.Context, ephemeralPublicKey, ciphertext []byte) error {
	plaintext, err := s.deps.Decryptor.Decrypt(ephemeralPublicKey, ciphertext)
	if err != nil {
		return err
	}
	defer secure.Wipe(plaintext)

	var p requestPayload
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return fmt.Errorf("%w: el payload descifrado no es JSON válido", domain.ErrInvalidInput)
	}

	dni := validation.NormalizeDNI([]byte(p.DNI))
	defer secure.Wipe(dni)
	if err := validation.ValidateDNI(dni); err != nil {
		return err
	}

	user, err := s.recoverableUser(ctx, dni)
	if err != nil {
		return err
	}
	if user == nil {
		s.deps.Logger.DebugContext(ctx, "pedido de recuperación procesado", slog.Bool("enviado", false))
		return nil
	}

	outcome, err := s.deps.Engine.Issue(ctx, emailchallenge.IssueParams{
		Purpose:  domain.EmailChallengePurposePasswordReset,
		Subject:  user.ID.String(),
		UserID:   &user.ID,
		To:       user.Email,
		Template: domain.EmailTemplatePasswordReset,
		WithCode: true,
	})
	if err != nil {
		return fmt.Errorf("passwordreset: no se pudo emitir el código: %w", err)
	}

	s.deps.Logger.DebugContext(ctx, "pedido de recuperación procesado",
		slog.Bool("enviado", outcome == emailchallenge.Sent))
	return nil
}

// recoverableUser devuelve la cuenta del DNI si se puede recuperar —solo con
// email verificado— o nil si no existe o no se puede. Un error de base se
// devuelve.
func (s *Service) recoverableUser(ctx context.Context, dni []byte) (*domain.User, error) {
	user, err := s.deps.Users.FindByDNIHashed(ctx, s.deps.Indexer.Index(dni))
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("passwordreset: no se pudo buscar la cuenta: %w", err)
	}
	if user.EmailVerifiedAt == nil {
		return nil, nil
	}
	return user, nil
}

// Confirm atiende la confirmación del código y devuelve el reset_token.
//
// Devuelve domain.ErrInvalidCode —sin distinguir el motivo— ante cualquier código
// que no sirva, incluida una cuenta inexistente o sin email verificado, y un DNI o
// un código con mala forma.
func (s *Service) Confirm(ctx context.Context, ephemeralPublicKey, ciphertext []byte) (token string, expiresIn time.Duration, err error) {
	plaintext, err := s.deps.Decryptor.Decrypt(ephemeralPublicKey, ciphertext)
	if err != nil {
		return "", 0, err
	}
	defer secure.Wipe(plaintext)

	var p confirmPayload
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return "", 0, domain.ErrInvalidCode
	}

	dni := validation.NormalizeDNI([]byte(p.DNI))
	defer secure.Wipe(dni)
	if validation.ValidateDNI(dni) != nil {
		return "", 0, domain.ErrInvalidCode
	}

	user, err := s.recoverableUser(ctx, dni)
	if err != nil {
		return "", 0, err
	}
	if user == nil {
		s.deps.Logger.WarnContext(ctx, "código de recuperación rechazado")
		return "", 0, domain.ErrInvalidCode
	}

	grant, err := s.deps.Engine.Confirm(ctx, domain.EmailChallengePurposePasswordReset, user.ID.String(), p.Code, s.deps.GrantTTL)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCode) {
			s.deps.Logger.WarnContext(ctx, "código de recuperación rechazado")
			return "", 0, domain.ErrInvalidCode
		}
		return "", 0, fmt.Errorf("passwordreset: no se pudo confirmar el código: %w", err)
	}
	return grant.Token, grant.ExpiresIn, nil
}

// Complete cambia la contraseña tras revalidar la identidad.
//
// El orden es el del contrato: el token, la contraseña y los campos, el DNI
// escaneado contra el de la cuenta, y recién entonces RENAPER. Cada rechazo de
// identidad —el DNI escaneado no es el de la cuenta, o RENAPER no lo confirma—
// descuenta un intento del token; una dependencia caída no descuenta nada.
//
// Devuelve ErrInvalidResetToken, ErrInvalidInput, ErrIdentityNotVerified, los
// centinelas de RENAPER (ErrUpstreamUnavailable, ErrUpstreamInvalidResponse), los
// del descifrado, o un error de base.
//
// Los datos en claro solo existen dentro de esta función y se limpian antes de
// volver.
func (s *Service) Complete(ctx context.Context, ephemeralPublicKey, ciphertext []byte) error {
	plaintext, err := s.deps.Decryptor.Decrypt(ephemeralPublicKey, ciphertext)
	if err != nil {
		return err
	}
	defer secure.Wipe(plaintext)

	var p completePayload
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return fmt.Errorf("%w: el payload descifrado no es JSON válido", domain.ErrInvalidInput)
	}

	now := s.deps.Now()

	grantHash, user, err := s.usableToken(ctx, p.ResetToken, now)
	if err != nil {
		return err
	}

	dni := validation.NormalizeDNI([]byte(p.DNI))
	defer secure.Wipe(dni)
	newPassword := []byte(p.NewPassword)
	defer secure.Wipe(newPassword)
	tramite := []byte(p.Tramite)
	defer secure.Wipe(tramite)
	sexo := validation.NormalizeSexo([]byte(p.Sexo))
	defer secure.Wipe(sexo)

	// ValidatePasswordReset devuelve la selfie aun si otro campo es inválido: el
	// defer se registra antes de mirar el error.
	selfie, err := validation.ValidatePasswordReset(validation.PasswordResetInput{
		Email:        user.Email,
		NewPassword:  newPassword,
		DNI:          dni,
		Tramite:      tramite,
		Sexo:         sexo,
		SelfieBase64: p.Selfie,
	})
	defer secure.Wipe(selfie)
	if err != nil {
		return err
	}

	// El DNI escaneado tiene que ser el de la cuenta. Se compara el Blind Index en
	// tiempo constante, y recién después de esto se gasta una llamada a RENAPER.
	scanned := s.deps.Indexer.Index(dni)
	if subtle.ConstantTimeCompare([]byte(scanned), []byte(user.DNIHashed)) != 1 {
		return s.rejectIdentity(ctx, grantHash, "el DNI escaneado no es el de la cuenta")
	}

	verified, err := s.deps.Renaper.ValidateIdentity(ctx, dni, tramite, sexo, selfie)
	if err != nil {
		// RENAPER caído: no es un veredicto sobre la identidad, no descuenta.
		return fmt.Errorf("passwordreset: no se pudo consultar RENAPER: %w", err)
	}
	if !verified {
		return s.rejectIdentity(ctx, grantHash, "RENAPER no confirmó la identidad")
	}

	// Como en el alta, el hash va antes de la transacción: es la operación cara y
	// no debe sostener una transacción abierta.
	passwordHash, err := s.deps.Hasher.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("passwordreset: no se pudo derivar la contraseña: %w", err)
	}

	revoked, err := domain.NewOutboxEvent(domain.EventTypeUserSessionsRevoked, map[string]string{
		"user_id": user.ID.String(),
		"reason":  string(domain.SessionsRevokedReasonPasswordReset),
	})
	if err != nil {
		return fmt.Errorf("passwordreset: no se pudo armar user.sessions.revoked: %w", err)
	}
	revoked.CreatedAt = now.UTC()

	changed, err := domain.NewEmailRequestedOutboxEvent(domain.EmailRequest{
		Template: domain.EmailTemplatePasswordChanged,
		To:       user.Email,
		Actor:    &user.ID,
	}, now)
	if err != nil {
		return fmt.Errorf("passwordreset: no se pudo armar email.requested: %w", err)
	}

	err = s.deps.Challenges.CompletePasswordReset(ctx, domain.PasswordResetCompletion{
		GrantHash:           grantHash,
		MaxIdentityAttempts: s.deps.MaxIdentityAttempts,
		UserID:              user.ID,
		PasswordHash:        passwordHash,
		Now:                 now,
		SessionsRevoked:     revoked,
		PasswordChanged:     changed,
	})
	if err != nil {
		if errors.Is(err, domain.ErrInvalidResetToken) {
			s.deps.Logger.WarnContext(ctx, "recuperación rechazada: el token dejó de servir antes de confirmarse")
			return domain.ErrInvalidResetToken
		}
		return fmt.Errorf("passwordreset: no se pudo completar la recuperación: %w", err)
	}

	s.deps.Logger.InfoContext(ctx, "contraseña restablecida", slog.String("user_id", user.ID.String()))
	return nil
}

// usableToken valida el reset_token y devuelve su hash y la cuenta a recuperar.
// Un token ausente, desconocido, de otro propósito, usado, vencido o sin intentos
// —o de una cuenta que ya no existe o no tiene el email verificado— da
// ErrInvalidResetToken, sin distinguir el motivo.
func (s *Service) usableToken(ctx context.Context, token string, now time.Time) (string, *domain.User, error) {
	if token == "" || len(token) > maxTokenLength {
		return "", nil, domain.ErrInvalidResetToken
	}

	hash := s.deps.Codec.GrantHash(token)
	challenge, err := s.deps.Challenges.FindByGrantHash(ctx, hash)
	if err != nil {
		if errors.Is(err, domain.ErrChallengeNotFound) {
			return "", nil, domain.ErrInvalidResetToken
		}
		return "", nil, fmt.Errorf("passwordreset: no se pudo buscar el token: %w", err)
	}
	if challenge.Purpose != domain.EmailChallengePurposePasswordReset ||
		challenge.UserID == nil ||
		!challenge.GrantUsable(now) ||
		challenge.GrantAttemptsExhausted(s.deps.MaxIdentityAttempts) {
		return "", nil, domain.ErrInvalidResetToken
	}

	user, err := s.deps.Users.FindByID(ctx, *challenge.UserID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return "", nil, domain.ErrInvalidResetToken
		}
		return "", nil, fmt.Errorf("passwordreset: no se pudo buscar la cuenta: %w", err)
	}
	if user.EmailVerifiedAt == nil {
		return "", nil, domain.ErrInvalidResetToken
	}
	return hash, user, nil
}

// rejectIdentity descuenta un intento del token y devuelve el rechazo de
// identidad. Si el intento no se pudo registrar, devuelve ese error en su lugar:
// callar el fallo dejaría pasar reintentos ilimitados.
func (s *Service) rejectIdentity(ctx context.Context, grantHash, motivo string) error {
	if err := s.deps.Challenges.AddGrantAttempt(ctx, grantHash); err != nil {
		return fmt.Errorf("passwordreset: no se pudo registrar el rechazo de identidad: %w", err)
	}
	s.deps.Logger.WarnContext(ctx, "recuperación rechazada: identidad no verificada", slog.String("motivo", motivo))
	return domain.ErrIdentityNotVerified
}
