// Package emailverification implementa la verificación del email del alta
// (US-13): el pedido del código y su confirmación, que emite el token que el
// alta consume.
//
// Anti-enumeración: el pedido responde lo mismo exista o no una cuenta con ese
// email, y escribe en el outbox lo que corresponde sin que nada de afuera lo
// distinga. Depende únicamente de los puertos de domain.
package emailverification

import (
	"context"
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

// requestPayload es el contenido descifrado del pedido de código.
type requestPayload struct {
	Email string `json:"email"`
}

// confirmPayload es el contenido descifrado de la confirmación.
type confirmPayload struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

// Deps son las dependencias del servicio. Todas son puertos de domain, salvo el
// motor de desafíos.
type Deps struct {
	Decryptor domain.HPKEDecryptor
	Users     domain.UserRepository
	Engine    *emailchallenge.Engine
	// GrantTTL es la vida del token de verificación
	// (EMAIL_VERIFICATION_GRANT_TTL_MINUTES).
	GrantTTL time.Duration
	Logger   *slog.Logger
}

// Service es el caso de uso de verificación de email.
type Service struct {
	deps Deps
}

// New valida que estén todas las dependencias y construye el servicio.
func New(d Deps) (*Service, error) {
	switch {
	case d.Decryptor == nil:
		return nil, errors.New("emailverification: falta el descifrador HPKE")
	case d.Users == nil:
		return nil, errors.New("emailverification: falta el repositorio de usuarios")
	case d.Engine == nil:
		return nil, errors.New("emailverification: falta el motor de desafíos")
	case d.GrantTTL <= 0:
		return nil, errors.New("emailverification: la vida del token debe ser positiva")
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	return &Service{deps: d}, nil
}

// Request atiende el pedido de un código de verificación.
//
// Devuelve nil siempre que el email tenga formato válido y la base responda,
// exista o no una cuenta, y se haya enviado o no por el throttle. Con el email
// libre encola EMAIL_VERIFICATION con el código; con una cuenta existente encola
// ACCOUNT_EXISTS, sin código. Ante fallos devuelve ErrInvalidInput, los
// centinelas del descifrado o un error de base.
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

	email := validation.NormalizeEmail(p.Email)
	if err := validation.ValidateEmail(email); err != nil {
		return err
	}

	exists, err := s.deps.Users.ExistsByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("emailverification: no se pudo consultar el email: %w", err)
	}

	params := emailchallenge.IssueParams{
		Purpose:  domain.EmailChallengePurposeEmailVerification,
		Subject:  email,
		To:       email,
		Template: domain.EmailTemplateEmailVerification,
		WithCode: true,
	}
	if exists {
		params.Template = domain.EmailTemplateAccountExists
		params.WithCode = false
	}

	outcome, err := s.deps.Engine.Issue(ctx, params)
	if err != nil {
		return fmt.Errorf("emailverification: no se pudo emitir el código: %w", err)
	}

	// Debug y sin identificar al email: ni el nivel ni el contenido dejan al log
	// decir si existe una cuenta.
	s.deps.Logger.DebugContext(ctx, "pedido de verificación de email procesado",
		slog.Bool("enviado", outcome == emailchallenge.Sent))
	return nil
}

// Confirm atiende la confirmación del código y devuelve el token de
// verificación, que el alta consume.
//
// Devuelve domain.ErrInvalidCode —sin distinguir el motivo— ante cualquier código
// que no sirva, incluido un email o un código con mala forma.
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

	email := validation.NormalizeEmail(p.Email)
	if validation.ValidateEmail(email) != nil {
		return "", 0, domain.ErrInvalidCode
	}

	grant, err := s.deps.Engine.Confirm(ctx, domain.EmailChallengePurposeEmailVerification, email, p.Code, s.deps.GrantTTL)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCode) {
			s.deps.Logger.WarnContext(ctx, "código de verificación de email rechazado")
			return "", 0, domain.ErrInvalidCode
		}
		return "", 0, fmt.Errorf("emailverification: no se pudo confirmar el código: %w", err)
	}
	return grant.Token, grant.ExpiresIn, nil
}
