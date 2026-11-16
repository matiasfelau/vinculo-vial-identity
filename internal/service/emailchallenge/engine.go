// Package emailchallenge implementa la mecánica común de los desafíos por email
// de US-13: emitir un código con throttle y confirmarlo por intentos, para la
// verificación del email del alta y para la recuperación de contraseña. Depende
// únicamente de los puertos de domain, para ejercitarse entero con dobles.
//
// Toda la lógica de decisión (throttle, intentos, vencimientos) vive acá, como
// una mutación que el repositorio ejecuta con la fila bloqueada: el repositorio
// solo aporta la atomicidad.
package emailchallenge

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/validation"
)

// Settings son los parámetros de los desafíos por email, todos de configuración.
type Settings struct {
	// CodeTTL es la vida del código (EMAIL_CODE_TTL_MINUTES).
	CodeTTL time.Duration
	// MaxCodeAttempts es el tope de intentos de un código
	// (EMAIL_CODE_MAX_ATTEMPTS).
	MaxCodeAttempts int
	// ResendInterval es el mínimo entre dos envíos del mismo subject
	// (EMAIL_CODE_RESEND_SECONDS).
	ResendInterval time.Duration
	// MaxSendsPerDay es el tope de envíos en la ventana de 24 h
	// (EMAIL_CODE_MAX_SENDS_PER_DAY).
	MaxSendsPerDay int
}

// Deps son las dependencias del motor. Todas son puertos de domain.
type Deps struct {
	Challenges domain.EmailChallengeRepository
	Codec      domain.EmailCodeCodec
	Settings   Settings
	Logger     *slog.Logger
	// Now permite fijar el reloj en los tests. Si es nil se usa time.Now.
	Now func() time.Time
}

// Engine emite y confirma desafíos por email.
type Engine struct {
	deps Deps
}

// New valida las dependencias y los parámetros, y construye el motor. Se falla en
// el arranque: un parámetro inválido no debe descubrirse con el primer pedido.
func New(d Deps) (*Engine, error) {
	switch {
	case d.Challenges == nil:
		return nil, errors.New("emailchallenge: falta el repositorio de desafíos")
	case d.Codec == nil:
		return nil, errors.New("emailchallenge: falta el codec de códigos")
	case d.Settings.CodeTTL <= 0:
		return nil, errors.New("emailchallenge: la vida del código debe ser positiva")
	case d.Settings.MaxCodeAttempts < 1:
		return nil, errors.New("emailchallenge: el tope de intentos debe ser al menos 1")
	case d.Settings.ResendInterval <= 0:
		return nil, errors.New("emailchallenge: el intervalo de reenvío debe ser positivo")
	case d.Settings.MaxSendsPerDay < 1:
		return nil, errors.New("emailchallenge: el tope de envíos por día debe ser al menos 1")
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Engine{deps: d}, nil
}

// IssueParams describe un pedido de envío.
type IssueParams struct {
	Purpose domain.EmailChallengePurpose
	// Subject es el email normalizado (EMAIL_VERIFICATION) o el id de la cuenta
	// (PASSWORD_RESET). Con el propósito, deriva la clave del desafío.
	Subject string
	// UserID es la cuenta a recuperar. Solo PASSWORD_RESET.
	UserID *uuid.UUID
	// To es el destinatario del email.
	To string
	// Template es la plantilla a enviar.
	Template domain.EmailTemplate
	// WithCode indica si el email lleva un código. Con false (ACCOUNT_EXISTS) el
	// desafío queda sin código, y confirmar da INVALID_CODE.
	WithCode bool
}

// IssueOutcome es lo que pasó con un pedido de envío. Los llamadores no lo
// muestran al cliente: la respuesta es la misma en todos los casos. Existe para
// los tests y para un log de nivel debug.
type IssueOutcome int

const (
	// Throttled indica que el throttle no permitió enviar: no se escribió nada.
	Throttled IssueOutcome = iota
	// Sent indica que se encoló el email.
	Sent
)

// Issue emite un desafío y encola el email, siempre que el throttle lo permita.
//
// Todo ocurre en una transacción con el desafío bloqueado: el cambio del código y
// la fila de outbox se confirman juntos o no se confirma ninguno, y dos pedidos
// concurrentes del mismo subject se serializan, así que el throttle no se puede
// saltear con paralelismo. Un pedido que sí se envía reemplaza el código, pone los
// intentos en 0 y anula el grant anterior.
func (e *Engine) Issue(ctx context.Context, p IssueParams) (IssueOutcome, error) {
	if !p.Purpose.Valid() || p.Subject == "" || p.To == "" {
		return Throttled, errors.New("emailchallenge: pedido de envío incompleto")
	}

	now := e.deps.Now().UTC()
	subject := e.deps.Codec.SubjectHMAC(p.Purpose, p.Subject)
	outcome := Throttled

	mutate := func(c *domain.EmailChallenge) ([]domain.OutboxEvent, error) {
		s := e.deps.Settings
		if !c.CanSend(now, s.ResendInterval, s.MaxSendsPerDay) {
			return nil, nil
		}
		c.RecordSend(now)
		c.UserID = p.UserID
		c.CodeAttempts = 0
		c.GrantHash, c.GrantExpiresAt, c.GrantAttempts = "", nil, 0
		c.ConsumedAt = nil

		req := domain.EmailRequest{Template: p.Template, To: p.To, Actor: p.UserID}
		if p.WithCode {
			code, err := e.deps.Codec.NewCode()
			if err != nil {
				return nil, err
			}
			expires := now.Add(s.CodeTTL)
			c.CodeHMAC = e.deps.Codec.CodeHMAC(c.ID, code)
			c.CodeExpiresAt = &expires
			req.Code, req.ExpiresAt = code, &expires
		} else {
			c.CodeHMAC, c.CodeExpiresAt = "", nil
		}

		event, err := domain.NewEmailRequestedOutboxEvent(req, now)
		if err != nil {
			return nil, err
		}
		outcome = Sent
		return []domain.OutboxEvent{event}, nil
	}

	if err := e.deps.Challenges.Mutate(ctx, p.Purpose, subject, true, mutate); err != nil {
		return Throttled, fmt.Errorf("emailchallenge: no se pudo emitir el desafío: %w", err)
	}
	return outcome, nil
}

// Grant es el token que emite una confirmación exitosa.
type Grant struct {
	// Token es el valor que se le devuelve al cliente, una única vez.
	Token string
	// ExpiresIn es lo que le queda de vida.
	ExpiresIn time.Duration
}

// Confirm verifica el código de un subject y, si es correcto, lo cambia por un
// grant de vida grantTTL.
//
// Devuelve domain.ErrInvalidCode, sin distinguir el motivo, si el código tiene mala
// forma, no hay desafío, no hay código, venció, agotó sus intentos o es
// incorrecto. Un código incorrecto suma un intento y se persiste, aunque la
// respuesta sea un error: por eso la mutación no falla, solo informa.
func (e *Engine) Confirm(ctx context.Context, purpose domain.EmailChallengePurpose, subject, code string, grantTTL time.Duration) (Grant, error) {
	if !purpose.Valid() || subject == "" || grantTTL <= 0 {
		return Grant{}, errors.New("emailchallenge: pedido de confirmación incompleto")
	}
	if !validation.IsEmailCode(code, domain.EmailCodeDigits) {
		return Grant{}, domain.ErrInvalidCode
	}

	now := e.deps.Now().UTC()
	key := e.deps.Codec.SubjectHMAC(purpose, subject)
	var granted *Grant

	mutate := func(c *domain.EmailChallenge) ([]domain.OutboxEvent, error) {
		if !c.CodeUsable(now, e.deps.Settings.MaxCodeAttempts) {
			return nil, nil
		}
		if !e.deps.Codec.VerifyCode(c.ID, code, c.CodeHMAC) {
			c.CodeAttempts++
			return nil, nil
		}

		token, hash, err := e.deps.Codec.NewGrant()
		if err != nil {
			return nil, err
		}
		expires := now.Add(grantTTL)
		c.CodeHMAC = ""
		c.GrantHash, c.GrantExpiresAt, c.GrantAttempts = hash, &expires, 0
		c.ConsumedAt = nil
		granted = &Grant{Token: token, ExpiresIn: grantTTL}
		return nil, nil
	}

	err := e.deps.Challenges.Mutate(ctx, purpose, key, false, mutate)
	switch {
	case errors.Is(err, domain.ErrChallengeNotFound):
		return Grant{}, domain.ErrInvalidCode
	case err != nil:
		return Grant{}, fmt.Errorf("emailchallenge: no se pudo confirmar el código: %w", err)
	case granted == nil:
		return Grant{}, domain.ErrInvalidCode
	}
	return *granted, nil
}
