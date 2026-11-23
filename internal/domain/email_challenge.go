package domain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// EmailChallengePurpose es el propósito de un desafío por email (US-13).
type EmailChallengePurpose string

const (
	// EmailChallengePurposeEmailVerification verifica el email en el alta.
	EmailChallengePurposeEmailVerification EmailChallengePurpose = "EMAIL_VERIFICATION"
	// EmailChallengePurposePasswordReset autoriza la recuperación de contraseña.
	EmailChallengePurposePasswordReset EmailChallengePurpose = "PASSWORD_RESET"
)

// Valid informa si el propósito es uno de los dos que define el contrato.
func (p EmailChallengePurpose) Valid() bool {
	return p == EmailChallengePurposeEmailVerification || p == EmailChallengePurposePasswordReset
}

// EmailChallengeSendWindow es la ventana sobre la que se cuentan los envíos de
// código de un mismo subject (EMAIL_CODE_MAX_SENDS_PER_DAY).
const EmailChallengeSendWindow = 24 * time.Hour

// EmailCodeDigits es la cantidad de dígitos del código que se envía por email.
const EmailCodeDigits = 6

// EmailChallenge es el desafío por email de un subject: un email (verificación
// del alta) o una cuenta (recuperación de contraseña). Hay a lo sumo uno por
// (Purpose, SubjectHMAC).
//
// Nunca guarda el código ni el email en claro: el subject es un HMAC y el código
// se compara por su HMAC. El código en claro solo viaja en el payload del
// outbox. Los campos opcionales son punteros, y los textos vacíos equivalen a
// NULL en la base.
type EmailChallenge struct {
	ID      uuid.UUID
	Purpose EmailChallengePurpose
	// SubjectHMAC es el HMAC-SHA256 de purpose + ":" + el email normalizado (o el
	// id de la cuenta en PASSWORD_RESET).
	SubjectHMAC string
	// UserID es la cuenta a recuperar. Solo PASSWORD_RESET.
	UserID *uuid.UUID

	// CodeHMAC es el HMAC del código vigente. Vacío si no hay código: nunca hubo
	// uno (ACCOUNT_EXISTS) o ya se confirmó.
	CodeHMAC      string
	CodeExpiresAt *time.Time
	CodeAttempts  int

	// GrantHash es el SHA-256 del token emitido al confirmar el código.
	GrantHash      string
	GrantExpiresAt *time.Time
	// GrantAttempts cuenta los rechazos de identidad. Solo PASSWORD_RESET.
	GrantAttempts int

	// SendsCount, SendsWindowStartedAt y LastSentAt alimentan el throttle de
	// envíos.
	SendsCount           int
	SendsWindowStartedAt *time.Time
	LastSentAt           *time.Time

	// ConsumedAt marca el grant como usado.
	ConsumedAt *time.Time
	CreatedAt  time.Time
}

// CanSend informa si el throttle permite enviar un código ahora: tienen que
// haber pasado resend desde el último envío y quedar cupo en la ventana de 24 h.
func (c *EmailChallenge) CanSend(now time.Time, resend time.Duration, maxPerDay int) bool {
	if c.LastSentAt != nil && now.Sub(*c.LastSentAt) < resend {
		return false
	}
	return c.sendsInWindow(now) < maxPerDay
}

// RecordSend registra un envío en el throttle. Si la ventana anterior ya
// terminó, abre una nueva con este envío. Hay que llamarlo solo si CanSend dio
// true.
func (c *EmailChallenge) RecordSend(now time.Time) {
	sends := c.sendsInWindow(now)
	if c.SendsWindowStartedAt == nil || !now.Before(c.SendsWindowStartedAt.Add(EmailChallengeSendWindow)) {
		start := now
		c.SendsWindowStartedAt = &start
		sends = 0
	}
	c.SendsCount = sends + 1
	last := now
	c.LastSentAt = &last
}

func (c *EmailChallenge) sendsInWindow(now time.Time) int {
	if c.SendsWindowStartedAt == nil || !now.Before(c.SendsWindowStartedAt.Add(EmailChallengeSendWindow)) {
		return 0
	}
	return c.SendsCount
}

// CodeUsable informa si hay un código vigente que todavía admite intentos.
func (c *EmailChallenge) CodeUsable(now time.Time, maxAttempts int) bool {
	return c.CodeHMAC != "" &&
		c.CodeExpiresAt != nil && now.Before(*c.CodeExpiresAt) &&
		c.CodeAttempts < maxAttempts
}

// GrantUsable informa si el grant existe, no se usó y no venció. No mira los
// intentos de identidad: ver GrantAttemptsExhausted.
func (c *EmailChallenge) GrantUsable(now time.Time) bool {
	return c.GrantHash != "" &&
		c.ConsumedAt == nil &&
		c.GrantExpiresAt != nil && now.Before(*c.GrantExpiresAt)
}

// GrantAttemptsExhausted informa si el grant ya llegó al tope de rechazos de
// identidad y quedó inválido.
func (c *EmailChallenge) GrantAttemptsExhausted(maxAttempts int) bool {
	return c.GrantAttempts >= maxAttempts
}

// EmailChallengeMutation es el cambio que un caso de uso le aplica a un
// desafío, ya bloqueado, dentro de la transacción del repositorio. Modifica c en
// el lugar y devuelve los eventos de outbox que se persisten junto con el
// cambio. Si devuelve error, la transacción se deshace.
//
// Tiene que ser rápida y sin E/S: corre con la transacción abierta.
type EmailChallengeMutation func(c *EmailChallenge) ([]OutboxEvent, error)

// GrantConsumption identifica el grant de verificación de email que el alta
// consume en la misma transacción que crea el usuario.
type GrantConsumption struct {
	Purpose     EmailChallengePurpose
	SubjectHMAC string
	GrantHash   string
	Now         time.Time
}

// PasswordResetCompletion es todo lo que el caso de uso de la recuperación le
// entrega al repositorio para completarla en una única transacción.
type PasswordResetCompletion struct {
	// GrantHash identifica el reset_token que se consume.
	GrantHash string
	// MaxIdentityAttempts es el tope de rechazos de identidad del grant: si lo
	// alcanzó entre la validación y esta transacción, no se consume.
	MaxIdentityAttempts int
	UserID              uuid.UUID
	PasswordHash        string
	Now                 time.Time
	// SessionsRevoked es el user.sessions.revoked (PASSWORD_RESET) que acompaña
	// la revocación de todas las sesiones del usuario.
	SessionsRevoked OutboxEvent
	// PasswordChanged es el email.requested (PASSWORD_CHANGED) con el aviso.
	PasswordChanged OutboxEvent
}

// EmailChallengeRepository persiste los desafíos por email de US-13.
type EmailChallengeRepository interface {
	// Mutate bloquea el desafío de (purpose, subjectHMAC), le aplica fn y
	// persiste el resultado junto con los eventos de outbox que fn devuelva, todo
	// en una única transacción. Dos llamadas concurrentes sobre el mismo subject
	// se serializan.
	//
	// Si el desafío no existe y create es true, fn recibe uno nuevo (con su ID).
	// Si create es false, devuelve ErrChallengeNotFound (envuelto o no). Un error
	// de base devuelve un error envuelto en ErrDatabaseUnavailable si la base no
	// respondió.
	Mutate(ctx context.Context, purpose EmailChallengePurpose, subjectHMAC string, create bool, fn EmailChallengeMutation) error

	// FindByGrantHash busca el desafío cuyo grant tiene ese SHA-256. Devuelve
	// ErrChallengeNotFound (envuelto o no) si ninguno lo tiene. No mira
	// vencimientos ni usos: quien lo usa decide.
	FindByGrantHash(ctx context.Context, grantHash string) (*EmailChallenge, error)

	// AddGrantAttempt suma un rechazo de identidad al grant, siempre que siga sin
	// consumirse. Que ninguna fila coincida no es un error.
	AddGrantAttempt(ctx context.Context, grantHash string) error

	// CompletePasswordReset consume el reset_token, cambia la contraseña, revoca
	// todas las sesiones del usuario (con el mismo código que RevokeAllByUserID) y
	// encola los dos eventos, todo en una única transacción. Devuelve
	// ErrInvalidResetToken si el grant ya no es utilizable —usado, vencido, sin
	// intentos o anulado por un pedido nuevo— y no cambia nada.
	CompletePasswordReset(ctx context.Context, c PasswordResetCompletion) error

	// DeleteExpired borra hasta limit desafíos cuyo code_expires_at,
	// grant_expires_at y fin de ventana de envíos ya pasaron todos, y devuelve
	// cuántos borró. Es idempotente y seguro con varias réplicas a la vez.
	DeleteExpired(ctx context.Context, now time.Time, limit int) (int64, error)
}

// EmailCodeCodec reúne las operaciones criptográficas de los desafíos, todas
// con EMAIL_CODE_HMAC_KEY o con aleatoriedad criptográfica.
type EmailCodeCodec interface {
	// SubjectHMAC deriva el subject de un desafío: HMAC-SHA256 de
	// purpose + ":" + subject, en hexadecimal.
	SubjectHMAC(purpose EmailChallengePurpose, subject string) string
	// CodeHMAC deriva el HMAC-SHA256 de challengeID + ":" + code, en hexadecimal.
	CodeHMAC(challengeID uuid.UUID, code string) string
	// VerifyCode compara en tiempo constante el código contra el HMAC guardado.
	VerifyCode(challengeID uuid.UUID, code, storedHMAC string) bool
	// NewCode genera un código de EmailCodeDigits dígitos con un CSPRNG, sin
	// sesgo.
	NewCode() (string, error)
	// NewGrant genera un token de 32 bytes aleatorios en base64url sin relleno y
	// su SHA-256 en hexadecimal, que es lo único que se guarda.
	NewGrant() (token, hash string, err error)
	// GrantHash calcula el SHA-256 de un token recibido.
	GrantHash(token string) string
}

// EventTypeEmailRequested es el tipo del evento que pide a Notification enviar
// un email, y también su routing key.
const EventTypeEmailRequested = "email.requested"

// EmailTemplate es la plantilla de email que Notification renderiza.
type EmailTemplate string

const (
	// EmailTemplateEmailVerification lleva el código de verificación del alta.
	EmailTemplateEmailVerification EmailTemplate = "EMAIL_VERIFICATION"
	// EmailTemplateAccountExists avisa que el email ya tiene cuenta. No lleva código.
	EmailTemplateAccountExists EmailTemplate = "ACCOUNT_EXISTS"
	// EmailTemplatePasswordReset lleva el código de recuperación de contraseña.
	EmailTemplatePasswordReset EmailTemplate = "PASSWORD_RESET"
	// EmailTemplatePasswordChanged avisa que se cambió la contraseña.
	EmailTemplatePasswordChanged EmailTemplate = "PASSWORD_CHANGED"
)

// EmailRequest es lo que un caso de uso necesita para pedir un email.
type EmailRequest struct {
	Template EmailTemplate
	// To es el destinatario. Dato personal: solo viaja en el outbox y en el
	// evento, nunca en un log.
	To string
	// Code es el código de 6 dígitos; vacío si la plantilla no lleva.
	Code string
	// ExpiresAt es el vencimiento del código; nil si no lleva.
	ExpiresAt *time.Time
	// Actor es el usuario del hecho (PASSWORD_RESET y PASSWORD_CHANGED); nil en
	// EMAIL_VERIFICATION y ACCOUNT_EXISTS.
	Actor *uuid.UUID
}

// EmailRequested es el evento de dominio email.requested. EventID es el ID de la
// fila del outbox y se reutiliza entre reintentos del worker.
type EmailRequested struct {
	EventID uuid.UUID
	EmailRequest
}

// emailRequestedRecord es el payload con que email.requested se guarda en el
// outbox. Lleva el actor (que el payload publicado no lleva: va en el sobre).
type emailRequestedRecord struct {
	Template  EmailTemplate `json:"template"`
	To        string        `json:"to"`
	Code      *string       `json:"code"`
	ExpiresAt *string       `json:"expires_at"`
	UserID    *string       `json:"user_id"`
}

// NewEmailRequestedOutboxEvent arma la fila de outbox de un email.requested.
func NewEmailRequestedOutboxEvent(req EmailRequest, now time.Time) (OutboxEvent, error) {
	if req.To == "" {
		return OutboxEvent{}, errors.New("domain: el email no tiene destinatario")
	}
	rec := emailRequestedRecord{Template: req.Template, To: req.To}
	if req.Code != "" {
		code := req.Code
		rec.Code = &code
	}
	if req.ExpiresAt != nil {
		expires := req.ExpiresAt.UTC().Format(time.RFC3339)
		rec.ExpiresAt = &expires
	}
	if req.Actor != nil {
		actor := req.Actor.String()
		rec.UserID = &actor
	}

	event, err := NewOutboxEvent(EventTypeEmailRequested, rec)
	if err != nil {
		return OutboxEvent{}, fmt.Errorf("domain: no se pudo armar email.requested: %w", err)
	}
	event.CreatedAt = now.UTC()
	return event, nil
}

// ParseEmailRequested reconstruye el evento a partir de su fila de outbox. Los
// errores nunca incluyen el contenido del payload: lleva el email y el código.
func ParseEmailRequested(event OutboxEvent) (EmailRequested, error) {
	var rec emailRequestedRecord
	if err := json.Unmarshal(event.Payload, &rec); err != nil {
		return EmailRequested{}, errors.New("domain: el payload de email.requested es ilegible")
	}
	if rec.Template == "" || rec.To == "" {
		return EmailRequested{}, errors.New("domain: email.requested sin plantilla o destinatario")
	}

	evt := EmailRequested{EventID: event.ID, EmailRequest: EmailRequest{Template: rec.Template, To: rec.To}}
	if rec.Code != nil {
		evt.Code = *rec.Code
	}
	if rec.ExpiresAt != nil {
		expires, err := time.Parse(time.RFC3339, *rec.ExpiresAt)
		if err != nil {
			return EmailRequested{}, errors.New("domain: expires_at de email.requested inválido")
		}
		evt.ExpiresAt = &expires
	}
	if rec.UserID != nil {
		actor, err := uuid.Parse(*rec.UserID)
		if err != nil {
			return EmailRequested{}, errors.New("domain: user_id de email.requested inválido")
		}
		evt.Actor = &actor
	}
	return evt, nil
}
