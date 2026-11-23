package domain_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

var t0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func TestPurposeValid(t *testing.T) {
	validos := []domain.EmailChallengePurpose{
		domain.EmailChallengePurposeEmailVerification, domain.EmailChallengePurposePasswordReset,
	}
	for _, p := range validos {
		if !p.Valid() {
			t.Errorf("%q debería ser válido", p)
		}
	}
	for _, p := range []domain.EmailChallengePurpose{"", "OTRO", "password_reset"} {
		if p.Valid() {
			t.Errorf("%q no debería ser válido", p)
		}
	}
}

// El throttle: tiempo mínimo entre envíos y tope por ventana de 24 h.
func TestCanSend(t *testing.T) {
	resend := time.Minute
	enVentana := func(sends int, windowStart, last time.Time) *domain.EmailChallenge {
		return &domain.EmailChallenge{SendsCount: sends, SendsWindowStartedAt: &windowStart, LastSentAt: &last}
	}

	casos := []struct {
		name string
		c    *domain.EmailChallenge
		now  time.Time
		want bool
	}{
		{"desafío nuevo", &domain.EmailChallenge{}, t0, true},
		{"antes del intervalo de reenvío", enVentana(1, t0, t0), t0.Add(59 * time.Second), false},
		{"justo en el intervalo de reenvío", enVentana(1, t0, t0), t0.Add(time.Minute), true},
		{"con cupo en la ventana", enVentana(4, t0, t0), t0.Add(2 * time.Minute), true},
		{"ventana agotada", enVentana(5, t0, t0), t0.Add(2 * time.Minute), false},
		{"ventana agotada pero ya terminó", enVentana(5, t0, t0), t0.Add(24 * time.Hour), true},
		{"ventana agotada, un instante antes de terminar", enVentana(5, t0, t0), t0.Add(24*time.Hour - time.Second), false},
	}
	for _, tc := range casos {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c.CanSend(tc.now, resend, 5); got != tc.want {
				t.Errorf("CanSend = %v, se esperaba %v", got, tc.want)
			}
		})
	}
}

func TestRecordSendAbreVentanaYCuenta(t *testing.T) {
	c := &domain.EmailChallenge{}

	c.RecordSend(t0)
	if c.SendsCount != 1 || c.SendsWindowStartedAt == nil || !c.SendsWindowStartedAt.Equal(t0) {
		t.Fatalf("primer envío: count=%d window=%v", c.SendsCount, c.SendsWindowStartedAt)
	}
	if c.LastSentAt == nil || !c.LastSentAt.Equal(t0) {
		t.Errorf("last_sent_at = %v, se esperaba %v", c.LastSentAt, t0)
	}

	c.RecordSend(t0.Add(2 * time.Minute))
	if c.SendsCount != 2 || !c.SendsWindowStartedAt.Equal(t0) {
		t.Errorf("segundo envío en la misma ventana: count=%d window=%v", c.SendsCount, c.SendsWindowStartedAt)
	}
}

func TestRecordSendReiniciaLaVentanaVencida(t *testing.T) {
	inicio := t0
	c := &domain.EmailChallenge{SendsCount: 5, SendsWindowStartedAt: &inicio, LastSentAt: &inicio}

	later := t0.Add(25 * time.Hour)
	c.RecordSend(later)

	if c.SendsCount != 1 {
		t.Errorf("count = %d, se esperaba 1 tras reiniciar la ventana", c.SendsCount)
	}
	if !c.SendsWindowStartedAt.Equal(later) {
		t.Errorf("la ventana nueva arranca en %v, se esperaba %v", c.SendsWindowStartedAt, later)
	}
}

func TestCodeUsable(t *testing.T) {
	vence := t0.Add(10 * time.Minute)
	base := func() *domain.EmailChallenge {
		return &domain.EmailChallenge{CodeHMAC: "h", CodeExpiresAt: &vence, CodeAttempts: 0}
	}

	casos := []struct {
		name   string
		mutate func(c *domain.EmailChallenge)
		now    time.Time
		want   bool
	}{
		{"vigente", func(*domain.EmailChallenge) {}, t0, true},
		{"sin código", func(c *domain.EmailChallenge) { c.CodeHMAC = "" }, t0, false},
		{"sin vencimiento", func(c *domain.EmailChallenge) { c.CodeExpiresAt = nil }, t0, false},
		{"vencido", func(*domain.EmailChallenge) {}, vence, false},
		{"último intento disponible", func(c *domain.EmailChallenge) { c.CodeAttempts = 4 }, t0, true},
		{"sin intentos", func(c *domain.EmailChallenge) { c.CodeAttempts = 5 }, t0, false},
	}
	for _, tc := range casos {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mutate(c)
			if got := c.CodeUsable(tc.now, 5); got != tc.want {
				t.Errorf("CodeUsable = %v, se esperaba %v", got, tc.want)
			}
		})
	}
}

func TestGrantUsable(t *testing.T) {
	vence := t0.Add(30 * time.Minute)
	usado := t0

	casos := []struct {
		name string
		c    domain.EmailChallenge
		now  time.Time
		want bool
	}{
		{"vigente", domain.EmailChallenge{GrantHash: "g", GrantExpiresAt: &vence}, t0, true},
		{"sin grant", domain.EmailChallenge{GrantExpiresAt: &vence}, t0, false},
		{"sin vencimiento", domain.EmailChallenge{GrantHash: "g"}, t0, false},
		{"vencido", domain.EmailChallenge{GrantHash: "g", GrantExpiresAt: &vence}, vence, false},
		{"usado", domain.EmailChallenge{GrantHash: "g", GrantExpiresAt: &vence, ConsumedAt: &usado}, t0, false},
	}
	for _, tc := range casos {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c.GrantUsable(tc.now); got != tc.want {
				t.Errorf("GrantUsable = %v, se esperaba %v", got, tc.want)
			}
		})
	}
}

func TestGrantAttemptsExhausted(t *testing.T) {
	for attempts, want := range map[int]bool{0: false, 2: false, 3: true, 4: true} {
		c := &domain.EmailChallenge{GrantAttempts: attempts}
		if got := c.GrantAttemptsExhausted(3); got != want {
			t.Errorf("con %d intentos: %v, se esperaba %v", attempts, got, want)
		}
	}
}

func TestEmailRequestedConCodigoHaceIdaYVuelta(t *testing.T) {
	actor := uuid.New()
	expira := t0.Add(10 * time.Minute)

	row, err := domain.NewEmailRequestedOutboxEvent(domain.EmailRequest{
		Template: domain.EmailTemplatePasswordReset, To: "vecino@example.com", Code: "042917", ExpiresAt: &expira, Actor: &actor,
	}, t0)
	if err != nil {
		t.Fatalf("NewEmailRequestedOutboxEvent: %v", err)
	}
	if row.Type != "email.requested" {
		t.Errorf("tipo = %q, se esperaba email.requested", row.Type)
	}
	if !row.CreatedAt.Equal(t0) {
		t.Errorf("created_at = %v, se esperaba %v", row.CreatedAt, t0)
	}

	evt, err := domain.ParseEmailRequested(row)
	if err != nil {
		t.Fatalf("ParseEmailRequested: %v", err)
	}
	if evt.EventID != row.ID {
		t.Error("el EventID tiene que ser el de la fila del outbox")
	}
	if evt.Template != domain.EmailTemplatePasswordReset || evt.To != "vecino@example.com" || evt.Code != "042917" {
		t.Errorf("evento = %+v", evt)
	}
	if evt.ExpiresAt == nil || !evt.ExpiresAt.Equal(expira) {
		t.Errorf("expires_at = %v, se esperaba %v", evt.ExpiresAt, expira)
	}
	if evt.Actor == nil || *evt.Actor != actor {
		t.Errorf("actor = %v, se esperaba %v", evt.Actor, actor)
	}
}

// Los códigos con ceros a la izquierda no pierden dígitos.
func TestEmailRequestedConservaLosCerosDelCodigo(t *testing.T) {
	row, _ := domain.NewEmailRequestedOutboxEvent(domain.EmailRequest{
		Template: domain.EmailTemplateEmailVerification, To: "a@b.co", Code: "000007",
	}, t0)
	evt, err := domain.ParseEmailRequested(row)
	if err != nil || evt.Code != "000007" {
		t.Fatalf("code = %q, err = %v", evt.Code, err)
	}
}

// Sin código, vencimiento ni actor, el payload los lleva como null, que es lo que
// el contrato pide para ACCOUNT_EXISTS y PASSWORD_CHANGED.
func TestEmailRequestedSinCodigoNiActorLlevaNull(t *testing.T) {
	row, err := domain.NewEmailRequestedOutboxEvent(domain.EmailRequest{
		Template: domain.EmailTemplateAccountExists, To: "a@b.co",
	}, t0)
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]any
	if err := json.Unmarshal(row.Payload, &raw); err != nil {
		t.Fatal(err)
	}
	for _, campo := range []string{"code", "expires_at", "user_id"} {
		v, presente := raw[campo]
		if !presente || v != nil {
			t.Errorf("%s = %v (presente=%v), se esperaba null", campo, v, presente)
		}
	}

	evt, err := domain.ParseEmailRequested(row)
	if err != nil {
		t.Fatal(err)
	}
	if evt.Code != "" || evt.ExpiresAt != nil || evt.Actor != nil {
		t.Errorf("el evento reconstruido debería estar vacío de código, vencimiento y actor: %+v", evt)
	}
}

func TestNewEmailRequestedOutboxEventExigeDestinatario(t *testing.T) {
	if _, err := domain.NewEmailRequestedOutboxEvent(domain.EmailRequest{Template: domain.EmailTemplatePasswordChanged}, t0); err == nil {
		t.Fatal("se esperaba un error sin destinatario")
	}
}

// Los errores de ParseEmailRequested nunca incluyen el contenido del payload: el
// worker los guarda en last_error y los loguea.
func TestParseEmailRequestedRechazaPayloadsInvalidosSinFiltrarContenido(t *testing.T) {
	casos := map[string]string{
		"no es JSON":          `{"to":"secreto@example.com","code":"123456"`,
		"sin plantilla":       `{"to":"secreto@example.com","code":"123456"}`,
		"sin destinatario":    `{"template":"PASSWORD_RESET","code":"123456"}`,
		"expires_at inválido": `{"template":"PASSWORD_RESET","to":"secreto@example.com","code":"123456","expires_at":"mañana"}`,
		"user_id inválido":    `{"template":"PASSWORD_RESET","to":"secreto@example.com","code":"123456","user_id":"no-es-uuid"}`,
	}
	for name, payload := range casos {
		t.Run(name, func(t *testing.T) {
			_, err := domain.ParseEmailRequested(domain.OutboxEvent{ID: uuid.New(), Type: domain.EventTypeEmailRequested, Payload: json.RawMessage(payload)})
			if err == nil {
				t.Fatal("se esperaba un error")
			}
			for _, secreto := range []string{"secreto@example.com", "123456"} {
				if strings.Contains(err.Error(), secreto) {
					t.Errorf("el error filtra %q: %v", secreto, err)
				}
			}
		})
	}
}

func TestSessionsRevokedReasonPasswordReset(t *testing.T) {
	if got := string(domain.SessionsRevokedReasonPasswordReset); got != "PASSWORD_RESET" {
		t.Errorf("motivo = %q, se esperaba PASSWORD_RESET", got)
	}
	if domain.EventTypeUserSessionsRevoked != "user.sessions.revoked" {
		t.Errorf("tipo = %q", domain.EventTypeUserSessionsRevoked)
	}
}
