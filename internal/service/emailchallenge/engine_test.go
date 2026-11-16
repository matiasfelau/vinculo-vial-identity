package emailchallenge_test

import (
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/emailcode"
	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/emailchallenge"
	"github.com/matiasfelau/vinculo-vial-identity/internal/testsupport/emailchallenges"
)

var inicio = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

// reloj es un reloj que los tests adelantan a mano.
type reloj struct{ now time.Time }

func (r *reloj) Now() time.Time          { return r.now }
func (r *reloj) advance(d time.Duration) { r.now = r.now.Add(d) }

var ajustes = emailchallenge.Settings{
	CodeTTL:         10 * time.Minute,
	MaxCodeAttempts: 5,
	ResendInterval:  time.Minute,
	MaxSendsPerDay:  5,
}

const grantTTL = 30 * time.Minute

type harness struct {
	engine *emailchallenge.Engine
	repo   *emailchallenges.Memory
	codec  *emailcode.Codec
	clock  *reloj
}

func newHarness(t *testing.T, tune ...func(*emailchallenge.Deps)) *harness {
	t.Helper()

	codec, err := emailcode.New(make([]byte, emailcode.KeyLength))
	if err != nil {
		t.Fatalf("codec: %v", err)
	}
	h := &harness{repo: emailchallenges.New(), codec: codec, clock: &reloj{now: inicio}}

	deps := emailchallenge.Deps{
		Challenges: h.repo,
		Codec:      codec,
		Settings:   ajustes,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:        h.clock.Now,
	}
	for _, f := range tune {
		f(&deps)
	}
	h.engine, err = emailchallenge.New(deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h
}

func pedido() emailchallenge.IssueParams {
	return emailchallenge.IssueParams{
		Purpose:  domain.EmailChallengePurposeEmailVerification,
		Subject:  "vecino@vinculovial.ar",
		To:       "vecino@vinculovial.ar",
		Template: domain.EmailTemplateEmailVerification,
		WithCode: true,
	}
}

func (h *harness) desafio(p emailchallenge.IssueParams) *domain.EmailChallenge {
	return h.repo.Get(p.Purpose, h.codec.SubjectHMAC(p.Purpose, p.Subject))
}

// ultimoEmail devuelve el último email.requested encolado, reconstruido.
func (h *harness) ultimoEmail(t *testing.T) domain.EmailRequested {
	t.Helper()
	out := h.repo.Outbox()
	if len(out) == 0 {
		t.Fatal("no hay eventos en el outbox")
	}
	evt, err := domain.ParseEmailRequested(out[len(out)-1])
	if err != nil {
		t.Fatalf("ParseEmailRequested: %v", err)
	}
	return evt
}

func TestIssueEmiteElCodigoYEncolaElEmail(t *testing.T) {
	h := newHarness(t)
	p := pedido()

	outcome, err := h.engine.Issue(t.Context(), p)
	if err != nil || outcome != emailchallenge.Sent {
		t.Fatalf("Issue = (%v, %v), se esperaba (Sent, nil)", outcome, err)
	}

	evt := h.ultimoEmail(t)
	if evt.Template != domain.EmailTemplateEmailVerification || evt.To != p.To {
		t.Errorf("evento = %+v", evt)
	}
	if len(evt.Code) != domain.EmailCodeDigits {
		t.Fatalf("el email no lleva un código de %d dígitos: %q", domain.EmailCodeDigits, evt.Code)
	}
	wantExpiry := inicio.Add(ajustes.CodeTTL)
	if evt.ExpiresAt == nil || !evt.ExpiresAt.Equal(wantExpiry) {
		t.Errorf("expires_at = %v, se esperaba %v", evt.ExpiresAt, wantExpiry)
	}
	if evt.Actor != nil {
		t.Errorf("EMAIL_VERIFICATION no lleva actor: %v", evt.Actor)
	}

	c := h.desafio(p)
	if c == nil {
		t.Fatal("el desafío no se guardó")
	}
	if !h.codec.VerifyCode(c.ID, evt.Code, c.CodeHMAC) {
		t.Error("el código del email no coincide con el HMAC guardado")
	}
	if c.CodeHMAC == evt.Code || strings.Contains(c.CodeHMAC, evt.Code) {
		t.Error("el código se guardó en claro")
	}
	if c.CodeAttempts != 0 || c.SendsCount != 1 || c.LastSentAt == nil || !c.LastSentAt.Equal(inicio) {
		t.Errorf("estado = %+v", c)
	}
	if c.SubjectHMAC == p.Subject {
		t.Error("el subject se guardó en claro")
	}
}

func TestIssueDePasswordResetLlevaElActorYLaCuenta(t *testing.T) {
	h := newHarness(t)
	user := uuid.New()
	p := emailchallenge.IssueParams{
		Purpose: domain.EmailChallengePurposePasswordReset, Subject: user.String(), UserID: &user,
		To: "vecino@vinculovial.ar", Template: domain.EmailTemplatePasswordReset, WithCode: true,
	}

	if _, err := h.engine.Issue(t.Context(), p); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if evt := h.ultimoEmail(t); evt.Actor == nil || *evt.Actor != user {
		t.Errorf("actor = %v, se esperaba %v", evt.Actor, user)
	}
	if c := h.desafio(p); c.UserID == nil || *c.UserID != user {
		t.Errorf("user_id = %v, se esperaba %v", c.UserID, user)
	}
}

// Dentro del intervalo de reenvío no se envía ni se cambia nada: el código
// anterior sigue siendo el vigente.
func TestIssueDentroDelIntervaloNoEnvia(t *testing.T) {
	h := newHarness(t)
	p := pedido()
	h.engine.Issue(t.Context(), p)
	antes := h.desafio(p)

	h.clock.advance(59 * time.Second)
	outcome, err := h.engine.Issue(t.Context(), p)

	if err != nil || outcome != emailchallenge.Throttled {
		t.Fatalf("Issue = (%v, %v), se esperaba (Throttled, nil)", outcome, err)
	}
	if got := len(h.repo.Outbox()); got != 1 {
		t.Errorf("hay %d eventos, se esperaba 1: no se debió enviar un segundo mail", got)
	}
	if despues := h.desafio(p); despues.CodeHMAC != antes.CodeHMAC || despues.SendsCount != 1 {
		t.Error("el throttle cambió el desafío")
	}
}

// Un pedido que sí se envía reemplaza el código, pone los intentos en 0 y anula
// el grant anterior.
func TestIssueNuevoReemplazaElCodigoReiniciaIntentosYAnulaElGrant(t *testing.T) {
	h := newHarness(t)
	p := pedido()
	h.engine.Issue(t.Context(), p)
	primero := h.ultimoEmail(t).Code

	// Se llega a confirmar, para tener un grant, y se gastan intentos.
	if _, err := h.engine.Confirm(t.Context(), p.Purpose, p.Subject, primero, grantTTL); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if c := h.desafio(p); c.GrantHash == "" {
		t.Fatal("no se emitió el grant")
	}

	h.clock.advance(2 * time.Minute)
	outcome, err := h.engine.Issue(t.Context(), p)
	if err != nil || outcome != emailchallenge.Sent {
		t.Fatalf("Issue = (%v, %v), se esperaba Sent", outcome, err)
	}

	c := h.desafio(p)
	if c.GrantHash != "" || c.GrantExpiresAt != nil || c.GrantAttempts != 0 || c.ConsumedAt != nil {
		t.Errorf("el grant anterior sigue vivo: %+v", c)
	}
	if c.CodeAttempts != 0 || c.CodeHMAC == "" {
		t.Errorf("código/intentos tras el reemplazo: %+v", c)
	}
	nuevo := h.ultimoEmail(t).Code
	if !h.codec.VerifyCode(c.ID, nuevo, c.CodeHMAC) {
		t.Error("el código nuevo no coincide con el guardado")
	}
	if nuevo != primero && h.codec.VerifyCode(c.ID, primero, c.CodeHMAC) {
		t.Error("el código anterior sigue verificando")
	}
}

func TestIssueReiniciaLosIntentosDelCodigo(t *testing.T) {
	h := newHarness(t)
	p := pedido()
	h.engine.Issue(t.Context(), p)
	malo := codigoDistintoDe(h.ultimoEmail(t).Code)
	for range 3 {
		h.engine.Confirm(t.Context(), p.Purpose, p.Subject, malo, grantTTL)
	}
	if got := h.desafio(p).CodeAttempts; got != 3 {
		t.Fatalf("intentos = %d, se esperaban 3", got)
	}

	h.clock.advance(time.Minute)
	h.engine.Issue(t.Context(), p)

	if got := h.desafio(p).CodeAttempts; got != 0 {
		t.Errorf("intentos = %d, se esperaba 0 tras reenviar", got)
	}
}

func TestIssueRespetaElTopeDiarioYLoLiberaAlTerminarLaVentana(t *testing.T) {
	h := newHarness(t)
	p := pedido()

	for i := range ajustes.MaxSendsPerDay {
		outcome, err := h.engine.Issue(t.Context(), p)
		if err != nil || outcome != emailchallenge.Sent {
			t.Fatalf("envío %d = (%v, %v), se esperaba Sent", i+1, outcome, err)
		}
		h.clock.advance(2 * time.Minute)
	}

	if outcome, _ := h.engine.Issue(t.Context(), p); outcome != emailchallenge.Throttled {
		t.Fatalf("el envío %d pasó: el tope diario es %d", ajustes.MaxSendsPerDay+1, ajustes.MaxSendsPerDay)
	}
	if got := len(h.repo.Outbox()); got != ajustes.MaxSendsPerDay {
		t.Errorf("hay %d mails, se esperaban %d", got, ajustes.MaxSendsPerDay)
	}

	// La ventana arrancó con el primer envío: 24 h después, hay cupo de nuevo.
	h.clock.now = inicio.Add(24 * time.Hour)
	if outcome, err := h.engine.Issue(t.Context(), p); err != nil || outcome != emailchallenge.Sent {
		t.Fatalf("Issue tras la ventana = (%v, %v), se esperaba Sent", outcome, err)
	}
	if got := h.desafio(p).SendsCount; got != 1 {
		t.Errorf("sends_count = %d, se esperaba 1 en la ventana nueva", got)
	}
}

// ACCOUNT_EXISTS no lleva código, pero cuenta para el throttle del subject.
func TestIssueSinCodigoDejaElDesafioSinCodigoYCuentaParaElThrottle(t *testing.T) {
	h := newHarness(t)
	p := pedido()
	p.Template, p.WithCode = domain.EmailTemplateAccountExists, false

	outcome, err := h.engine.Issue(t.Context(), p)
	if err != nil || outcome != emailchallenge.Sent {
		t.Fatalf("Issue = (%v, %v)", outcome, err)
	}

	evt := h.ultimoEmail(t)
	if evt.Template != domain.EmailTemplateAccountExists || evt.Code != "" || evt.ExpiresAt != nil {
		t.Errorf("ACCOUNT_EXISTS no debe llevar código ni vencimiento: %+v", evt)
	}
	c := h.desafio(p)
	if c.CodeHMAC != "" || c.CodeExpiresAt != nil {
		t.Errorf("el desafío quedó con código: %+v", c)
	}

	// Un pedido de verificación del mismo email, dentro del intervalo, no se envía.
	h.clock.advance(10 * time.Second)
	if outcome, _ := h.engine.Issue(t.Context(), pedido()); outcome != emailchallenge.Throttled {
		t.Error("ACCOUNT_EXISTS no contó para el throttle del subject")
	}
}

// Confirmar sobre un desafío ACCOUNT_EXISTS da INVALID_CODE, como cualquier otro.
func TestConfirmSobreAccountExistsDaCodigoInvalido(t *testing.T) {
	h := newHarness(t)
	p := pedido()
	p.Template, p.WithCode = domain.EmailTemplateAccountExists, false
	h.engine.Issue(t.Context(), p)

	_, err := h.engine.Confirm(t.Context(), p.Purpose, p.Subject, "123456", grantTTL)
	if !errors.Is(err, domain.ErrInvalidCode) {
		t.Fatalf("error = %v, se esperaba ErrInvalidCode", err)
	}
}

func TestIssueRechazaPedidosIncompletos(t *testing.T) {
	casos := map[string]func(*emailchallenge.IssueParams){
		"propósito inválido": func(p *emailchallenge.IssueParams) { p.Purpose = "OTRO" },
		"sin subject":        func(p *emailchallenge.IssueParams) { p.Subject = "" },
		"sin destinatario":   func(p *emailchallenge.IssueParams) { p.To = "" },
	}
	for name, tune := range casos {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			p := pedido()
			tune(&p)
			if _, err := h.engine.Issue(t.Context(), p); err == nil {
				t.Fatal("se esperaba un error")
			}
			if h.repo.Mutations() != 0 {
				t.Error("se tocó la base con un pedido incompleto")
			}
		})
	}
}

func TestIssueConLaBaseCaidaDevuelveElErrorSinEnviar(t *testing.T) {
	h := newHarness(t)
	h.repo.Err = domain.ErrDatabaseUnavailable

	outcome, err := h.engine.Issue(t.Context(), pedido())

	if !errors.Is(err, domain.ErrDatabaseUnavailable) {
		t.Fatalf("error = %v, se esperaba ErrDatabaseUnavailable", err)
	}
	if outcome != emailchallenge.Throttled {
		t.Error("un envío fallido no puede reportarse como enviado")
	}
}

// codecQueFalla delega todo en el codec real salvo la fuente aleatoria.
type codecQueFalla struct {
	domain.EmailCodeCodec
	codeErr, grantErr error
}

func (c codecQueFalla) NewCode() (string, error) {
	if c.codeErr != nil {
		return "", c.codeErr
	}
	return c.EmailCodeCodec.NewCode()
}

func (c codecQueFalla) NewGrant() (string, string, error) {
	if c.grantErr != nil {
		return "", "", c.grantErr
	}
	return c.EmailCodeCodec.NewGrant()
}

func TestIssueSiFallaLaFuenteAleatoriaNoDejaNadaHecho(t *testing.T) {
	boom := errors.New("sin entropía")
	h := newHarness(t, func(d *emailchallenge.Deps) { d.Codec = codecQueFalla{EmailCodeCodec: d.Codec, codeErr: boom} })
	p := pedido()

	if _, err := h.engine.Issue(t.Context(), p); !errors.Is(err, boom) {
		t.Fatalf("error = %v, se esperaba el de la fuente aleatoria", err)
	}
	if h.desafio(p) != nil || len(h.repo.Outbox()) != 0 {
		t.Error("quedó un desafío o un evento pese al error")
	}
}

func TestConfirmConCodigoCorrectoEmiteElGrant(t *testing.T) {
	h := newHarness(t)
	p := pedido()
	h.engine.Issue(t.Context(), p)
	code := h.ultimoEmail(t).Code

	h.clock.advance(3 * time.Minute)
	grant, err := h.engine.Confirm(t.Context(), p.Purpose, p.Subject, code, grantTTL)
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}

	if grant.ExpiresIn != grantTTL {
		t.Errorf("expires_in = %v, se esperaba %v", grant.ExpiresIn, grantTTL)
	}
	c := h.desafio(p)
	if c.GrantHash != h.codec.GrantHash(grant.Token) {
		t.Error("el hash guardado no es el SHA-256 del token emitido")
	}
	if strings.Contains(c.GrantHash, grant.Token) {
		t.Error("el token se guardó en claro")
	}
	if want := h.clock.now.Add(grantTTL); c.GrantExpiresAt == nil || !c.GrantExpiresAt.Equal(want) {
		t.Errorf("grant_expires_at = %v, se esperaba %v", c.GrantExpiresAt, want)
	}
	if c.CodeHMAC != "" {
		t.Error("el código sigue guardado tras confirmarse: tiene que borrarse")
	}
	if c.GrantAttempts != 0 {
		t.Errorf("grant_attempts = %d, se esperaba 0", c.GrantAttempts)
	}
}

func TestConfirmConCodigoCorrectoNoSePuedeUsarDosVeces(t *testing.T) {
	h := newHarness(t)
	p := pedido()
	h.engine.Issue(t.Context(), p)
	code := h.ultimoEmail(t).Code

	if _, err := h.engine.Confirm(t.Context(), p.Purpose, p.Subject, code, grantTTL); err != nil {
		t.Fatalf("primera: %v", err)
	}
	if _, err := h.engine.Confirm(t.Context(), p.Purpose, p.Subject, code, grantTTL); !errors.Is(err, domain.ErrInvalidCode) {
		t.Fatalf("segunda: %v, se esperaba ErrInvalidCode", err)
	}
}

// codigoDistintoDe devuelve un código de 6 dígitos que no es code.
func codigoDistintoDe(code string) string {
	if code == "000000" {
		return "000001"
	}
	return "000000"
}

func TestConfirmConCodigoIncorrectoSumaUnIntentoYSePersiste(t *testing.T) {
	h := newHarness(t)
	p := pedido()
	h.engine.Issue(t.Context(), p)
	malo := codigoDistintoDe(h.ultimoEmail(t).Code)

	for i := 1; i <= 3; i++ {
		_, err := h.engine.Confirm(t.Context(), p.Purpose, p.Subject, malo, grantTTL)
		if !errors.Is(err, domain.ErrInvalidCode) {
			t.Fatalf("intento %d: %v, se esperaba ErrInvalidCode", i, err)
		}
		if got := h.desafio(p).CodeAttempts; got != i {
			t.Fatalf("tras %d intentos fallidos, code_attempts = %d", i, got)
		}
	}
}

// Cinco incorrectos obligan a pedir otro: el sexto, aunque sea el correcto, no sirve.
func TestConfirmSinIntentosNoAceptaNiElCodigoCorrecto(t *testing.T) {
	h := newHarness(t)
	p := pedido()
	h.engine.Issue(t.Context(), p)
	code := h.ultimoEmail(t).Code
	malo := codigoDistintoDe(code)

	for range ajustes.MaxCodeAttempts {
		h.engine.Confirm(t.Context(), p.Purpose, p.Subject, malo, grantTTL)
	}

	if _, err := h.engine.Confirm(t.Context(), p.Purpose, p.Subject, code, grantTTL); !errors.Is(err, domain.ErrInvalidCode) {
		t.Fatalf("error = %v, se esperaba ErrInvalidCode aunque el código sea el correcto", err)
	}
	if got := h.desafio(p).CodeAttempts; got != ajustes.MaxCodeAttempts {
		t.Errorf("code_attempts = %d, no debería seguir sumando tras agotarse (%d)", got, ajustes.MaxCodeAttempts)
	}

	// Pedir otro código lo rehabilita.
	h.clock.advance(time.Minute)
	h.engine.Issue(t.Context(), p)
	nuevo := h.ultimoEmail(t).Code
	if _, err := h.engine.Confirm(t.Context(), p.Purpose, p.Subject, nuevo, grantTTL); err != nil {
		t.Errorf("con el código nuevo: %v", err)
	}
}

func TestConfirmConCodigoVencidoDaCodigoInvalido(t *testing.T) {
	h := newHarness(t)
	p := pedido()
	h.engine.Issue(t.Context(), p)
	code := h.ultimoEmail(t).Code

	h.clock.advance(ajustes.CodeTTL)
	if _, err := h.engine.Confirm(t.Context(), p.Purpose, p.Subject, code, grantTTL); !errors.Is(err, domain.ErrInvalidCode) {
		t.Fatalf("error = %v, se esperaba ErrInvalidCode", err)
	}
}

// Los cinco motivos son el mismo error: ni el tipo ni el texto los distinguen.
func TestConfirmNoDistingueLosMotivosDelRechazo(t *testing.T) {
	arma := func(t *testing.T, fn func(h *harness, p emailchallenge.IssueParams, code string) (subject, submitted string)) error {
		h := newHarness(t)
		p := pedido()
		h.engine.Issue(t.Context(), p)
		subject, submitted := fn(h, p, h.ultimoEmail(t).Code)
		_, err := h.engine.Confirm(t.Context(), p.Purpose, subject, submitted, grantTTL)
		return err
	}

	casos := map[string]func(h *harness, p emailchallenge.IssueParams, code string) (string, string){
		"incorrecto": func(h *harness, p emailchallenge.IssueParams, code string) (string, string) {
			return p.Subject, codigoDistintoDe(code)
		},
		"inexistente": func(h *harness, p emailchallenge.IssueParams, code string) (string, string) {
			return "otro@vinculovial.ar", code
		},
		"mal formado": func(h *harness, p emailchallenge.IssueParams, code string) (string, string) {
			return p.Subject, "12ab56"
		},
		"vencido": func(h *harness, p emailchallenge.IssueParams, code string) (string, string) {
			h.clock.advance(time.Hour)
			return p.Subject, code
		},
	}

	var primero error
	for name, fn := range casos {
		err := arma(t, fn)
		if !errors.Is(err, domain.ErrInvalidCode) {
			t.Fatalf("%s: %v, se esperaba ErrInvalidCode", name, err)
		}
		if primero == nil {
			primero = err
		}
		if err.Error() != primero.Error() {
			t.Errorf("%s: el texto del error (%q) difiere del de otro motivo (%q)", name, err, primero)
		}
	}
}

func TestConfirmConCodigoMalFormadoNoTocaLaBase(t *testing.T) {
	h := newHarness(t)

	for _, code := range []string{"", "12345", "1234567", "abcdef", "12 456"} {
		if _, err := h.engine.Confirm(t.Context(), domain.EmailChallengePurposeEmailVerification, "a@b.co", code, grantTTL); !errors.Is(err, domain.ErrInvalidCode) {
			t.Errorf("code %q: %v, se esperaba ErrInvalidCode", code, err)
		}
	}
	if h.repo.Mutations() != 0 {
		t.Errorf("se consultó la base %d veces con códigos mal formados", h.repo.Mutations())
	}
}

func TestConfirmRechazaPedidosIncompletos(t *testing.T) {
	h := newHarness(t)
	if _, err := h.engine.Confirm(t.Context(), "OTRO", "s", "123456", grantTTL); err == nil {
		t.Error("propósito inválido aceptado")
	}
	if _, err := h.engine.Confirm(t.Context(), domain.EmailChallengePurposeEmailVerification, "", "123456", grantTTL); err == nil {
		t.Error("subject vacío aceptado")
	}
	if _, err := h.engine.Confirm(t.Context(), domain.EmailChallengePurposeEmailVerification, "s", "123456", 0); err == nil {
		t.Error("vida del grant en cero aceptada")
	}
}

// Una base caída no es "código inválido": es un 503, y no descuenta nada.
func TestConfirmConLaBaseCaidaNoDiceCodigoInvalido(t *testing.T) {
	h := newHarness(t)
	p := pedido()
	h.engine.Issue(t.Context(), p)
	code := h.ultimoEmail(t).Code

	h.repo.Err = domain.ErrDatabaseUnavailable
	_, err := h.engine.Confirm(t.Context(), p.Purpose, p.Subject, code, grantTTL)

	if !errors.Is(err, domain.ErrDatabaseUnavailable) || errors.Is(err, domain.ErrInvalidCode) {
		t.Fatalf("error = %v, se esperaba ErrDatabaseUnavailable", err)
	}
}

func TestConfirmSiFallaLaGeneracionDelGrantNoConsumeElCodigo(t *testing.T) {
	boom := errors.New("sin entropía")
	h := newHarness(t)
	p := pedido()
	h.engine.Issue(t.Context(), p)
	code := h.ultimoEmail(t).Code

	// Se reconstruye el motor con un codec que falla al emitir el grant, sobre el
	// mismo repositorio.
	roto, err := emailchallenge.New(emailchallenge.Deps{
		Challenges: h.repo, Codec: codecQueFalla{EmailCodeCodec: h.codec, grantErr: boom},
		Settings: ajustes, Now: h.clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := roto.Confirm(t.Context(), p.Purpose, p.Subject, code, grantTTL); !errors.Is(err, boom) {
		t.Fatalf("error = %v, se esperaba el de la fuente aleatoria", err)
	}
	if h.desafio(p).CodeHMAC == "" {
		t.Error("el código se consumió pese a que no se pudo emitir el grant")
	}
	if _, err := h.engine.Confirm(t.Context(), p.Purpose, p.Subject, code, grantTTL); err != nil {
		t.Errorf("el código debería seguir sirviendo: %v", err)
	}
}

func TestNewValidaLasDependenciasYLosParametros(t *testing.T) {
	h := newHarness(t)
	base := func() emailchallenge.Deps {
		return emailchallenge.Deps{Challenges: h.repo, Codec: h.codec, Settings: ajustes}
	}

	if _, err := emailchallenge.New(base()); err != nil {
		t.Fatalf("configuración válida: %v", err)
	}

	casos := map[string]func(*emailchallenge.Deps){
		"sin repositorio":          func(d *emailchallenge.Deps) { d.Challenges = nil },
		"sin codec":                func(d *emailchallenge.Deps) { d.Codec = nil },
		"vida del código en cero":  func(d *emailchallenge.Deps) { d.Settings.CodeTTL = 0 },
		"sin intentos":             func(d *emailchallenge.Deps) { d.Settings.MaxCodeAttempts = 0 },
		"reenvío en cero":          func(d *emailchallenge.Deps) { d.Settings.ResendInterval = 0 },
		"tope diario en cero":      func(d *emailchallenge.Deps) { d.Settings.MaxSendsPerDay = 0 },
		"vida del código negativa": func(d *emailchallenge.Deps) { d.Settings.CodeTTL = -time.Minute },
	}
	for name, tune := range casos {
		t.Run(name, func(t *testing.T) {
			d := base()
			tune(&d)
			if _, err := emailchallenge.New(d); err == nil {
				t.Fatal("New no rechazó la configuración inválida")
			}
		})
	}
}

// Sin Logger ni Now explícitos el motor funciona.
func TestNewAplicaValoresPorDefecto(t *testing.T) {
	h := newHarness(t)
	e, err := emailchallenge.New(emailchallenge.Deps{Challenges: h.repo, Codec: h.codec, Settings: ajustes})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Issue(t.Context(), pedido()); err != nil {
		t.Errorf("Issue con los valores por defecto: %v", err)
	}
}
