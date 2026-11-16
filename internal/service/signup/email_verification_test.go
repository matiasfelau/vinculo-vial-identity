package signup_test

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/signup"
)

// US-13: el alta valida el token de verificación de email antes de RENAPER y lo
// consume en la transacción que crea el usuario.

// emailDelPayload es el email del validPayload ya normalizado: el subject del
// desafío se deriva de este valor.
const emailDelPayload = "vecino@vinculovial.ar"

func payloadConToken(token string) []byte {
	return []byte(strings.Replace(validPayload, `"selfie":`,
		fmt.Sprintf(`"email_verification_token":%q,"selfie":`, token), 1))
}

// conGrant deja en el repositorio de desafíos un grant de verificación y devuelve
// su token. tune ajusta el desafío antes de guardarlo.
func (h *harness) conGrant(t *testing.T, email string, tune ...func(*domain.EmailChallenge)) string {
	t.Helper()

	token, hash, err := h.codec.NewGrant()
	if err != nil {
		t.Fatalf("no se pudo generar el grant: %v", err)
	}
	expira := fijo.Add(30 * time.Minute)
	c := domain.EmailChallenge{
		ID:             uuid.New(),
		Purpose:        domain.EmailChallengePurposeEmailVerification,
		SubjectHMAC:    h.codec.SubjectHMAC(domain.EmailChallengePurposeEmailVerification, email),
		GrantHash:      hash,
		GrantExpiresAt: &expira,
		CreatedAt:      fijo,
	}
	for _, f := range tune {
		f(&c)
	}
	h.challenges.Put(c)
	return token
}

func exigiendoVerificacion(d *signup.Deps) { d.RequireEmailVerification = true }

func TestSignUpConTokenVigenteMarcaElEmailVerificadoYConsumeElGrant(t *testing.T) {
	h := newHarness(t, exigiendoVerificacion)
	token := h.conGrant(t, emailDelPayload)
	h.decryptor.plaintext = payloadConToken(token)

	id, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext))
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	u := h.repo.last()
	if u.ID != id {
		t.Fatalf("id = %v, el persistido es %v", id, u.ID)
	}
	if u.EmailVerifiedAt == nil || !u.EmailVerifiedAt.Equal(fijo) {
		t.Errorf("email_verified_at = %v, se esperaba %v", u.EmailVerifiedAt, fijo)
	}

	if len(h.repo.grants) != 1 || h.repo.grants[0] == nil {
		t.Fatalf("el repositorio recibió %v, se esperaba el grant a consumir", h.repo.grants)
	}
	g := h.repo.grants[0]
	if g.Purpose != domain.EmailChallengePurposeEmailVerification {
		t.Errorf("propósito = %q", g.Purpose)
	}
	if g.GrantHash != h.codec.GrantHash(token) {
		t.Error("el grant que se consume no es el del token recibido")
	}
	if g.SubjectHMAC != h.codec.SubjectHMAC(domain.EmailChallengePurposeEmailVerification, emailDelPayload) {
		t.Error("el grant se consume atado a otro email")
	}
	if !g.Now.Equal(fijo) {
		t.Errorf("now = %v, se esperaba el reloj inyectado", g.Now)
	}
}

// El token se valida antes de gastar una consulta a RENAPER.
func TestSignUpSinTokenCuandoSeExigeNoConsultaRenaper(t *testing.T) {
	h := newHarness(t, exigiendoVerificacion)

	_, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext))
	if !errors.Is(err, domain.ErrEmailNotVerified) {
		t.Fatalf("error = %v, se esperaba ErrEmailNotVerified", err)
	}
	if h.renaper.calls != 0 {
		t.Errorf("se consultó RENAPER %d veces, se esperaba 0", h.renaper.calls)
	}
	if h.repo.calls != 0 {
		t.Errorf("se persistió %d veces, se esperaba 0", h.repo.calls)
	}
}

func TestSignUpConTokenInvalidoDaEmailNoVerificado(t *testing.T) {
	futuro := fijo.Add(time.Hour)
	pasado := fijo.Add(-time.Minute)
	usado := fijo

	casos := []struct {
		name  string
		setup func(h *harness) string
	}{
		{"token desconocido", func(h *harness) string { return "token-que-nadie-emitio" }},
		{"token de otro email", func(h *harness) string { return h.conGrant(t, "otra@persona.ar") }},
		{"token vencido", func(h *harness) string {
			return h.conGrant(t, emailDelPayload, func(c *domain.EmailChallenge) { c.GrantExpiresAt = &pasado })
		}},
		{"token ya usado", func(h *harness) string {
			return h.conGrant(t, emailDelPayload, func(c *domain.EmailChallenge) { c.ConsumedAt = &usado })
		}},
		{"token de recuperación de contraseña", func(h *harness) string {
			return h.conGrant(t, emailDelPayload, func(c *domain.EmailChallenge) {
				c.Purpose = domain.EmailChallengePurposePasswordReset
				c.SubjectHMAC = h.codec.SubjectHMAC(domain.EmailChallengePurposePasswordReset, emailDelPayload)
				c.GrantExpiresAt = &futuro
			})
		}},
		{"token desmesurado", func(h *harness) string { return strings.Repeat("a", 4096) }},
	}

	for _, tc := range casos {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, exigiendoVerificacion)
			h.decryptor.plaintext = payloadConToken(tc.setup(h))

			_, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext))
			if !errors.Is(err, domain.ErrEmailNotVerified) {
				t.Fatalf("error = %v, se esperaba ErrEmailNotVerified", err)
			}
			if h.renaper.calls != 0 || h.repo.calls != 0 {
				t.Errorf("renaper=%d create=%d, se esperaba 0 y 0", h.renaper.calls, h.repo.calls)
			}
		})
	}
}

// Un token desmesurado se descarta sin tocar la base.
func TestSignUpConTokenDesmesuradoNoConsultaLaBase(t *testing.T) {
	h := newHarness(t, exigiendoVerificacion)
	h.challenges.Err = errors.New("no debería consultarse")
	h.decryptor.plaintext = payloadConToken(strings.Repeat("a", 4096))

	_, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext))
	if !errors.Is(err, domain.ErrEmailNotVerified) {
		t.Fatalf("error = %v, se esperaba ErrEmailNotVerified", err)
	}
}

// Una base caída no es "email no verificado": es un 503, no un 400.
func TestSignUpConLaBaseCaidaNoDiceQueElEmailNoEstaVerificado(t *testing.T) {
	h := newHarness(t, exigiendoVerificacion)
	h.challenges.Err = domain.ErrDatabaseUnavailable
	h.decryptor.plaintext = payloadConToken("cualquiera")

	_, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext))
	if !errors.Is(err, domain.ErrDatabaseUnavailable) {
		t.Fatalf("error = %v, se esperaba ErrDatabaseUnavailable", err)
	}
	if errors.Is(err, domain.ErrEmailNotVerified) {
		t.Error("una base caída se tradujo a ErrEmailNotVerified")
	}
}

// Si entre la validación temprana y la transacción el token dejó de servir (otra
// alta lo gastó primero), el repositorio lo rechaza y el alta falla igual.
func TestSignUpSiElRepositorioRechazaElGrantElAltaFalla(t *testing.T) {
	h := newHarness(t, exigiendoVerificacion)
	h.decryptor.plaintext = payloadConToken(h.conGrant(t, emailDelPayload))
	h.repo.err = domain.ErrEmailNotVerified

	_, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext))
	if !errors.Is(err, domain.ErrEmailNotVerified) {
		t.Fatalf("error = %v, se esperaba ErrEmailNotVerified", err)
	}
}

// SIGNUP_REQUIRE_EMAIL_VERIFICATION=false: el alta sin token sigue funcionando,
// y la cuenta nace sin email verificado.
func TestSignUpSinTokenYSinExigirloCreaLaCuentaSinVerificar(t *testing.T) {
	h := newHarness(t)

	if _, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext)); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if u := h.repo.last(); u.EmailVerifiedAt != nil {
		t.Errorf("email_verified_at = %v, se esperaba nil", u.EmailVerifiedAt)
	}
	if h.repo.grants[0] != nil {
		t.Errorf("se pidió consumir un grant sin que hubiera token: %+v", h.repo.grants[0])
	}
}

// Aunque no se exija, un token que llega se valida y se consume: así el
// Frontend que ya lo manda obtiene un email verificado en cualquier entorno.
func TestSignUpConTokenValidoSinExigirloLoConsumeIgual(t *testing.T) {
	h := newHarness(t)
	h.decryptor.plaintext = payloadConToken(h.conGrant(t, emailDelPayload))

	if _, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext)); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if u := h.repo.last(); u.EmailVerifiedAt == nil {
		t.Error("el email quedó sin verificar pese al token válido")
	}
	if h.repo.grants[0] == nil {
		t.Error("el grant no se entregó al repositorio para consumirlo")
	}
}

// ...y un token que llega y no sirve se rechaza aunque no se exija: no se ignora
// en silencio.
func TestSignUpConTokenInvalidoSinExigirloIgualFalla(t *testing.T) {
	h := newHarness(t)
	h.decryptor.plaintext = payloadConToken("token-que-nadie-emitio")

	_, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext))
	if !errors.Is(err, domain.ErrEmailNotVerified) {
		t.Fatalf("error = %v, se esperaba ErrEmailNotVerified", err)
	}
}

// Ni el token ni el email viajan a un log.
func TestSignUpNoLogueaElTokenDeVerificacion(t *testing.T) {
	h := newHarness(t, exigiendoVerificacion)
	token := h.conGrant(t, emailDelPayload)
	h.decryptor.plaintext = payloadConToken(token)

	if _, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext)); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if out := h.logs.String(); strings.Contains(out, token) || strings.Contains(out, emailDelPayload) {
		t.Errorf("el log contiene el token o el email:\n%s", out)
	}
}

func TestNewExigeLosColaboradoresDeLaVerificacionDeEmail(t *testing.T) {
	casos := map[string]func(*signup.Deps){
		"sin repositorio de desafíos": func(d *signup.Deps) { d.Challenges = nil },
		"sin codec":                   func(d *signup.Deps) { d.Codec = nil },
	}
	for name, tune := range casos {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			deps := signup.Deps{
				Decryptor: h.decryptor, Indexer: h.indexer, Cipher: h.cipher, Hasher: h.hasher,
				Renaper: h.renaper, Users: h.repo, Challenges: h.challenges, Codec: h.codec,
				TermsCurrentVersion: versionVigente,
				Logger:              slog.Default(),
			}
			tune(&deps)
			if _, err := signup.New(deps); err == nil {
				t.Fatal("New no rechazó la dependencia faltante")
			}
		})
	}
}
