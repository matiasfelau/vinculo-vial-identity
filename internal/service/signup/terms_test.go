package signup_test

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/signup"
)

// US-19: el alta comprueba la versión de los términos antes de RENAPER y, si
// coincide, la guarda con la fecha en el mismo Create que inserta el usuario.

const versionVigente = "1.0"

func payloadConTerminos(version string) []byte {
	return []byte(strings.Replace(validPayload, `"selfie":`,
		fmt.Sprintf(`"terms_version":%q,"selfie":`, version), 1))
}

func exigiendoTerminos(d *signup.Deps) { d.RequireTerms = true }

func TestSignUpConLaVersionVigenteGuardaLaVersionYLaFecha(t *testing.T) {
	h := newHarness(t, exigiendoTerminos)
	h.decryptor.plaintext = payloadConTerminos(versionVigente)

	if _, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext)); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	u := h.repo.last()
	if u.TermsVersion != versionVigente {
		t.Errorf("terms_version = %q, se esperaba %q", u.TermsVersion, versionVigente)
	}
	if u.TermsAcceptedAt == nil || !u.TermsAcceptedAt.Equal(fijo) {
		t.Errorf("terms_accepted_at = %v, se esperaba el reloj inyectado %v", u.TermsAcceptedAt, fijo)
	}
	if h.repo.calls != 1 {
		t.Errorf("se persistió %d veces, se esperaba 1", h.repo.calls)
	}
}

// Otra versión —anterior, futura, con otra forma o con espacios— no es la vigente.
// Tiene que cortar antes de RENAPER y de persistir, y no dejar nada guardado.
func TestSignUpConOtraVersionDaTermsNotAcceptedSinConsultarRenaper(t *testing.T) {
	casos := map[string]string{
		"versión anterior": "0.9",
		"versión futura":   "2.0",
		"otra forma":       "1",
		"con espacios":     " 1.0",
		"en mayúsculas":    "V1.0",
		"texto arbitrario": strings.Repeat("x", 500),
	}
	for name, version := range casos {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, exigiendoTerminos)
			h.decryptor.plaintext = payloadConTerminos(version)

			_, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext))

			if !errors.Is(err, domain.ErrTermsNotAccepted) {
				t.Fatalf("error = %v, se esperaba ErrTermsNotAccepted", err)
			}
			if h.renaper.calls != 0 {
				t.Errorf("se consultó RENAPER %d veces, se esperaba 0", h.renaper.calls)
			}
			if h.repo.calls != 0 {
				t.Errorf("se persistió %d veces, se esperaba 0", h.repo.calls)
			}
		})
	}
}

func TestSignUpSinElCampoCuandoSeExigeDaTermsNotAcceptedSinConsultarRenaper(t *testing.T) {
	h := newHarness(t, exigiendoTerminos) // validPayload no trae terms_version

	_, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext))

	if !errors.Is(err, domain.ErrTermsNotAccepted) {
		t.Fatalf("error = %v, se esperaba ErrTermsNotAccepted", err)
	}
	if h.renaper.calls != 0 || h.repo.calls != 0 {
		t.Errorf("renaper = %d, persistencias = %d: se esperaba 0 y 0", h.renaper.calls, h.repo.calls)
	}
}

// Un campo presente pero vacío es lo mismo que uno ausente.
func TestSignUpConElCampoVacioCuandoSeExigeDaTermsNotAccepted(t *testing.T) {
	h := newHarness(t, exigiendoTerminos)
	h.decryptor.plaintext = payloadConTerminos("")

	_, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext))

	if !errors.Is(err, domain.ErrTermsNotAccepted) {
		t.Fatalf("error = %v, se esperaba ErrTermsNotAccepted", err)
	}
}

// Con el flag apagado el campo no se exige: el alta sigue y la cuenta queda sin
// consentimiento registrado.
func TestSignUpConElFlagApagadoNoExigeElCampo(t *testing.T) {
	h := newHarness(t) // RequireTerms en false

	if _, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext)); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	u := h.repo.last()
	if u.TermsVersion != "" || u.TermsAcceptedAt != nil {
		t.Errorf("terms = (%q, %v), se esperaba sin consentimiento registrado", u.TermsVersion, u.TermsAcceptedAt)
	}
	if h.renaper.calls != 1 {
		t.Errorf("se consultó RENAPER %d veces, se esperaba 1", h.renaper.calls)
	}
}

// Con el flag apagado, si el campo llega con la versión vigente se registra
// igual: el flag relaja la exigencia, no el registro del consentimiento.
func TestSignUpConElFlagApagadoRegistraLaVersionSiLlega(t *testing.T) {
	h := newHarness(t)
	h.decryptor.plaintext = payloadConTerminos(versionVigente)

	if _, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext)); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	u := h.repo.last()
	if u.TermsVersion != versionVigente || u.TermsAcceptedAt == nil {
		t.Errorf("terms = (%q, %v), se esperaba la versión y la fecha", u.TermsVersion, u.TermsAcceptedAt)
	}
}

// Con el flag apagado, una versión equivocada tampoco se acepta: no se guarda un
// consentimiento a otro texto, ni se deja pasar un cliente desactualizado.
func TestSignUpConElFlagApagadoRechazaUnaVersionEquivocada(t *testing.T) {
	h := newHarness(t)
	h.decryptor.plaintext = payloadConTerminos("0.9")

	_, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext))

	if !errors.Is(err, domain.ErrTermsNotAccepted) {
		t.Fatalf("error = %v, se esperaba ErrTermsNotAccepted", err)
	}
	if h.renaper.calls != 0 || h.repo.calls != 0 {
		t.Errorf("renaper = %d, persistencias = %d: se esperaba 0 y 0", h.renaper.calls, h.repo.calls)
	}
}

// Los términos se rechazan antes que el token de email: no se gasta el desafío ni
// se mira la base de desafíos por un alta que no va a prosperar.
func TestSignUpRechazaLosTerminosAntesQueElTokenDeEmail(t *testing.T) {
	h := newHarness(t, exigiendoTerminos, exigiendoVerificacion)
	// Sin terms_version y sin token: manda el error de los términos.
	_, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext))

	if !errors.Is(err, domain.ErrTermsNotAccepted) {
		t.Fatalf("error = %v, se esperaba ErrTermsNotAccepted y no ErrEmailNotVerified", err)
	}
}

// La validación de formato va primero: un payload inválido sigue siendo
// ErrInvalidInput aunque tampoco traiga los términos.
func TestSignUpConPayloadInvalidoSigueDandoInvalidInput(t *testing.T) {
	h := newHarness(t, exigiendoTerminos)
	h.decryptor.plaintext = []byte(`{"email":"no-es-un-email"}`)

	_, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext))

	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("error = %v, se esperaba ErrInvalidInput", err)
	}
}

// La sanción heredada (US-11) no pisa el consentimiento: el repositorio la
// aplica sobre el mismo usuario y los términos siguen donde estaban.
func TestSignUpConSancionHeredadaConservaLosTerminos(t *testing.T) {
	h := newHarness(t, exigiendoTerminos)
	h.repo.inherit = &domain.SanctionCarryover{AccountStatus: domain.AccountStatusUnderReview, ReportCount: 1}
	h.decryptor.plaintext = payloadConTerminos(versionVigente)

	if _, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext)); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	u := h.repo.last()
	if u.TermsVersion != versionVigente || u.TermsAcceptedAt == nil {
		t.Errorf("terms = (%q, %v), se esperaba la versión y la fecha", u.TermsVersion, u.TermsAcceptedAt)
	}
}

func TestSignUpNoLogueaLaVersionDeLosTerminos(t *testing.T) {
	h := newHarness(t, exigiendoTerminos)
	h.decryptor.plaintext = payloadConTerminos("version-rarisima-7")

	_, _ = h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext))

	if out := h.logs.String(); strings.Contains(out, "version-rarisima-7") {
		t.Errorf("el log contiene la versión enviada por el cliente:\n%s", out)
	}
}

func TestNewExigeLaVersionVigenteDeLosTerminos(t *testing.T) {
	h := newHarness(t)
	_, err := signup.New(signup.Deps{
		Decryptor: h.decryptor, Indexer: h.indexer, Cipher: h.cipher, Hasher: h.hasher,
		Renaper: h.renaper, Users: h.repo, Challenges: h.challenges, Codec: h.codec,
		Logger: slog.Default(),
	})
	if err == nil {
		t.Fatal("New no rechazó la falta de TermsCurrentVersion")
	}
}
