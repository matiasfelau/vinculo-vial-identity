package signup_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/signup"
	"github.com/matiasfelau/vinculo-vial-identity/internal/validation"
)

// selfieBytes es el contenido mínimo que pasa la validación de formato: la
// cabecera PNG y nada más. El validador solo mira los primeros bytes, así que
// no hace falta un PNG real y decodificable.
var selfieBytes = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x01, 0x02, 0x03}

var validSelfieBase64 = base64.StdEncoding.EncodeToString(selfieBytes)

// validPayload es un payload enteramente válido. El sexo va en minúscula a
// propósito, para que la vía feliz también ejercite NormalizeSexo de punta a
// punta y no solo en los tests de la capa de validación.
var validPayload = fmt.Sprintf(
	`{"email":"Vecino@VinculoVial.AR","password":"Rosario-2026!clave","dni":"30.123.456","tramite":"12345678901","sexo":"f","selfie":%q}`,
	validSelfieBase64,
)

const (
	// Las dos piezas del mensaje HPKE son opacas para el servicio: quien las
	// interpreta es el descifrador, que acá está doblado.
	ephemeralPublicKey = "clave-efimera-opaca"
	ciphertext         = "ciphertext-opaco"
)

// fijo es el instante que devuelve el reloj inyectado, para que las marcas de
// tiempo del usuario sean verificables.
var fijo = time.Date(2026, 8, 12, 15, 30, 0, 0, time.UTC)

type harness struct {
	svc       *signup.Service
	decryptor *decryptorMock
	indexer   *indexerMock
	cipher    *cipherMock
	hasher    *hasherMock
	renaper   *renaperMock
	repo      *repositoryMock
	logs      *strings.Builder
}

func newHarness(t *testing.T, tune ...func(*signup.Deps)) *harness {
	t.Helper()

	h := &harness{
		decryptor: &decryptorMock{plaintext: []byte(validPayload)},
		indexer:   &indexerMock{},
		cipher:    &cipherMock{},
		hasher:    &hasherMock{},
		renaper:   &renaperMock{verified: true},
		repo:      &repositoryMock{},
		logs:      &strings.Builder{},
	}

	deps := signup.Deps{
		Decryptor: h.decryptor,
		Indexer:   h.indexer,
		Cipher:    h.cipher,
		Hasher:    h.hasher,
		Renaper:   h.renaper,
		Users:     h.repo,
		Logger:    slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now:       func() time.Time { return fijo },
	}
	for _, f := range tune {
		f(&deps)
	}

	svc, err := signup.New(deps)
	if err != nil {
		t.Fatalf("no se pudo construir el servicio: %v", err)
	}
	h.svc = svc

	return h
}

func TestSignUpFelizPersisteYPublica(t *testing.T) {
	h := newHarness(t)

	id, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext))
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if id == uuid.Nil {
		t.Fatal("se esperaba el identificador del usuario creado")
	}

	if h.repo.calls != 1 {
		t.Fatalf("se persistió %d veces, se esperaba 1", h.repo.calls)
	}
	u := h.repo.last()

	if u.ID != id {
		t.Errorf("id devuelto = %v, el persistido es %v", id, u.ID)
	}
	if u.AccountStatus != domain.AccountStatusActive {
		t.Errorf("account status = %q, se esperaba %q", u.AccountStatus, domain.AccountStatusActive)
	}
	if !u.CreatedAt.Equal(fijo) {
		t.Errorf("created at = %v, se esperaba el reloj inyectado %v", u.CreatedAt, fijo)
	}
	if h.renaper.calls != 1 {
		t.Errorf("se consultó RENAPER %d veces, se esperaba 1", h.renaper.calls)
	}
}

// Las dos piezas llegan tal cual al descifrador, sin manipulación previa y cada
// una en su argumento.
func TestSignUpPasaLasDosPiezasSinTocarlas(t *testing.T) {
	h := newHarness(t)

	if _, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext)); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if got := string(h.decryptor.ephemeralPublicKey); got != ephemeralPublicKey {
		t.Errorf("clave efímera = %q, se esperaba %q", got, ephemeralPublicKey)
	}
	if got := string(h.decryptor.ciphertext); got != ciphertext {
		t.Errorf("ciphertext = %q, se esperaba %q", got, ciphertext)
	}
}

// La normalización tiene que ocurrir antes de derivar y antes de consultar
// RENAPER: si no, 30.123.456 y 30123456 producirían Blind Index distintos y la
// misma persona entraría dos veces, Vecino@… y vecino@… esquivarían el índice
// único de email, y "f" llegaría a RENAPER en lugar de "F".
func TestSignUpNormalizaAntesDeDerivar(t *testing.T) {
	h := newHarness(t)

	if _, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext)); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if want := []string{"30123456"}; !slices.Equal(h.indexer.values, want) {
		t.Errorf("el Blind Index se calculó sobre %v, se esperaba %v", h.indexer.values, want)
	}
	if want := []string{"30123456"}; !slices.Equal(h.cipher.plaintexts, want) {
		t.Errorf("se cifró %v, se esperaba %v", h.cipher.plaintexts, want)
	}
	if got := h.repo.last().Email; got != "vecino@vinculovial.ar" {
		t.Errorf("email persistido = %q, se esperaba en minúscula", got)
	}
	if want := []string{"F"}; !slices.Equal(h.renaper.sexo, want) {
		t.Errorf("RENAPER recibió sexo = %v, se esperaba %v", h.renaper.sexo, want)
	}
}

// RENAPER recibe exactamente el DNI, el trámite, el sexo y la selfie del
// payload, ya normalizados, sin que el servicio los transforme de más.
func TestSignUpConsultaRenaperConLosDatosCorrectos(t *testing.T) {
	h := newHarness(t)

	if _, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext)); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if want := []string{"30123456"}; !slices.Equal(h.renaper.dni, want) {
		t.Errorf("RENAPER recibió dni = %v, se esperaba %v", h.renaper.dni, want)
	}
	if want := []string{"12345678901"}; !slices.Equal(h.renaper.tramite, want) {
		t.Errorf("RENAPER recibió tramite = %v, se esperaba %v", h.renaper.tramite, want)
	}
	if len(h.renaper.selfie) != 1 || string(h.renaper.selfie[0]) != string(selfieBytes) {
		t.Errorf("RENAPER recibió selfie = %v, se esperaba %v", h.renaper.selfie, selfieBytes)
	}
}

// Ninguna columna puede terminar guardando el DNI, el trámite, el sexo, la
// selfie ni la contraseña en claro. domain.User no tiene ni siquiera un campo
// donde eso pudiera colarse: la garantía es estructural, no solo de valor.
func TestSignUpNoPersisteDatosEnClaro(t *testing.T) {
	h := newHarness(t)

	if _, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext)); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	u := h.repo.last()

	if u.DNIHashed == "30123456" {
		t.Error("dni_hashed no puede ser el DNI en claro")
	}
	if u.DNIEncrypted == "30123456" {
		t.Error("dni_encrypted no puede ser el DNI en claro")
	}
	if u.PasswordHash == "Rosario-2026!clave" {
		t.Error("la contraseña se persistió sin derivar")
	}
	if u.DNIHashed == "" || u.DNIEncrypted == "" || u.PasswordHash == "" {
		t.Error("los tres derivados criptográficos deben estar presentes")
	}
}

// El DNI, el trámite, el sexo, la selfie y la contraseña solo pueden aparecer
// en el log si alguien los loguea acá; el servicio registra únicamente el
// identificador opaco.
func TestSignUpNoLogueaDatosSensibles(t *testing.T) {
	h := newHarness(t)

	if _, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext)); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	logs := h.logs.String()
	secretos := []string{
		"30123456", "30.123.456", "Rosario-2026!clave", "vecino@vinculovial.ar",
		"12345678901", validSelfieBase64,
	}
	for _, secreto := range secretos {
		if strings.Contains(logs, secreto) {
			t.Errorf("el log filtra %q: %s", secreto, logs)
		}
	}
}

func TestSignUpPropagaElFalloDeDescifrado(t *testing.T) {
	h := newHarness(t)
	h.decryptor.err = domain.ErrInvalidCryptogram

	_, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext))

	if !errors.Is(err, domain.ErrInvalidCryptogram) {
		t.Fatalf("error = %v, se esperaba ErrInvalidCryptogram", err)
	}
	// Nada se deriva ni se persiste si el criptograma no abrió.
	if h.renaper.calls != 0 || h.hasher.calls != 0 || h.repo.calls != 0 {
		t.Error("no debe hacerse trabajo alguno tras un fallo de descifrado")
	}
}

func TestSignUpRechazaPayloadNoJSON(t *testing.T) {
	h := newHarness(t)
	h.decryptor.plaintext = []byte("esto no es json")

	_, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext))

	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("error = %v, se esperaba ErrInvalidInput", err)
	}
	if h.repo.calls != 0 {
		t.Error("no debe persistirse nada con un payload ilegible")
	}
}

func TestSignUpRechazaDatosInvalidos(t *testing.T) {
	valida := fmt.Sprintf(`"tramite":"12345678901","sexo":"F","selfie":%q`, validSelfieBase64)

	cases := map[string]string{
		"email inválido":     fmt.Sprintf(`{"email":"no-es-un-email","password":"Rosario-2026!clave","dni":"30123456",%s}`, valida),
		"DNI corto":          fmt.Sprintf(`{"email":"vecino@vinculovial.ar","password":"Rosario-2026!clave","dni":"123",%s}`, valida),
		"DNI con letras":     fmt.Sprintf(`{"email":"vecino@vinculovial.ar","password":"Rosario-2026!clave","dni":"3012345A",%s}`, valida),
		"contraseña débil":   fmt.Sprintf(`{"email":"vecino@vinculovial.ar","password":"corta","dni":"30123456",%s}`, valida),
		"campos ausentes":    `{}`,
		"contraseña con DNI": fmt.Sprintf(`{"email":"vecino@vinculovial.ar","password":"Rosario30123456!","dni":"30123456",%s}`, valida),
		"trámite corto": fmt.Sprintf(
			`{"email":"vecino@vinculovial.ar","password":"Rosario-2026!clave","dni":"30123456","tramite":"123","sexo":"F","selfie":%q}`,
			validSelfieBase64,
		),
		"sexo inválido": fmt.Sprintf(
			`{"email":"vecino@vinculovial.ar","password":"Rosario-2026!clave","dni":"30123456","tramite":"12345678901","sexo":"Z","selfie":%q}`,
			validSelfieBase64,
		),
		"selfie no es base64": `{"email":"vecino@vinculovial.ar","password":"Rosario-2026!clave","dni":"30123456","tramite":"12345678901","sexo":"F","selfie":"no-es-base64-!!!"}`,
		"selfie sin magic bytes de imagen": fmt.Sprintf(
			`{"email":"vecino@vinculovial.ar","password":"Rosario-2026!clave","dni":"30123456","tramite":"12345678901","sexo":"F","selfie":%q}`,
			base64.StdEncoding.EncodeToString([]byte("esto no es una imagen")),
		),
	}

	for name, plaintext := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.decryptor.plaintext = []byte(plaintext)

			_, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext))

			if !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("error = %v, se esperaba ErrInvalidInput", err)
			}

			var verrs validation.Errors
			if !errors.As(err, &verrs) || len(verrs) == 0 {
				t.Errorf("se esperaba el detalle por campo, error = %v", err)
			}

			// La validación local corta antes de RENAPER y antes del trabajo caro:
			// no tiene sentido gastar una consulta externa en un payload que se
			// iba a rechazar de todos modos.
			if h.renaper.calls != 0 || h.hasher.calls != 0 || h.cipher.calls != 0 || h.repo.calls != 0 {
				t.Error("no debe derivarse, consultarse ni persistirse nada con datos inválidos")
			}
		})
	}
}

// Caso dedicado, con el resto del payload válido: aísla el rechazo cuando
// RENAPER responde que no puede confirmar la identidad.
func TestSignUpPropagaIdentidadNoVerificada(t *testing.T) {
	h := newHarness(t)
	h.renaper.verified = false

	_, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext))

	if !errors.Is(err, domain.ErrIdentityNotVerified) {
		t.Fatalf("error = %v, se esperaba ErrIdentityNotVerified", err)
	}
	// La identidad no se confirmó: no hay hash de contraseña que calcular ni
	// alta que persistir.
	if h.hasher.calls != 0 {
		t.Error("no debe derivarse la contraseña si RENAPER no verificó la identidad")
	}
	if h.repo.calls != 0 {
		t.Error("no debe persistirse un alta sin identidad verificada")
	}
}

// Un fallo al consultar RENAPER (caído, timeout) no es lo mismo que una
// identidad no verificada: es un problema de la dependencia externa, no un
// veredicto, y no debe mapearse a ErrIdentityNotVerified.
func TestSignUpPropagaElFalloDeRenaper(t *testing.T) {
	h := newHarness(t)
	falloRenaper := errors.New("renaper no responde")
	h.renaper.err = falloRenaper

	_, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext))

	if !errors.Is(err, falloRenaper) {
		t.Fatalf("error = %v, se esperaba el fallo de RENAPER", err)
	}
	if errors.Is(err, domain.ErrIdentityNotVerified) {
		t.Error("un fallo de la consulta no es un veredicto de identidad no verificada")
	}
	if h.repo.calls != 0 {
		t.Error("no debe persistirse un alta si no se pudo consultar RENAPER")
	}
}

func TestSignUpPropagaElDuplicado(t *testing.T) {
	h := newHarness(t)
	h.repo.err = domain.ErrDuplicateUser

	_, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext))

	if !errors.Is(err, domain.ErrDuplicateUser) {
		t.Fatalf("error = %v, se esperaba ErrDuplicateUser", err)
	}
}

func TestSignUpPropagaFallosDeLosPrimitivos(t *testing.T) {
	falloCifrado := errors.New("no se pudo cifrar")
	falloHash := errors.New("no se pudo derivar")

	t.Run("cifrado at-rest", func(t *testing.T) {
		h := newHarness(t)
		h.cipher.err = falloCifrado

		_, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext))

		if !errors.Is(err, falloCifrado) {
			t.Fatalf("error = %v, se esperaba el fallo del cifrador", err)
		}
		if h.repo.calls != 0 {
			t.Error("no debe persistirse un usuario sin DNI cifrado")
		}
	})

	t.Run("hash de contraseña", func(t *testing.T) {
		h := newHarness(t)
		h.hasher.err = falloHash

		_, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext))

		if !errors.Is(err, falloHash) {
			t.Fatalf("error = %v, se esperaba el fallo del hasher", err)
		}
		if h.repo.calls != 0 {
			t.Error("no debe persistirse un usuario sin hash de contraseña")
		}
	})
}

func TestNewExigeTodasLasDependencias(t *testing.T) {
	cases := map[string]func(*signup.Deps){
		"sin descifrador": func(d *signup.Deps) { d.Decryptor = nil },
		"sin indexador":   func(d *signup.Deps) { d.Indexer = nil },
		"sin cifrador":    func(d *signup.Deps) { d.Cipher = nil },
		"sin hasher":      func(d *signup.Deps) { d.Hasher = nil },
		"sin renaper":     func(d *signup.Deps) { d.Renaper = nil },
		"sin repositorio": func(d *signup.Deps) { d.Users = nil },
	}

	for name, romper := range cases {
		t.Run(name, func(t *testing.T) {
			deps := signup.Deps{
				Decryptor: &decryptorMock{},
				Indexer:   &indexerMock{},
				Cipher:    &cipherMock{},
				Hasher:    &hasherMock{},
				Renaper:   &renaperMock{verified: true},
				Users:     &repositoryMock{},
			}
			romper(&deps)

			if _, err := signup.New(deps); err == nil {
				t.Error("se esperaba un error de cableado en la construcción")
			}
		})
	}
}

func TestNewAplicaValoresPorDefecto(t *testing.T) {
	svc, err := signup.New(signup.Deps{
		Decryptor: &decryptorMock{plaintext: []byte(validPayload)},
		Indexer:   &indexerMock{},
		Cipher:    &cipherMock{},
		Hasher:    &hasherMock{},
		Renaper:   &renaperMock{verified: true},
		Users:     &repositoryMock{},
	})
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	// Sin Logger ni Now explícitos el servicio debe seguir funcionando.
	if _, err := svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext)); err != nil {
		t.Errorf("error inesperado: %v", err)
	}
}

func TestSignUpEsConcurrente(t *testing.T) {
	h := newHarness(t, func(d *signup.Deps) {
		d.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	})

	const goroutines = 16
	errs := make(chan error, goroutines)
	for range goroutines {
		go func() {
			_, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext))
			errs <- err
		}()
	}
	for range goroutines {
		if err := <-errs; err != nil {
			t.Fatalf("fallo en ejecución concurrente: %v", err)
		}
	}

	if h.repo.calls != goroutines {
		t.Errorf("se persistieron %d altas, se esperaban %d", h.repo.calls, goroutines)
	}
}
