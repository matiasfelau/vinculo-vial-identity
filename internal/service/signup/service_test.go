package signup_test

import (
	"errors"
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

const (
	validPayload = `{"email":"Vecino@VinculoVial.AR","password":"Rosario-2026!clave","dni":"30.123.456"}`
	// El criptograma es opaco para el servicio: quien lo interpreta es el
	// descifrador, que acá está doblado.
	cryptogram = "criptograma-opaco"
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
	repo      *repositoryMock
	publisher *publisherMock
	logs      *strings.Builder
}

func newHarness(t *testing.T, tune ...func(*signup.Deps)) *harness {
	t.Helper()

	h := &harness{
		decryptor: &decryptorMock{plaintext: []byte(validPayload)},
		indexer:   &indexerMock{},
		cipher:    &cipherMock{},
		hasher:    &hasherMock{},
		repo:      &repositoryMock{},
		publisher: &publisherMock{},
		logs:      &strings.Builder{},
	}

	deps := signup.Deps{
		Decryptor: h.decryptor,
		Indexer:   h.indexer,
		Cipher:    h.cipher,
		Hasher:    h.hasher,
		Users:     h.repo,
		Publisher: h.publisher,
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

	id, err := h.svc.SignUp(t.Context(), []byte(cryptogram))
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
	if h.publisher.calls != 1 {
		t.Errorf("se publicó %d veces, se esperaba 1", h.publisher.calls)
	}
}

// El criptograma llega tal cual al descifrador, sin manipulación previa.
func TestSignUpPasaElCriptogramaSinTocarlo(t *testing.T) {
	h := newHarness(t)

	if _, err := h.svc.SignUp(t.Context(), []byte(cryptogram)); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if got := string(h.decryptor.cryptogram); got != cryptogram {
		t.Errorf("criptograma = %q, se esperaba %q", got, cryptogram)
	}
}

// La normalización tiene que ocurrir antes de derivar: si no, 30.123.456 y
// 30123456 producirían Blind Index distintos y la misma persona entraría dos
// veces, y Vecino@… y vecino@… esquivarían el índice único de email.
func TestSignUpNormalizaAntesDeDerivar(t *testing.T) {
	h := newHarness(t)

	if _, err := h.svc.SignUp(t.Context(), []byte(cryptogram)); err != nil {
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
}

// Ninguna columna puede terminar guardando el DNI ni la contraseña en claro.
func TestSignUpNoPersisteDatosEnClaro(t *testing.T) {
	h := newHarness(t)

	if _, err := h.svc.SignUp(t.Context(), []byte(cryptogram)); err != nil {
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

// El DNI y la contraseña solo pueden aparecer en el log del gateway si alguien
// los loguea acá; el servicio registra únicamente el identificador opaco.
func TestSignUpNoLogueaDatosSensibles(t *testing.T) {
	h := newHarness(t)

	if _, err := h.svc.SignUp(t.Context(), []byte(cryptogram)); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	logs := h.logs.String()
	for _, secreto := range []string{"30123456", "30.123.456", "Rosario-2026!clave", "vecino@vinculovial.ar"} {
		if strings.Contains(logs, secreto) {
			t.Errorf("el log filtra %q: %s", secreto, logs)
		}
	}
}

func TestSignUpPropagaElFalloDeDescifrado(t *testing.T) {
	h := newHarness(t)
	h.decryptor.err = domain.ErrInvalidCryptogram

	_, err := h.svc.SignUp(t.Context(), []byte(cryptogram))

	if !errors.Is(err, domain.ErrInvalidCryptogram) {
		t.Fatalf("error = %v, se esperaba ErrInvalidCryptogram", err)
	}
	// Nada se deriva ni se persiste si el criptograma no abrió.
	if h.hasher.calls != 0 || h.repo.calls != 0 || h.publisher.calls != 0 {
		t.Error("no debe hacerse trabajo alguno tras un fallo de descifrado")
	}
}

func TestSignUpRechazaPayloadNoJSON(t *testing.T) {
	h := newHarness(t)
	h.decryptor.plaintext = []byte("esto no es json")

	_, err := h.svc.SignUp(t.Context(), []byte(cryptogram))

	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("error = %v, se esperaba ErrInvalidInput", err)
	}
	if h.repo.calls != 0 {
		t.Error("no debe persistirse nada con un payload ilegible")
	}
}

func TestSignUpRechazaDatosInvalidos(t *testing.T) {
	cases := map[string]string{
		"email inválido":     `{"email":"no-es-un-email","password":"Rosario-2026!clave","dni":"30123456"}`,
		"DNI corto":          `{"email":"vecino@vinculovial.ar","password":"Rosario-2026!clave","dni":"123"}`,
		"DNI con letras":     `{"email":"vecino@vinculovial.ar","password":"Rosario-2026!clave","dni":"3012345A"}`,
		"contraseña débil":   `{"email":"vecino@vinculovial.ar","password":"corta","dni":"30123456"}`,
		"campos ausentes":    `{}`,
		"contraseña con DNI": `{"email":"vecino@vinculovial.ar","password":"Rosario30123456!","dni":"30123456"}`,
	}

	for name, plaintext := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.decryptor.plaintext = []byte(plaintext)

			_, err := h.svc.SignUp(t.Context(), []byte(cryptogram))

			if !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("error = %v, se esperaba ErrInvalidInput", err)
			}

			var verrs validation.Errors
			if !errors.As(err, &verrs) || len(verrs) == 0 {
				t.Errorf("se esperaba el detalle por campo, error = %v", err)
			}

			// La validación corta antes del trabajo caro y antes de la base.
			if h.hasher.calls != 0 || h.cipher.calls != 0 || h.repo.calls != 0 {
				t.Error("no debe derivarse ni persistirse nada con datos inválidos")
			}
		})
	}
}

func TestSignUpPropagaElDuplicado(t *testing.T) {
	h := newHarness(t)
	h.repo.err = domain.ErrDuplicateUser

	_, err := h.svc.SignUp(t.Context(), []byte(cryptogram))

	if !errors.Is(err, domain.ErrDuplicateUser) {
		t.Fatalf("error = %v, se esperaba ErrDuplicateUser", err)
	}
	// Un alta que no ocurrió no puede generar un evento.
	if h.publisher.calls != 0 {
		t.Error("no debe publicarse el evento si la persistencia falló")
	}
}

// El usuario ya está confirmado en la base: un broker caído no puede convertir
// un alta exitosa en un 500 que la app reintentaría contra un 409.
func TestSignUpSobreviveAlFalloDelPublisher(t *testing.T) {
	h := newHarness(t)
	h.publisher.err = errors.New("rabbitmq no responde")

	id, err := h.svc.SignUp(t.Context(), []byte(cryptogram))

	if err != nil {
		t.Fatalf("el alta debe mantenerse pese al fallo del broker, error = %v", err)
	}
	if id == uuid.Nil {
		t.Error("se esperaba el identificador del usuario creado")
	}
	if h.repo.calls != 1 {
		t.Errorf("se persistió %d veces, se esperaba 1", h.repo.calls)
	}
	if !strings.Contains(h.logs.String(), "user.registered") {
		t.Error("el fallo de publicación debe quedar registrado para poder repararlo")
	}
}

func TestSignUpPublicaElEventoDelUsuarioCreado(t *testing.T) {
	h := newHarness(t)

	id, err := h.svc.SignUp(t.Context(), []byte(cryptogram))
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if len(h.publisher.published) != 1 {
		t.Fatalf("se publicaron %d eventos, se esperaba 1", len(h.publisher.published))
	}
	evt := h.publisher.published[0]

	if evt.UserID != id {
		t.Errorf("user id del evento = %v, se esperaba %v", evt.UserID, id)
	}
	if evt.AccountStatus != domain.AccountStatusActive {
		t.Errorf("account status = %q, se esperaba %q", evt.AccountStatus, domain.AccountStatusActive)
	}
	if !evt.OccurredAt.Equal(fijo) {
		t.Errorf("occurred at = %v, se esperaba %v", evt.OccurredAt, fijo)
	}
}

func TestSignUpPropagaFallosDeLosPrimitivos(t *testing.T) {
	falloCifrado := errors.New("no se pudo cifrar")
	falloHash := errors.New("no se pudo derivar")

	t.Run("cifrado at-rest", func(t *testing.T) {
		h := newHarness(t)
		h.cipher.err = falloCifrado

		_, err := h.svc.SignUp(t.Context(), []byte(cryptogram))

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

		_, err := h.svc.SignUp(t.Context(), []byte(cryptogram))

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
		"sin repositorio": func(d *signup.Deps) { d.Users = nil },
		"sin publisher":   func(d *signup.Deps) { d.Publisher = nil },
	}

	for name, romper := range cases {
		t.Run(name, func(t *testing.T) {
			deps := signup.Deps{
				Decryptor: &decryptorMock{},
				Indexer:   &indexerMock{},
				Cipher:    &cipherMock{},
				Hasher:    &hasherMock{},
				Users:     &repositoryMock{},
				Publisher: &publisherMock{},
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
		Users:     &repositoryMock{},
		Publisher: &publisherMock{},
	})
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	// Sin Logger ni Now explícitos el servicio debe seguir funcionando.
	if _, err := svc.SignUp(t.Context(), []byte(cryptogram)); err != nil {
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
			_, err := h.svc.SignUp(t.Context(), []byte(cryptogram))
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
