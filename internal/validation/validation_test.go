package validation_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/validation"
)

// Sexteto base válido; cada test degrada un solo campo para aislar la regla.
const (
	validEmail    = "vecino@vinculovial.ar"
	validPassword = "Rosario-2026!clave"
	validDNI      = "30123456"
	validTramite  = "12345678901"
	validSexo     = "F"
)

// selfieBytes es el contenido mínimo que pasa la validación de formato: la
// cabecera PNG y nada más. El validador solo mira los primeros bytes, así que
// no hace falta un PNG real y decodificable para probarlo.
var selfieBytes = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x01, 0x02, 0x03}

var validSelfieBase64 = base64.StdEncoding.EncodeToString(selfieBytes)

// validInput arma un SignUpInput enteramente válido; cada test lo clona y
// degrada solo el campo que quiere ejercitar.
func validInput() validation.SignUpInput {
	return validation.SignUpInput{
		Email:        validEmail,
		Password:     []byte(validPassword),
		DNI:          []byte(validDNI),
		Tramite:      []byte(validTramite),
		Sexo:         []byte(validSexo),
		SelfieBase64: validSelfieBase64,
	}
}

// validate solo varía email, password y DNI: es la vía feliz para los tests que
// no ejercitan trámite, sexo o selfie en particular, que tienen sus propios
// tests dedicados.
func validate(email, pwd, dni string) error {
	in := validInput()
	in.Email, in.Password, in.DNI = email, []byte(pwd), []byte(dni)
	_, err := validation.ValidateSignUp(in)
	return err
}

// fieldsOf extrae los campos rechazados para poder afirmar sobre el conjunto
// completo, no solo sobre el primero.
func fieldsOf(t *testing.T, err error) map[string]string {
	t.Helper()

	var verrs validation.Errors
	if !errors.As(err, &verrs) {
		t.Fatalf("error = %v (%T), se esperaba validation.Errors", err, err)
	}

	out := make(map[string]string, len(verrs))
	for _, fe := range verrs {
		out[fe.Field] = fe.Code
	}
	return out
}

func TestValidateSignUpAceptaDatosValidos(t *testing.T) {
	cases := map[string][3]string{
		"caso base":                      {validEmail, validPassword, validDNI},
		"DNI de 7 dígitos":               {validEmail, validPassword, "7654321"},
		"email con subdominio":           {"vecino@mail.vinculovial.gob.ar", validPassword, validDNI},
		"email con etiqueta":             {"vecino+alertas@vinculovial.ar", validPassword, validDNI},
		"email con puntos":               {"juan.perez@vinculovial.ar", validPassword, validDNI},
		"contraseña con acentos y emoji": {validEmail, "Ñandú-2026!🚦clave", validDNI},
		"contraseña de 8 caracteres":     {validEmail, "Rosa-2!6", validDNI},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if err := validate(tc[0], tc[1], tc[2]); err != nil {
				t.Errorf("se esperaba válido, error = %v", err)
			}
		})
	}
}

// El handler mapea a 400 con errors.Is contra el centinela de dominio, sin
// conocer este paquete.
func TestErroresDeValidacionSonErrInvalidInput(t *testing.T) {
	err := validate("no-es-un-email", "corta", "abc")
	if err == nil {
		t.Fatal("se esperaba un error")
	}
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Error("el error de validación debe satisfacer errors.Is contra domain.ErrInvalidInput")
	}
}

// La app corrige el formulario en un intento, así que se acumulan todos los
// rechazos en lugar de cortar en el primero. Se ejercita con el sexteto
// completo degradado —no solo el trío original— para probar que trámite, sexo
// y selfie entran en la misma acumulación.
func TestValidateSignUpAcumulaTodosLosRechazos(t *testing.T) {
	in := validation.SignUpInput{
		Email:        "no-es-un-email",
		Password:     []byte("corta"),
		DNI:          []byte("abc"),
		Tramite:      []byte("123"),
		Sexo:         []byte("Z"),
		SelfieBase64: "no-es-base64-!!!",
	}
	_, err := validation.ValidateSignUp(in)

	campos := fieldsOf(t, err)
	for _, field := range []string{"email", "dni", "password", "tramite", "sexo", "selfie"} {
		if _, ok := campos[field]; !ok {
			t.Errorf("falta el rechazo del campo %q; se obtuvo %v", field, campos)
		}
	}
}

func TestValidateEmail(t *testing.T) {
	invalidos := map[string]string{
		"vacío":                     "",
		"sin arroba":                "vecino.vinculovial.ar",
		"dos arrobas":               "vecino@otro@vinculovial.ar",
		"sin parte local":           "@vinculovial.ar",
		"sin dominio":               "vecino@",
		"dominio sin TLD":           "vecino@localhost",
		"TLD de una letra":          "vecino@vinculovial.a",
		"TLD numérico":              "vecino@192.168.0.1",
		"etiqueta vacía":            "vecino@vinculovial..ar",
		"dominio con guion final":   "vecino@vinculovial-.ar",
		"dominio con guion inicial": "vecino@-vinculovial.ar",
		"local con punto inicial":   ".vecino@vinculovial.ar",
		"local con punto final":     "vecino.@vinculovial.ar",
		"local con puntos dobles":   "ve..cino@vinculovial.ar",
		"local con espacio":         "ve cino@vinculovial.ar",
		"local con acento":          "veciño@vinculovial.ar",
		"con salto de línea":        "vecino@vinculovial.ar\n",
		"parte local muy larga":     strings.Repeat("a", 65) + "@vinculovial.ar",
		"email muy largo":           strings.Repeat("a", 60) + "@" + strings.Repeat("b", 200) + ".ar",
	}

	for name, email := range invalidos {
		t.Run(name, func(t *testing.T) {
			err := validate(email, validPassword, validDNI)
			if err == nil {
				t.Fatalf("%q debería rechazarse", email)
			}
			if _, ok := fieldsOf(t, err)["email"]; !ok {
				t.Errorf("el rechazo debería señalar el campo email, se obtuvo %v", err)
			}
		})
	}
}

func TestValidateDNI(t *testing.T) {
	invalidos := map[string]string{
		"vacío":               "",
		"muy corto":           "123456",
		"muy largo":           "301234567",
		"con letras":          "3012345A",
		"con signo":           "-3012345",
		"con cero inicial":    "01234567",
		"solo ceros":          "00000000",
		"notación científica": "3.01e+07",
	}

	for name, dni := range invalidos {
		t.Run(name, func(t *testing.T) {
			err := validate(validEmail, validPassword, dni)
			if err == nil {
				t.Fatalf("%q debería rechazarse", dni)
			}
			if _, ok := fieldsOf(t, err)["dni"]; !ok {
				t.Errorf("el rechazo debería señalar el campo dni, se obtuvo %v", err)
			}
		})
	}
}

func TestValidateTramite(t *testing.T) {
	invalidos := map[string]string{
		"vacío":               "",
		"corto":               "1234567890",
		"largo":               "123456789012",
		"con letras":          "1234567890A",
		"con separadores":     "123-456-789",
		"notación científica": "1.2345e+10",
	}

	for name, tramite := range invalidos {
		t.Run(name, func(t *testing.T) {
			in := validInput()
			in.Tramite = []byte(tramite)

			_, err := validation.ValidateSignUp(in)
			if err == nil {
				t.Fatalf("%q debería rechazarse", tramite)
			}
			if _, ok := fieldsOf(t, err)["tramite"]; !ok {
				t.Errorf("el rechazo debería señalar el campo tramite, se obtuvo %v", err)
			}
		})
	}

	t.Run("11 dígitos pasa", func(t *testing.T) {
		in := validInput()
		in.Tramite = []byte("98765432109")

		if _, err := validation.ValidateSignUp(in); err != nil {
			t.Errorf("se esperaba válido, error = %v", err)
		}
	})
}

func TestValidateSexo(t *testing.T) {
	invalidos := []string{"", "A", "MF", "m ", " M", "1", "Ñ"}

	for _, sexo := range invalidos {
		t.Run("rechaza "+sexo, func(t *testing.T) {
			in := validInput()
			in.Sexo = []byte(sexo)

			_, err := validation.ValidateSignUp(in)
			if err == nil {
				t.Fatalf("%q debería rechazarse", sexo)
			}
			if _, ok := fieldsOf(t, err)["sexo"]; !ok {
				t.Errorf("el rechazo debería señalar el campo sexo, se obtuvo %v", err)
			}
		})
	}

	for _, sexo := range []string{"M", "F", "X"} {
		t.Run("acepta "+sexo, func(t *testing.T) {
			in := validInput()
			in.Sexo = []byte(sexo)

			if _, err := validation.ValidateSignUp(in); err != nil {
				t.Errorf("se esperaba válido, error = %v", err)
			}
		})
	}
}

func TestNormalizeSexo(t *testing.T) {
	cases := map[string]string{
		"m": "M",
		"f": "F",
		"x": "X",
		"M": "M",
	}

	for raw, want := range cases {
		got := validation.NormalizeSexo([]byte(raw))
		if string(got) != want {
			t.Errorf("NormalizeSexo(%q) = %q, se esperaba %q", raw, got, want)
		}
	}
}

// NormalizeSexo muta el mismo buffer: el llamador lo limpia con defer más
// adelante y no debe quedar un segundo buffer sin limpiar dando vueltas.
func TestNormalizeSexoMutaElMismoBuffer(t *testing.T) {
	buf := []byte("f")
	got := validation.NormalizeSexo(buf)

	if &got[0] != &buf[0] {
		t.Error("NormalizeSexo debería devolver el mismo buffer, no uno nuevo")
	}
}

func TestValidateSelfie(t *testing.T) {
	t.Run("ausente se rechaza", func(t *testing.T) {
		in := validInput()
		in.SelfieBase64 = ""

		selfie, err := validation.ValidateSignUp(in)
		if err == nil {
			t.Fatal("la selfie ausente debería rechazarse")
		}
		if code := fieldsOf(t, err)["selfie"]; code != validation.CodeRequired {
			t.Errorf("code = %q, se esperaba %q", code, validation.CodeRequired)
		}
		if selfie != nil {
			t.Error("no debería devolverse ninguna selfie cuando la validación falla")
		}
	})

	t.Run("no es base64 se rechaza", func(t *testing.T) {
		in := validInput()
		in.SelfieBase64 = "no-es-base64-!!!"

		_, err := validation.ValidateSignUp(in)
		if err == nil {
			t.Fatal("debería rechazarse")
		}
		if code := fieldsOf(t, err)["selfie"]; code != validation.CodeFormat {
			t.Errorf("code = %q, se esperaba %q", code, validation.CodeFormat)
		}
	})

	t.Run("base64 válido pero sin magic bytes de imagen se rechaza", func(t *testing.T) {
		in := validInput()
		in.SelfieBase64 = base64.StdEncoding.EncodeToString([]byte("esto no es una imagen"))

		_, err := validation.ValidateSignUp(in)
		if err == nil {
			t.Fatal("debería rechazarse")
		}
		if code := fieldsOf(t, err)["selfie"]; code != validation.CodeFormat {
			t.Errorf("code = %q, se esperaba %q", code, validation.CodeFormat)
		}
	})

	t.Run("supera MaxSelfieBytes se rechaza", func(t *testing.T) {
		grande := append([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, make([]byte, validation.MaxSelfieBytes)...)

		in := validInput()
		in.SelfieBase64 = base64.StdEncoding.EncodeToString(grande)

		_, err := validation.ValidateSignUp(in)
		if err == nil {
			t.Fatal("debería rechazarse")
		}
		if code := fieldsOf(t, err)["selfie"]; code != validation.CodeLength {
			t.Errorf("code = %q, se esperaba %q", code, validation.CodeLength)
		}
	})

	t.Run("acepta JPEG y PNG", func(t *testing.T) {
		magics := map[string][]byte{
			"JPEG": {0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10},
			"PNG":  {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
		}

		for name, magic := range magics {
			t.Run(name, func(t *testing.T) {
				in := validInput()
				in.SelfieBase64 = base64.StdEncoding.EncodeToString(magic)

				selfie, err := validation.ValidateSignUp(in)
				if err != nil {
					t.Fatalf("se esperaba válido, error = %v", err)
				}
				if !bytes.Equal(selfie, magic) {
					t.Errorf("selfie devuelta = %v, se esperaba %v", selfie, magic)
				}
			})
		}
	})
}

// La selfie decodificada es el único artefacto que ValidateSignUp devuelve
// además del error, precisamente para que el llamador siempre tenga algo que
// limpiar con defer: se devuelve incluso cuando otro campo falla la validación.
func TestValidateSignUpDevuelveLaSelfieAunquenOtroCampoFalle(t *testing.T) {
	in := validInput()
	in.Email = "no-es-un-email"

	selfie, err := validation.ValidateSignUp(in)
	if err == nil {
		t.Fatal("se esperaba un error por el email")
	}
	if !bytes.Equal(selfie, selfieBytes) {
		t.Errorf("selfie devuelta = %v, se esperaba %v", selfie, selfieBytes)
	}
}

func TestValidatePassword(t *testing.T) {
	invalidos := map[string]string{
		"vacía":              "",
		"muy corta":          "Rosa-1!", // 7 caracteres: por debajo del nuevo piso de 8.
		"muy larga":          strings.Repeat("Abc-2026!", 20),
		"sin mayúscula":      "rosario-2026!clave",
		"sin minúscula":      "ROSARIO-2026!CLAVE",
		"sin dígito":         "Rosario-clave!seg",
		"sin símbolo":        "Rosario2026clave",
		"solo minúsculas":    "rosariorosario",
		"con salto de línea": "Rosario-2026!\nclave",
		"con tabulación":     "Rosario-2026!\tclave",
	}

	for name, pwd := range invalidos {
		t.Run(name, func(t *testing.T) {
			err := validate(validEmail, pwd, validDNI)
			if err == nil {
				t.Fatalf("%q debería rechazarse", pwd)
			}
			if _, ok := fieldsOf(t, err)["password"]; !ok {
				t.Errorf("el rechazo debería señalar el campo password, se obtuvo %v", err)
			}
		})
	}
}

func TestValidatePasswordRechazaUTF8Invalido(t *testing.T) {
	pwd := []byte("Rosario-2026!")
	pwd = append(pwd, 0xFF, 0xFE)

	in := validInput()
	in.Password = pwd

	_, err := validation.ValidateSignUp(in)
	if err == nil {
		t.Fatal("una contraseña que no es UTF-8 válido debería rechazarse")
	}
	if code := fieldsOf(t, err)["password"]; code != validation.CodeFormat {
		t.Errorf("code = %q, se esperaba %q", code, validation.CodeFormat)
	}
}

// Cumplir las cuatro clases no alcanza si la contraseña se deduce de datos que
// el atacante ya tiene.
func TestValidatePasswordRechazaDerivadasDeOtrosCampos(t *testing.T) {
	cases := map[string][3]string{
		"contiene el DNI":               {validEmail, "Rosario-30123456!", validDNI},
		"es el DNI decorado":            {validEmail, "A30123456!bcd", validDNI},
		"contiene el usuario del email": {"martina@vinculovial.ar", "Martina-2026!ok", validDNI},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := validate(tc[0], tc[1], tc[2])
			if err == nil {
				t.Fatal("se esperaba un rechazo por similitud")
			}
			if code := fieldsOf(t, err)["password"]; code != validation.CodeSimilarity {
				t.Errorf("code = %q, se esperaba %q", code, validation.CodeSimilarity)
			}
		})
	}
}

func TestNormalizeEmail(t *testing.T) {
	cases := map[string]string{
		"  vecino@vinculovial.ar  ": "vecino@vinculovial.ar",
		"VECINO@VINCULOVIAL.AR":     "vecino@vinculovial.ar",
		"Vecino@VinculoVial.Ar":     "vecino@vinculovial.ar",
		"vecino@vinculovial.ar":     "vecino@vinculovial.ar",
	}

	for raw, want := range cases {
		if got := validation.NormalizeEmail(raw); got != want {
			t.Errorf("NormalizeEmail(%q) = %q, se esperaba %q", raw, got, want)
		}
	}
}

// Sin esta normalización, "30.123.456" y "30123456" producirían Blind Index
// distintos y la misma persona podría registrarse dos veces.
func TestNormalizeDNIUnificaLasFormasDeEscritura(t *testing.T) {
	formas := []string{"30123456", "30.123.456", "30 123 456", "30-123-456", " 30123456\n"}

	for _, forma := range formas {
		got := validation.NormalizeDNI([]byte(forma))
		if string(got) != validDNI {
			t.Errorf("NormalizeDNI(%q) = %q, se esperaba %q", forma, got, validDNI)
		}

		in := validInput()
		in.DNI = got
		if _, err := validation.ValidateSignUp(in); err != nil {
			t.Errorf("%q normalizado debería ser válido: %v", forma, err)
		}
	}
}

func TestNormalizeDNINoAliasaElBufferDeEntrada(t *testing.T) {
	raw := []byte("30.123.456")

	got := validation.NormalizeDNI(raw)
	clear(raw)

	if string(got) != validDNI {
		t.Errorf("limpiar la entrada alteró la salida: %q", got)
	}
}

func TestFieldErrorNoFiltraElValorRechazado(t *testing.T) {
	const secreto = "30123456"

	err := validate(validEmail, "Rosario-"+secreto+"!", secreto)
	if err == nil {
		t.Fatal("se esperaba un error")
	}

	var verrs validation.Errors
	if !errors.As(err, &verrs) {
		t.Fatalf("error = %v (%T), se esperaba validation.Errors", err, err)
	}
	for _, fe := range verrs {
		if strings.Contains(fe.Message, secreto) {
			t.Errorf("el mensaje filtra el dato rechazado: %q", fe.Message)
		}
	}
	if strings.Contains(err.Error(), secreto) {
		t.Errorf("el error agregado filtra el dato rechazado: %q", err.Error())
	}
}

// El mensaje de longitud incluye cuántos dígitos se recibieron —para
// diagnosticar sin adivinar— pero nunca cuáles. Un DNI de longitud inválida no
// pasa por TestFieldErrorNoFiltraElValorRechazado (ese usa uno de longitud
// correcta, rechazado por otra regla), así que esta garantía necesita su propio
// caso.
func TestValidateDNILongitudNoFiltraElValor(t *testing.T) {
	const secreto = "3012345" // 7 dígitos: válido para DNI, inválido para trámite.

	in := validInput()
	in.DNI = []byte(secreto[:5]) // longitud inválida a propósito

	_, err := validation.ValidateSignUp(in)
	campos := fieldsOf(t, err)
	if campos["dni"] != validation.CodeLength {
		t.Fatalf("code = %q, se esperaba %q", campos["dni"], validation.CodeLength)
	}

	var verrs validation.Errors
	errors.As(err, &verrs)
	for _, fe := range verrs {
		if fe.Field != "dni" {
			continue
		}
		if !strings.Contains(fe.Message, "5") {
			t.Errorf("el mensaje debería informar la longitud recibida (5): %q", fe.Message)
		}
		if strings.Contains(fe.Message, secreto[:5]) {
			t.Errorf("el mensaje filtra el DNI recibido: %q", fe.Message)
		}
	}
}

func TestValidateTramiteLongitudNoFiltraElValor(t *testing.T) {
	const secreto = "98765432109" // 11 dígitos válidos, para truncar a propósito.

	in := validInput()
	in.Tramite = []byte(secreto[:4])

	_, err := validation.ValidateSignUp(in)
	campos := fieldsOf(t, err)
	if campos["tramite"] != validation.CodeLength {
		t.Fatalf("code = %q, se esperaba %q", campos["tramite"], validation.CodeLength)
	}

	var verrs validation.Errors
	errors.As(err, &verrs)
	for _, fe := range verrs {
		if fe.Field != "tramite" {
			continue
		}
		if !strings.Contains(fe.Message, "4") {
			t.Errorf("el mensaje debería informar la longitud recibida (4): %q", fe.Message)
		}
		if strings.Contains(fe.Message, secreto[:4]) {
			t.Errorf("el mensaje filtra el trámite recibido: %q", fe.Message)
		}
	}
}

// El sexo no es un identificador de la persona, así que acá sí se ecoa el
// valor recibido —acotado y escapado— para que el frontend vea exactamente qué
// mandó.
func TestValidateSexoEcoaElValorRecibidoAcotadoYEscapado(t *testing.T) {
	t.Run("valor corto se ecoa tal cual", func(t *testing.T) {
		in := validInput()
		in.Sexo = []byte("Femenino")

		_, err := validation.ValidateSignUp(in)
		campos := fieldsOf(t, err)
		if campos["sexo"] != validation.CodeFormat {
			t.Fatalf("code = %q, se esperaba %q", campos["sexo"], validation.CodeFormat)
		}

		var verrs validation.Errors
		errors.As(err, &verrs)
		for _, fe := range verrs {
			if fe.Field == "sexo" && !strings.Contains(fe.Message, "Femenino") {
				t.Errorf("se esperaba ver el valor recibido en el mensaje: %q", fe.Message)
			}
		}
	})

	t.Run("valor largo se trunca", func(t *testing.T) {
		in := validInput()
		in.Sexo = []byte(strings.Repeat("a", 200))

		_, err := validation.ValidateSignUp(in)
		var verrs validation.Errors
		errors.As(err, &verrs)
		for _, fe := range verrs {
			if fe.Field != "sexo" {
				continue
			}
			if len(fe.Message) > 100 {
				t.Errorf("el mensaje no debería crecer con un campo desmesurado: %d bytes", len(fe.Message))
			}
		}
	})

	t.Run("saltos de línea quedan escapados, no inyectan una línea de log falsa", func(t *testing.T) {
		in := validInput()
		in.Sexo = []byte("F\n{\"level\":\"INFO\",\"msg\":\"fabricado\"}")

		_, err := validation.ValidateSignUp(in)
		var verrs validation.Errors
		errors.As(err, &verrs)
		for _, fe := range verrs {
			if fe.Field != "sexo" {
				continue
			}
			if strings.Contains(fe.Message, "\n") {
				t.Errorf("el mensaje contiene un salto de línea sin escapar: %q", fe.Message)
			}
		}
	})
}

// La selfie nunca aparece en el mensaje, ni siquiera en base64: solo su
// tamaño y si matcheó o no contra las cabeceras conocidas.
func TestValidateSelfieMensajesInformanTamanoNoContenido(t *testing.T) {
	t.Run("no es base64", func(t *testing.T) {
		in := validInput()
		in.SelfieBase64 = "no-es-base64-!!!"

		_, err := validation.ValidateSignUp(in)
		campos := fieldsOf(t, err)
		if campos["selfie"] != validation.CodeFormat {
			t.Fatalf("code = %q, se esperaba %q", campos["selfie"], validation.CodeFormat)
		}

		var verrs validation.Errors
		errors.As(err, &verrs)
		for _, fe := range verrs {
			if fe.Field == "selfie" {
				if strings.Contains(fe.Message, in.SelfieBase64) {
					t.Errorf("el mensaje incluye el contenido recibido: %q", fe.Message)
				}
				if !strings.Contains(fe.Message, "16") { // len("no-es-base64-!!!") == 16
					t.Errorf("el mensaje debería informar la longitud recibida: %q", fe.Message)
				}
			}
		}
	})

	t.Run("sin magic bytes de imagen", func(t *testing.T) {
		in := validInput()
		in.SelfieBase64 = base64.StdEncoding.EncodeToString([]byte("esto no es una imagen"))

		_, err := validation.ValidateSignUp(in)
		var verrs validation.Errors
		errors.As(err, &verrs)
		for _, fe := range verrs {
			if fe.Field == "selfie" && strings.Contains(fe.Message, "esto no es una imagen") {
				t.Errorf("el mensaje incluye el contenido de la selfie: %q", fe.Message)
			}
		}
	})
}

func TestErrorsVacioEsNil(t *testing.T) {
	var errs validation.Errors
	if err := errs.OrNil(); err != nil {
		t.Errorf("un conjunto vacío debe devolver nil, se obtuvo %v (%T)", err, err)
	}
}
