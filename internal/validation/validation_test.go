package validation_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/validation"
)

// Trío base válido; cada test degrada un solo campo para aislar la regla.
const (
	validEmail    = "vecino@vinculovial.ar"
	validPassword = "Rosario-2026!clave"
	validDNI      = "30123456"
)

func validate(email, pwd, dni string) error {
	return validation.ValidateSignUp(email, []byte(pwd), []byte(dni))
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
// rechazos en lugar de cortar en el primero.
func TestValidateSignUpAcumulaTodosLosRechazos(t *testing.T) {
	err := validate("no-es-un-email", "corta", "abc")

	campos := fieldsOf(t, err)
	for _, field := range []string{"email", "dni", "password"} {
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

func TestValidatePassword(t *testing.T) {
	invalidos := map[string]string{
		"vacía":              "",
		"muy corta":          "Abc-2026!",
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

	err := validation.ValidateSignUp(validEmail, pwd, []byte(validDNI))
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
		if err := validation.ValidateSignUp(validEmail, []byte(validPassword), got); err != nil {
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

func TestErrorsVacioEsNil(t *testing.T) {
	var errs validation.Errors
	if err := errs.OrNil(); err != nil {
		t.Errorf("un conjunto vacío debe devolver nil, se obtuvo %v (%T)", err, err)
	}
}
