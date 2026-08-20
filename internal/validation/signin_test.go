package validation_test

import (
	"errors"
	"testing"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/validation"
)

func TestValidateSignInAceptaDatosValidos(t *testing.T) {
	cases := map[string][]byte{
		"DNI de 8 dígitos": []byte(validDNI),
		"DNI de 7 dígitos": []byte("7654321"),
	}

	for name, dni := range cases {
		t.Run(name, func(t *testing.T) {
			err := validation.ValidateSignIn(validation.SignInInput{DNI: dni, Password: []byte(validPassword)})
			if err != nil {
				t.Errorf("se esperaba válido, error = %v", err)
			}
		})
	}
}

func TestValidateSignInRechazaDNIInvalido(t *testing.T) {
	cases := map[string][]byte{
		"vacío":              nil,
		"con letras":         []byte("30abc456"),
		"demasiado corto":    []byte("123456"),
		"demasiado largo":    []byte("123456789"),
		"con cero inicial":   []byte("01234567"),
	}

	for name, dni := range cases {
		t.Run(name, func(t *testing.T) {
			err := validation.ValidateSignIn(validation.SignInInput{DNI: dni, Password: []byte(validPassword)})
			campos := fieldsOf(t, err)
			if _, ok := campos["dni"]; !ok {
				t.Errorf("se esperaba un rechazo del campo dni; se obtuvo %v", campos)
			}
		})
	}
}

func TestValidateSignInRechazaPasswordVacio(t *testing.T) {
	err := validation.ValidateSignIn(validation.SignInInput{DNI: []byte(validDNI), Password: nil})

	campos := fieldsOf(t, err)
	if campos["password"] != validation.CodeRequired {
		t.Errorf("password = %v, se esperaba %q", campos["password"], validation.CodeRequired)
	}
}

// A diferencia del alta, el login no exige clases de caracteres ni descarta
// contraseñas similares al DNI: una cuenta existente pudo crearse bajo otra
// política, y el login no es el lugar para rechazarla retroactivamente por eso.
func TestValidateSignInNoAplicaLaPoliticaDeFortalezaDelAlta(t *testing.T) {
	err := validation.ValidateSignIn(validation.SignInInput{
		DNI:      []byte(validDNI),
		Password: []byte("corta"),
	})
	if err != nil {
		t.Errorf("el login no debe rechazar por fortaleza de contraseña, error = %v", err)
	}
}

// El handler mapea a 400 con errors.Is contra el centinela de dominio, sin
// conocer este paquete.
func TestErroresDeValidateSignInSonErrInvalidInput(t *testing.T) {
	err := validation.ValidateSignIn(validation.SignInInput{DNI: []byte("abc"), Password: nil})
	if err == nil {
		t.Fatal("se esperaba un error")
	}
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Error("el error de validación debe satisfacer errors.Is contra domain.ErrInvalidInput")
	}
}

// La app corrige el formulario en un intento: DNI y contraseña inválidos se
// acumulan en el mismo error en lugar de cortar en el primero.
func TestValidateSignInAcumulaLosRechazos(t *testing.T) {
	err := validation.ValidateSignIn(validation.SignInInput{DNI: []byte("abc"), Password: nil})

	campos := fieldsOf(t, err)
	for _, field := range []string{"dni", "password"} {
		if _, ok := campos[field]; !ok {
			t.Errorf("falta el rechazo del campo %q; se obtuvo %v", field, campos)
		}
	}
}
