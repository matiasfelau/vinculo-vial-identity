package validation_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/validation"
)

func TestValidateEmailUsaLasReglasDelAlta(t *testing.T) {
	if err := validation.ValidateEmail(validEmail); err != nil {
		t.Errorf("email válido rechazado: %v", err)
	}

	invalidos := map[string]string{
		"vacío":       "",
		"sin arroba":  "vecino.vinculovial.ar",
		"dos arrobas": "a@b@vinculovial.ar",
		"sin TLD":     "vecino@localhost",
		"demasiado largo": strings.Repeat("a", 60) + "@" + strings.Repeat("b", 63) + "." +
			strings.Repeat("c", 63) + "." + strings.Repeat("d", 63) + "." + strings.Repeat("e", 63) + ".ar",
	}
	for name, email := range invalidos {
		t.Run(name, func(t *testing.T) {
			err := validation.ValidateEmail(email)
			if !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("error = %v, se esperaba ErrInvalidInput", err)
			}
			var verrs validation.Errors
			if !errors.As(err, &verrs) || verrs[0].Field != "email" {
				t.Errorf("se esperaba el rechazo del campo email: %v", err)
			}
		})
	}
}

func TestValidateDNIUsaLasReglasDelAlta(t *testing.T) {
	if err := validation.ValidateDNI([]byte(validDNI)); err != nil {
		t.Errorf("DNI válido rechazado: %v", err)
	}

	for name, dni := range map[string]string{
		"vacío": "", "corto": "123456", "largo": "123456789", "con letras": "30A23456", "empieza con cero": "01234567",
	} {
		t.Run(name, func(t *testing.T) {
			err := validation.ValidateDNI([]byte(dni))
			if !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("error = %v, se esperaba ErrInvalidInput", err)
			}
			if strings.Contains(err.Error(), dni) && dni != "" {
				t.Errorf("el error incluye el DNI recibido: %v", err)
			}
		})
	}
}

func TestIsEmailCode(t *testing.T) {
	casos := map[string]bool{
		"123456":  true,
		"000000":  true,
		"":        false,
		"12345":   false,
		"1234567": false,
		"12345a":  false,
		"12 456":  false,
		"１２３４５６":  false, // dígitos de ancho completo: solo ASCII
	}
	for code, want := range casos {
		if got := validation.IsEmailCode(code, 6); got != want {
			t.Errorf("IsEmailCode(%q) = %v, se esperaba %v", code, got, want)
		}
	}
}

func inputDeRecuperacion() validation.PasswordResetInput {
	return validation.PasswordResetInput{
		Email:        validEmail,
		NewPassword:  []byte(validPassword),
		DNI:          []byte(validDNI),
		Tramite:      []byte(validTramite),
		Sexo:         []byte(validSexo),
		SelfieBase64: validSelfieBase64,
	}
}

func TestValidatePasswordResetAceptaUnPayloadValido(t *testing.T) {
	selfie, err := validation.ValidatePasswordReset(inputDeRecuperacion())
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if string(selfie) != string(selfieBytes) {
		t.Error("la selfie devuelta no es la decodificada")
	}
}

// La contraseña se valida con las reglas del alta y los errores nombran el campo
// password, igual que allá.
func TestValidatePasswordResetAplicaLasReglasDeContrasenaDelAlta(t *testing.T) {
	casos := map[string]string{
		"corta":                        "Ab1!",
		"sin símbolos":                 "Rosario2026clave",
		"sin mayúsculas":               "rosario-2026!clave",
		"contiene el DNI":              "Zz-" + validDNI + "-Aa!",
		"contiene el usuario del mail": "Vecino-2026!Aa",
	}
	for name, pwd := range casos {
		t.Run(name, func(t *testing.T) {
			in := inputDeRecuperacion()
			in.NewPassword = []byte(pwd)

			_, err := validation.ValidatePasswordReset(in)

			var verrs validation.Errors
			if !errors.As(err, &verrs) {
				t.Fatalf("se esperaba validation.Errors, se obtuvo %v", err)
			}
			hallado := false
			for _, fe := range verrs {
				hallado = hallado || fe.Field == "password"
			}
			if !hallado {
				t.Errorf("no se rechazó el campo password: %v", verrs)
			}
			if strings.Contains(err.Error(), pwd) {
				t.Errorf("el error incluye la contraseña: %v", err)
			}
		})
	}
}

// Se acumulan todos los rechazos, y la selfie se devuelve aun con otro campo
// inválido, para que el llamador la limpie.
func TestValidatePasswordResetAcumulaLosRechazos(t *testing.T) {
	in := inputDeRecuperacion()
	in.DNI = []byte("123")
	in.Tramite = []byte("1")
	in.Sexo = []byte("Q")

	selfie, err := validation.ValidatePasswordReset(in)

	var verrs validation.Errors
	if !errors.As(err, &verrs) {
		t.Fatalf("se esperaba validation.Errors, se obtuvo %v", err)
	}
	campos := map[string]bool{}
	for _, fe := range verrs {
		campos[fe.Field] = true
	}
	for _, f := range []string{"dni", "tramite", "sexo"} {
		if !campos[f] {
			t.Errorf("falta el rechazo de %s: %v", f, verrs)
		}
	}
	if len(selfie) == 0 {
		t.Error("la selfie válida tendría que devolverse aunque otro campo falle")
	}
}

func TestValidatePasswordResetRechazaUnaSelfieInvalida(t *testing.T) {
	in := inputDeRecuperacion()
	in.SelfieBase64 = "no-es-una-imagen"

	selfie, err := validation.ValidatePasswordReset(in)
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("error = %v, se esperaba ErrInvalidInput", err)
	}
	if selfie != nil {
		t.Error("no se debería devolver una selfie que no validó")
	}
}

// El email de la cuenta solo sirve para la similitud; no se valida su formato
// porque no lo manda el cliente.
func TestValidatePasswordResetNoValidaElFormatoDelEmailDeLaCuenta(t *testing.T) {
	in := inputDeRecuperacion()
	in.Email = "cuenta-vieja-sin-arroba"
	if _, err := validation.ValidatePasswordReset(in); err != nil {
		t.Errorf("el formato del email de la cuenta no debería rechazar la recuperación: %v", err)
	}
}
