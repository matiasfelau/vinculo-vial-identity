// Package validation aplica el principio Never Trust the Client sobre el
// payload ya descifrado, antes de derivar nada criptográficamente y antes de
// tocar la base de datos.
//
// Que el criptograma HPKE haya abierto correctamente prueba que el emisor tenía
// la clave pública del servicio, no que los datos sean válidos: el cliente sigue
// siendo un dispositivo fuera de nuestro control.
package validation

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Umbrales de formato.
const (
	// MaxEmailLength es el máximo de la ruta de reenvío de RFC 5321.
	MaxEmailLength = 254
	// MaxEmailLocalLength es el máximo de la parte local de RFC 5321.
	MaxEmailLocalLength = 64

	// MinDNIDigits y MaxDNIDigits acotan el DNI argentino vigente.
	MinDNIDigits = 7
	MaxDNIDigits = 8
)

// Política de fortaleza de contraseña.
//
// El piso es de 12 caracteres —por encima del mínimo habitual de 8— porque el
// registro no exige segundo factor: la contraseña es la única credencial hasta
// que se implemente US-02. El techo acota el costo de la derivación Argon2id.
const (
	MinPasswordLength = 12
	MaxPasswordLength = 128
	// MinPasswordClasses exige presencia de minúscula, mayúscula, dígito y
	// símbolo: las cuatro clases, sin excepciones.
	MinPasswordClasses = 4
)

// NormalizeEmail deja el email en la forma canónica que se persiste y sobre la
// que actúa la restricción UNIQUE.
//
// Se recorta el espacio circundante y se pasa a minúscula. La parte local es
// técnicamente sensible a mayúsculas según RFC 5321, pero ningún proveedor real
// lo explota y respetarlo permitiría registrar Vecino@… y vecino@… como cuentas
// distintas, que es exactamente el bypass de unicidad que hay que evitar.
func NormalizeEmail(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

// NormalizeDNI descarta los separadores con los que la gente escribe el DNI
// (30.123.456, 30 123 456) y devuelve solo los dígitos, en un buffer nuevo.
//
// El resultado alimenta tanto el Blind Index como el cifrado at-rest, así que
// normalizar acá es lo que garantiza que "30.123.456" y "30123456" colisionen
// como el duplicado que son.
func NormalizeDNI(raw []byte) []byte {
	out := make([]byte, 0, len(raw))
	for _, b := range raw {
		switch b {
		case '.', ' ', '-', '\t', '\n', '\r':
			continue
		}
		out = append(out, b)
	}
	return out
}

// ValidateSignUp valida el trío de registro y acumula todos los rechazos.
//
// Espera los valores ya normalizados con NormalizeEmail y NormalizeDNI. Devuelve
// nil o un Errors que satisface errors.Is(err, domain.ErrInvalidInput).
func ValidateSignUp(email string, pwd, dni []byte) error {
	var errs Errors

	validateEmail(&errs, email)
	validateDNI(&errs, dni)
	validatePassword(&errs, pwd)
	validatePasswordSimilarity(&errs, pwd, email, dni)

	return errs.OrNil()
}

func validateEmail(errs *Errors, email string) {
	const field = "email"

	if email == "" {
		errs.add(field, CodeRequired, "el email es obligatorio")
		return
	}
	if len(email) > MaxEmailLength {
		errs.add(field, CodeLength, fmt.Sprintf("el email no puede superar los %d caracteres", MaxEmailLength))
		return
	}

	local, domainPart, found := strings.Cut(email, "@")
	// Cut corta en la primera arroba; exigir que no haya otra descarta
	// direcciones con arrobas embebidas sin recurrir a una regex más frágil.
	if !found || strings.Contains(domainPart, "@") {
		errs.add(field, CodeFormat, "el email debe tener exactamente una arroba")
		return
	}

	if !validEmailLocal(local) {
		errs.add(field, CodeFormat, "la parte local del email no es válida")
		return
	}
	if !validEmailDomain(domainPart) {
		errs.add(field, CodeFormat, "el dominio del email no es válido")
	}
}

func validEmailLocal(local string) bool {
	if local == "" || len(local) > MaxEmailLocalLength {
		return false
	}
	// Un punto al borde o dos seguidos son inválidos según RFC 5322 en su forma
	// sin comillas, la única que aceptamos.
	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return false
	}

	for _, r := range local {
		if r == '.' || isEmailAtom(r) {
			continue
		}
		return false
	}
	return true
}

// isEmailAtom cubre los caracteres "atext" de RFC 5322 sin comillas.
func isEmailAtom(r rune) bool {
	if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
		return true
	}
	return strings.ContainsRune("!#$%&'*+/=?^_`{|}~-", r)
}

func validEmailDomain(host string) bool {
	// Se exige al menos un punto: un dominio sin TLD no es enrutable en
	// Internet y en la práctica siempre es un error de tipeo.
	if host == "" || len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}

	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			isAlnum := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
			if !isAlnum && r != '-' {
				return false
			}
		}
	}

	// El TLD nunca es numérico; esto descarta que una IP se cuele como dominio.
	labels := strings.Split(host, ".")
	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return false
	}
	for _, r := range tld {
		if r >= '0' && r <= '9' {
			return false
		}
	}
	return true
}

func validateDNI(errs *Errors, dni []byte) {
	const field = "dni"

	if len(dni) == 0 {
		errs.add(field, CodeRequired, "el DNI es obligatorio")
		return
	}
	if len(dni) < MinDNIDigits || len(dni) > MaxDNIDigits {
		errs.add(field, CodeLength, fmt.Sprintf("el DNI debe tener entre %d y %d dígitos", MinDNIDigits, MaxDNIDigits))
		return
	}

	for _, b := range dni {
		if b < '0' || b > '9' {
			errs.add(field, CodeFormat, "el DNI solo puede contener dígitos")
			return
		}
	}

	// Un DNI argentino no se escribe con ceros a la izquierda: aceptarlos
	// permitiría registrar 0123456 y 123456 como personas distintas.
	if dni[0] == '0' {
		errs.add(field, CodeFormat, "el DNI no puede empezar con cero")
	}
}

func validatePassword(errs *Errors, pwd []byte) {
	const field = "password"

	if len(pwd) == 0 {
		errs.add(field, CodeRequired, "la contraseña es obligatoria")
		return
	}
	if !utf8.Valid(pwd) {
		errs.add(field, CodeFormat, "la contraseña debe ser texto UTF-8 válido")
		return
	}

	// Se cuenta en runas, no en bytes: con acentos o emoji, contar bytes
	// rechazaría contraseñas que el usuario ve como suficientemente largas.
	length := utf8.RuneCount(pwd)
	if length < MinPasswordLength || length > MaxPasswordLength {
		errs.add(field, CodeLength, fmt.Sprintf("la contraseña debe tener entre %d y %d caracteres", MinPasswordLength, MaxPasswordLength))
		return
	}

	var lower, upper, digit, symbol, control bool
	for _, r := range string(pwd) {
		switch {
		case unicode.IsControl(r):
			control = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			symbol = true
		}
	}

	if control {
		errs.add(field, CodeFormat, "la contraseña no puede contener caracteres de control")
		return
	}

	classes := 0
	for _, present := range []bool{lower, upper, digit, symbol} {
		if present {
			classes++
		}
	}
	if classes < MinPasswordClasses {
		errs.add(field, CodeWeak, "la contraseña debe combinar minúsculas, mayúsculas, dígitos y símbolos")
	}
}

// validatePasswordSimilarity descarta las contraseñas derivadas de datos que el
// atacante ya conoce o puede adivinar. Cumplir las cuatro clases de caracteres
// no sirve de nada si la contraseña es el propio DNI con un signo al final.
func validatePasswordSimilarity(errs *Errors, pwd []byte, email string, dni []byte) {
	const field = "password"

	if len(pwd) == 0 || !utf8.Valid(pwd) {
		return // Ya se reportó como ausente o malformada.
	}

	lowered := strings.ToLower(string(pwd))

	if len(dni) > 0 && strings.Contains(lowered, string(dni)) {
		errs.add(field, CodeSimilarity, "la contraseña no puede contener el DNI")
	}

	if local, _, found := strings.Cut(email, "@"); found && len(local) >= 3 && strings.Contains(lowered, strings.ToLower(local)) {
		errs.add(field, CodeSimilarity, "la contraseña no puede contener el nombre de usuario del email")
	}
}
