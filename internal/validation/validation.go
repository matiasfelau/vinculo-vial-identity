// Package validation aplica el principio Never Trust the Client sobre el
// payload ya descifrado, antes de derivar nada criptográficamente y antes de
// tocar la base de datos.
//
// Que el criptograma HPKE haya abierto correctamente prueba que el emisor tenía
// la clave pública del servicio, no que los datos sean válidos: el cliente sigue
// siendo un dispositivo fuera de nuestro control.
package validation

import (
	"bytes"
	"encoding/base64"
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

	// TramiteDigits es la longitud fija del número de trámite de la cédula
	// argentina vigente.
	TramiteDigits = 11

	// MaxSelfieBytes acota el peso de la selfie ya decodificada. Cuatro
	// megabytes cubre con margen una foto de cámara frontal comprimida en
	// JPEG/PNG sin habilitar que el endpoint se use para subir archivos
	// arbitrariamente grandes. Es un valor de partida, no una medición contra
	// selfies reales: ajustar si la app produce archivos más livianos o más
	// pesados.
	MaxSelfieBytes = 4 << 20
)

// Política de fortaleza de contraseña.
//
// El piso es 8 para alinearse con el mínimo que ya exige el Frontend (agosto
// 2026). Es una relajación deliberada, no neutra: el registro sigue sin exigir
// segundo factor, así que la contraseña sigue siendo la única credencial hasta
// que se implemente US-02, exactamente la misma condición que en su momento
// justificó poner el piso en 12. Si el mínimo del Frontend cambia, o si US-02
// introduce MFA, vale revisar este valor de nuevo — no quedó en 8 porque 8 sea
// evidentemente mejor, quedó en 8 porque las dos partes tienen que exigir lo
// mismo y esta es la decisión de producto. El techo acota el costo de la
// derivación Argon2id.
const (
	MinPasswordLength = 8
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

// NormalizeSexo pasa el sexo registral a mayúscula, en el mismo buffer y sin
// asignar uno nuevo.
//
// A diferencia de NormalizeDNI, acá conviene mutar in-place: el buffer sigue
// siendo el mismo que el llamador limpia con defer más adelante, y no hace
// falta un buffer nuevo porque pasar a mayúscula no cambia la longitud.
func NormalizeSexo(raw []byte) []byte {
	for i, b := range raw {
		if b >= 'a' && b <= 'z' {
			raw[i] = b - ('a' - 'A')
		}
	}
	return raw
}

// SignUpInput son los datos del registro que ValidateSignUp necesita.
//
// Se agrupan en un struct y no en parámetros posicionales porque la mitad son
// []byte de contenido similar (DNI, trámite, sexo): una firma posicional larga
// con varios []byte seguidos es un lugar fácil para transponer dos por error sin
// que el compilador lo vea.
//
// Email, DNI y Sexo deben llegar ya normalizados con NormalizeEmail,
// NormalizeDNI y NormalizeSexo.
type SignUpInput struct {
	Email    string
	Password []byte
	DNI      []byte
	Tramite  []byte
	Sexo     []byte
	// SelfieBase64 es la selfie tal como la mandó el cliente, sin decodificar.
	// ValidateSignUp la decodifica acá mismo: su validez de formato (base64,
	// magic bytes de imagen) solo puede verificarse una vez decodificada, y
	// hacerlo en este paso —en vez de en el llamador— es lo que permite que una
	// selfie inválida se acumule junto al resto de los rechazos en un solo 400,
	// en lugar de cortar antes de validar los demás campos.
	SelfieBase64 string
}

// ValidateSignUp valida el payload de registro y acumula todos los rechazos.
//
// Devuelve la selfie ya decodificada —el único artefacto derivado que el
// llamador necesita después de este punto, para pasarlo a RenaperService— junto
// con el error, si lo hay. Se devuelve incluso cuando otro campo es inválido,
// para que el llamador siempre tenga algo que limpiar con defer, haya fallado la
// validación o no.
func ValidateSignUp(in SignUpInput) ([]byte, error) {
	var errs Errors

	validateEmail(&errs, in.Email)
	validateDNI(&errs, in.DNI)
	validatePassword(&errs, in.Password)
	validatePasswordSimilarity(&errs, in.Password, in.Email, in.DNI)
	validateTramite(&errs, in.Tramite)
	validateSexo(&errs, in.Sexo)
	selfie := validateSelfie(&errs, in.SelfieBase64)

	return selfie, errs.OrNil()
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
		// La longitud recibida ayuda a diagnosticar (¿se está mandando el DNI
		// con puntos sin normalizar del lado del cliente? ¿un campo pisado por
		// otro?) sin revelar ni un dígito del DNI en sí.
		errs.add(field, CodeLength, fmt.Sprintf(
			"el DNI debe tener entre %d y %d dígitos (se recibieron %d)", MinDNIDigits, MaxDNIDigits, len(dni)))
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

func validateTramite(errs *Errors, tramite []byte) {
	const field = "tramite"

	if len(tramite) == 0 {
		errs.add(field, CodeRequired, "el número de trámite es obligatorio")
		return
	}
	if len(tramite) != TramiteDigits {
		errs.add(field, CodeLength, fmt.Sprintf(
			"el número de trámite debe tener %d dígitos (se recibieron %d)", TramiteDigits, len(tramite)))
		return
	}
	for _, b := range tramite {
		if b < '0' || b > '9' {
			errs.add(field, CodeFormat, "el número de trámite solo puede contener dígitos")
			return
		}
	}
}

// sexosValidos son los tres valores que acepta el sexo registral. Se comparan
// después de NormalizeSexo, así que acá ya solo puede llegar mayúscula.
var sexosValidos = map[byte]bool{'M': true, 'F': true, 'X': true}

func validateSexo(errs *Errors, sexo []byte) {
	const field = "sexo"

	if len(sexo) == 0 {
		errs.add(field, CodeRequired, "el sexo registral es obligatorio")
		return
	}
	if len(sexo) != 1 || !sexosValidos[sexo[0]] {
		// A diferencia de DNI/trámite, el sexo no es un identificador de la
		// persona: se puede devolver el valor recibido para que el frontend vea
		// exactamente qué mandó ("Femenino" en vez de "F", un espacio de más,
		// etc.). %q escapa saltos de línea y caracteres de control: sexo llega
		// sin validar todavía en este punto, así que sigue siendo texto
		// arbitrario del cliente.
		errs.add(field, CodeFormat, fmt.Sprintf("el sexo debe ser M, F o X (se recibió %q)", previewValue(sexo, 16)))
	}
}

// previewValue acota lo que se ecoa de un campo no sensible en un mensaje de
// validación. El valor en sí no es el problema (por eso existe esta función en
// vez de omitirlo directamente); un cliente con un bug podría mandar un campo
// desmesuradamente largo, y no hay motivo para que eso infle el mensaje, la
// respuesta HTTP o el log.
func previewValue(b []byte, max int) string {
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "…"
}

// jpegMagic y pngMagic son las cabeceras que identifican cada formato. No se
// intenta decodificar la imagen completa —el costo y la superficie de ataque de
// un decoder de imágenes no se justifican solo para validar un formato de
// entrada—, solo confirmar que el contenido no es un archivo arbitrario
// disfrazado de selfie.
var (
	jpegMagic = []byte{0xFF, 0xD8, 0xFF}
	pngMagic  = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
)

// validateSelfie decodifica y valida la selfie, devolviendo los bytes crudos
// solo cuando es válida (nil en cualquier otro caso, incluida la selfie
// ausente).
func validateSelfie(errs *Errors, raw string) []byte {
	const field = "selfie"

	if raw == "" {
		errs.add(field, CodeRequired, "la selfie es obligatoria")
		return nil
	}

	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		// El tamaño del string recibido no revela nada de la imagen —ni
		// siquiera prueba que sea una imagen— pero sí distingue "no mandaron
		// nada real" de "mandaron algo con la codificación equivocada".
		errs.add(field, CodeFormat, fmt.Sprintf("la selfie debe ser base64 estándar válido (%d bytes recibidos, sin decodificar)", len(raw)))
		return nil
	}
	if len(decoded) == 0 {
		errs.add(field, CodeRequired, "la selfie es obligatoria")
		return nil
	}
	if len(decoded) > MaxSelfieBytes {
		errs.add(field, CodeLength, fmt.Sprintf(
			"la selfie no puede superar los %d bytes decodificada (se recibieron %d)", MaxSelfieBytes, len(decoded)))
		return nil
	}
	if !bytes.HasPrefix(decoded, jpegMagic) && !bytes.HasPrefix(decoded, pngMagic) {
		// Nunca los bytes de la imagen: solo si matcheó contra las cabeceras
		// conocidas, que es exactamente lo que ya se estaba evaluando.
		errs.add(field, CodeFormat, fmt.Sprintf(
			"la selfie debe ser una imagen JPEG o PNG (%d bytes decodificados, no coincide con ninguna cabecera conocida)", len(decoded)))
		return nil
	}

	return decoded
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
