package emailcode_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/emailcode"
	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

func nuevo(t *testing.T, relleno byte) *emailcode.Codec {
	t.Helper()
	c, err := emailcode.New(bytes.Repeat([]byte{relleno}, emailcode.KeyLength))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestNewExigeElLargoMinimo(t *testing.T) {
	if _, err := emailcode.New(make([]byte, emailcode.KeyLength-1)); err == nil {
		t.Error("una clave de 31 bytes debería rechazarse")
	}
	if _, err := emailcode.New(nil); err == nil {
		t.Error("una clave vacía debería rechazarse")
	}
	if _, err := emailcode.New(make([]byte, emailcode.KeyLength)); err != nil {
		t.Errorf("una clave de 32 bytes debería aceptarse: %v", err)
	}
}

// El Codec no comparte el buffer del llamador: limpiarlo después no cambia los
// HMAC.
func TestNewCopiaLaClave(t *testing.T) {
	clave := bytes.Repeat([]byte{7}, emailcode.KeyLength)
	c, _ := emailcode.New(clave)
	antes := c.SubjectHMAC(domain.EmailChallengePurposePasswordReset, "x")

	clear(clave)

	if despues := c.SubjectHMAC(domain.EmailChallengePurposePasswordReset, "x"); despues != antes {
		t.Error("el HMAC cambió al limpiar el buffer del llamador")
	}
}

func TestNewFromBase64(t *testing.T) {
	valida := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, emailcode.KeyLength))
	if _, err := emailcode.NewFromBase64(valida); err != nil {
		t.Errorf("clave válida: %v", err)
	}
	if _, err := emailcode.NewFromBase64("no es base64 !!!"); err == nil {
		t.Error("una clave que no es base64 debería rechazarse")
	}
	corta := base64.StdEncoding.EncodeToString([]byte("corta"))
	if _, err := emailcode.NewFromBase64(corta); err == nil {
		t.Error("una clave corta debería rechazarse")
	}
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestSubjectHMACEsDeterministicoYAtadoAlPropositoYAlSubject(t *testing.T) {
	c := nuevo(t, 1)
	reset, verif := domain.EmailChallengePurposePasswordReset, domain.EmailChallengePurposeEmailVerification

	a := c.SubjectHMAC(reset, "x@y.com")
	if !hex64.MatchString(a) {
		t.Fatalf("el HMAC %q no son 64 caracteres hexadecimales", a)
	}
	if a != c.SubjectHMAC(reset, "x@y.com") {
		t.Error("el HMAC no es determinístico")
	}
	if a == c.SubjectHMAC(verif, "x@y.com") {
		t.Error("el mismo subject con otro propósito dio el mismo HMAC")
	}
	if a == c.SubjectHMAC(reset, "z@y.com") {
		t.Error("subjects distintos dieron el mismo HMAC")
	}
	if a == nuevo(t, 2).SubjectHMAC(reset, "x@y.com") {
		t.Error("claves distintas dieron el mismo HMAC")
	}
}

// La entrada del HMAC es la del contrato: purpose + ":" + subject. Se fija con un
// vector calculado a mano, para que un cambio de formato —que invalidaría todos
// los desafíos vigentes— no pase desapercibido.
func TestSubjectHMACUsaLaEntradaDelContrato(t *testing.T) {
	c := nuevo(t, 1)
	m := hmac.New(sha256.New, bytes.Repeat([]byte{1}, emailcode.KeyLength))
	m.Write([]byte("PASSWORD_RESET:11111111-1111-1111-1111-111111111111"))
	want := hex.EncodeToString(m.Sum(nil))

	if got := c.SubjectHMAC(domain.EmailChallengePurposePasswordReset, "11111111-1111-1111-1111-111111111111"); got != want {
		t.Errorf("SubjectHMAC = %s, se esperaba %s", got, want)
	}
}

// Ídem para el HMAC del código: id + ":" + código.
func TestCodeHMACUsaLaEntradaDelContrato(t *testing.T) {
	c := nuevo(t, 1)
	id := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	m := hmac.New(sha256.New, bytes.Repeat([]byte{1}, emailcode.KeyLength))
	m.Write([]byte("22222222-2222-2222-2222-222222222222:123456"))
	want := hex.EncodeToString(m.Sum(nil))

	if got := c.CodeHMAC(id, "123456"); got != want {
		t.Errorf("CodeHMAC = %s, se esperaba %s", got, want)
	}
}

func TestCodeHMACEstaAtadoAlDesafio(t *testing.T) {
	c := nuevo(t, 1)
	id := uuid.New()

	h := c.CodeHMAC(id, "123456")
	if !hex64.MatchString(h) {
		t.Fatalf("el HMAC %q no son 64 caracteres hexadecimales", h)
	}
	if h == c.CodeHMAC(uuid.New(), "123456") {
		t.Error("el mismo código en otro desafío dio el mismo HMAC")
	}
	if h == c.CodeHMAC(id, "123457") {
		t.Error("códigos distintos dieron el mismo HMAC")
	}
}

func TestVerifyCode(t *testing.T) {
	c := nuevo(t, 1)
	id := uuid.New()
	guardado := c.CodeHMAC(id, "123456")

	if !c.VerifyCode(id, "123456", guardado) {
		t.Error("el código correcto no verificó")
	}
	if c.VerifyCode(id, "654321", guardado) {
		t.Error("un código incorrecto verificó")
	}
	if c.VerifyCode(uuid.New(), "123456", guardado) {
		t.Error("el código verificó contra otro desafío")
	}
	if c.VerifyCode(id, "123456", "") {
		t.Error("verificó contra un HMAC vacío")
	}
	if c.VerifyCode(id, "123456", guardado[:10]) {
		t.Error("verificó contra un HMAC truncado")
	}
}

func TestNewCodeSonSeisDigitosYNoSeRepitenEnSerie(t *testing.T) {
	c := nuevo(t, 1)
	visto := make(map[string]bool)

	for range 200 {
		code, err := c.NewCode()
		if err != nil {
			t.Fatalf("NewCode: %v", err)
		}
		if len(code) != domain.EmailCodeDigits || strings.Trim(code, "0123456789") != "" {
			t.Fatalf("código %q: se esperaban %d dígitos", code, domain.EmailCodeDigits)
		}
		visto[code] = true
	}
	// 200 códigos de un espacio de 10^6: si casi todos se repiten, no es aleatorio.
	if len(visto) < 190 {
		t.Errorf("solo %d códigos distintos de 200: la fuente no parece aleatoria", len(visto))
	}
}

// El relleno con ceros es lo que impide que 7 se envíe como "7" y deje sin
// dígitos al usuario: se prueba con la función de formato real, sacando códigos
// hasta ver uno que empiece con cero (una de cada diez).
func TestNewCodeConservaLosCerosAlInicio(t *testing.T) {
	c := nuevo(t, 1)
	for range 2000 {
		code, _ := c.NewCode()
		if strings.HasPrefix(code, "0") {
			if len(code) != domain.EmailCodeDigits {
				t.Fatalf("el código %q perdió dígitos", code)
			}
			return
		}
	}
	t.Fatal("en 2000 códigos ninguno empezó con cero: el formato no está rellenando")
}

var base64urlSinRelleno = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func TestNewGrantEs32BytesEnBase64URLSinRellenoYSuHashEsSHA256(t *testing.T) {
	c := nuevo(t, 1)

	token, hash, err := c.NewGrant()
	if err != nil {
		t.Fatalf("NewGrant: %v", err)
	}
	if !base64urlSinRelleno.MatchString(token) {
		t.Errorf("token %q: se esperaban 32 bytes en base64url sin relleno (43 caracteres)", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		t.Errorf("el token decodifica a %d bytes (err=%v), se esperaban 32", len(raw), err)
	}
	if !hex64.MatchString(hash) {
		t.Errorf("hash %q no son 64 caracteres hexadecimales", hash)
	}
	if hash != c.GrantHash(token) {
		t.Error("el hash devuelto no es GrantHash(token)")
	}
}

func TestNewGrantNoSeRepite(t *testing.T) {
	c := nuevo(t, 1)
	a, _, _ := c.NewGrant()
	b, _, _ := c.NewGrant()
	if a == b {
		t.Error("dos grants salieron iguales")
	}
}

// El hash del grant es el SHA-256 sin clave del token: vector conocido.
func TestGrantHashVectorConocido(t *testing.T) {
	// SHA-256("abc")
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := nuevo(t, 1).GrantHash("abc"); got != want {
		t.Errorf("GrantHash(abc) = %s, se esperaba %s", got, want)
	}
	// Sin clave: otra instancia con otra clave da lo mismo.
	if nuevo(t, 9).GrantHash("abc") != want {
		t.Error("el hash del grant no debería depender de la clave")
	}
}
