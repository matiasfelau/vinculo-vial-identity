package password_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/password"
)

// Parámetros al mínimo admisible: los tests ejercitan el formato y la lógica,
// no el costo. La política real vive en DefaultParams y se verifica aparte.
func testParams() password.Params {
	p := password.DefaultParams()
	p.MemoryKiB = 19 * 1024
	p.Iterations = 1
	return p
}

func newHasher(t *testing.T) *password.Hasher {
	t.Helper()
	h, err := password.New(testParams())
	if err != nil {
		t.Fatalf("no se pudo construir el hasher: %v", err)
	}
	return h
}

func TestHashYVerify(t *testing.T) {
	h := newHasher(t)
	const pwd = "Rosario-2026!seguro"

	encoded, err := h.Hash([]byte(pwd))
	if err != nil {
		t.Fatalf("no se pudo hashear: %v", err)
	}

	t.Run("acepta la contraseña correcta", func(t *testing.T) {
		ok, err := h.Verify([]byte(pwd), encoded)
		if err != nil {
			t.Fatalf("error inesperado: %v", err)
		}
		if !ok {
			t.Error("la contraseña correcta debería verificar")
		}
	})

	t.Run("rechaza contraseñas incorrectas", func(t *testing.T) {
		for _, wrong := range []string{"", "rosario-2026!seguro", "Rosario-2026!segur", "Rosario-2026!seguro ", "otra"} {
			ok, err := h.Verify([]byte(wrong), encoded)
			if err != nil {
				t.Fatalf("error inesperado con %q: %v", wrong, err)
			}
			if ok {
				t.Errorf("%q no debería verificar", wrong)
			}
		}
	})
}

func TestHashEsSaladoPorLlamada(t *testing.T) {
	h := newHasher(t)
	const pwd = "Rosario-2026!seguro"

	primero, err := h.Hash([]byte(pwd))
	if err != nil {
		t.Fatalf("no se pudo hashear: %v", err)
	}
	segundo, err := h.Hash([]byte(pwd))
	if err != nil {
		t.Fatalf("no se pudo hashear: %v", err)
	}

	// Sin salt por llamada, dos usuarios con la misma contraseña compartirían
	// hash y una única tabla rainbow los rompería a todos.
	if primero == segundo {
		t.Error("dos derivaciones de la misma contraseña no pueden coincidir")
	}

	// Y aun así ambas deben verificar.
	for _, encoded := range []string{primero, segundo} {
		ok, err := h.Verify([]byte(pwd), encoded)
		if err != nil || !ok {
			t.Errorf("el hash %q debería verificar (ok=%v, err=%v)", encoded, ok, err)
		}
	}
}

func TestHashUsaFormatoPHC(t *testing.T) {
	h := newHasher(t)

	encoded, err := h.Hash([]byte("Rosario-2026!seguro"))
	if err != nil {
		t.Fatalf("no se pudo hashear: %v", err)
	}

	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		t.Fatalf("el hash tiene %d segmentos, se esperaban 6: %q", len(parts), encoded)
	}
	if parts[1] != "argon2id" {
		t.Errorf("variante = %q, se esperaba argon2id", parts[1])
	}
	if parts[2] != "v=19" {
		t.Errorf("versión = %q, se esperaba v=19", parts[2])
	}
	if want := "m=19456,t=1,p=1"; parts[3] != want {
		t.Errorf("parámetros = %q, se esperaba %q", parts[3], want)
	}
	if strings.Contains(encoded, "Rosario") {
		t.Error("el hash filtra la contraseña")
	}
}

// Los parámetros viajan dentro del hash justamente para que endurecer la
// política no deje afuera a los usuarios ya registrados.
func TestVerifyUsaLosParametrosDelHashAlmacenado(t *testing.T) {
	debil := testParams()
	viejo, err := password.New(debil)
	if err != nil {
		t.Fatalf("no se pudo construir el hasher: %v", err)
	}

	encoded, err := viejo.Hash([]byte("Rosario-2026!seguro"))
	if err != nil {
		t.Fatalf("no se pudo hashear: %v", err)
	}

	endurecido := debil
	endurecido.MemoryKiB = 64 * 1024
	endurecido.Iterations = 3
	nuevo, err := password.New(endurecido)
	if err != nil {
		t.Fatalf("no se pudo construir el hasher endurecido: %v", err)
	}

	ok, err := nuevo.Verify([]byte("Rosario-2026!seguro"), encoded)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if !ok {
		t.Error("un hash viejo debe seguir verificando tras endurecer la política")
	}
}

func TestNeedsRehash(t *testing.T) {
	debil := testParams()
	viejo, err := password.New(debil)
	if err != nil {
		t.Fatalf("no se pudo construir el hasher: %v", err)
	}
	encodedDebil, err := viejo.Hash([]byte("Rosario-2026!seguro"))
	if err != nil {
		t.Fatalf("no se pudo hashear: %v", err)
	}

	endurecido := debil
	endurecido.MemoryKiB = 64 * 1024
	endurecido.Iterations = 3
	nuevo, err := password.New(endurecido)
	if err != nil {
		t.Fatalf("no se pudo construir el hasher endurecido: %v", err)
	}
	encodedFuerte, err := nuevo.Hash([]byte("Rosario-2026!seguro"))
	if err != nil {
		t.Fatalf("no se pudo hashear: %v", err)
	}

	if needs, err := nuevo.NeedsRehash(encodedDebil); err != nil || !needs {
		t.Errorf("un hash por debajo de la política requiere rehash (needs=%v, err=%v)", needs, err)
	}
	if needs, err := nuevo.NeedsRehash(encodedFuerte); err != nil || needs {
		t.Errorf("un hash acorde a la política no requiere rehash (needs=%v, err=%v)", needs, err)
	}
}

func TestVerifyRechazaHashesMalformados(t *testing.T) {
	h := newHasher(t)

	valido, err := h.Hash([]byte("Rosario-2026!seguro"))
	if err != nil {
		t.Fatalf("no se pudo hashear: %v", err)
	}
	parts := strings.Split(valido, "$")

	cases := map[string]struct {
		encoded string
		want    error
	}{
		"vacío":                {"", password.ErrInvalidHash},
		"sin estructura":       {"no-es-un-hash", password.ErrInvalidHash},
		"segmentos de menos":   {"$argon2id$v=19$m=19456,t=1,p=1$" + parts[4], password.ErrInvalidHash},
		"otra variante":        {"$argon2i$" + strings.Join(parts[2:], "$"), password.ErrInvalidHash},
		"versión ilegible":     {"$argon2id$v=xx$" + strings.Join(parts[3:], "$"), password.ErrInvalidHash},
		"versión incompatible": {"$argon2id$v=16$" + strings.Join(parts[3:], "$"), password.ErrIncompatibleVersion},
		"parámetros ilegibles": {"$argon2id$v=19$m=abc,t=1,p=1$" + strings.Join(parts[4:], "$"), password.ErrInvalidHash},
		"salt no base64":       {"$argon2id$v=19$m=19456,t=1,p=1$!!!$" + parts[5], password.ErrInvalidHash},
		"hash no base64":       {"$argon2id$v=19$m=19456,t=1,p=1$" + parts[4] + "$!!!", password.ErrInvalidHash},
		"salt vacío":           {"$argon2id$v=19$m=19456,t=1,p=1$$" + parts[5], password.ErrInvalidHash},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ok, err := h.Verify([]byte("Rosario-2026!seguro"), tc.encoded)
			if !errors.Is(err, tc.want) {
				t.Errorf("error = %v, se esperaba %v", err, tc.want)
			}
			if ok {
				t.Error("un hash malformado nunca debe verificar")
			}
		})
	}
}

func TestRechazaContrasenasDesmesuradas(t *testing.T) {
	h := newHasher(t)
	enorme := make([]byte, password.MaxPasswordLength+1)

	if _, err := h.Hash(enorme); !errors.Is(err, password.ErrPasswordTooLong) {
		t.Errorf("Hash: error = %v, se esperaba ErrPasswordTooLong", err)
	}
	if _, err := h.Verify(enorme, "$argon2id$v=19$m=19456,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaA"); !errors.Is(err, password.ErrPasswordTooLong) {
		t.Errorf("Verify: error = %v, se esperaba ErrPasswordTooLong", err)
	}
}

func TestNewRechazaPoliticasDebiles(t *testing.T) {
	cases := map[string]func(*password.Params){
		"poca memoria": func(p *password.Params) { p.MemoryKiB = 8 * 1024 },
		"sin pasadas":  func(p *password.Params) { p.Iterations = 0 },
		"sin carriles": func(p *password.Params) { p.Parallelism = 0 },
		"salt corto":   func(p *password.Params) { p.SaltLength = 8 },
		"hash corto":   func(p *password.Params) { p.KeyLength = 16 },
	}

	for name, degradar := range cases {
		t.Run(name, func(t *testing.T) {
			p := password.DefaultParams()
			degradar(&p)
			if _, err := password.New(p); err == nil {
				t.Error("se esperaba un error por política insuficiente")
			}
		})
	}
}

func TestDefaultParamsCumpleLaPolitica(t *testing.T) {
	if err := password.DefaultParams().Validate(); err != nil {
		t.Errorf("los parámetros por defecto deben ser válidos: %v", err)
	}
}
