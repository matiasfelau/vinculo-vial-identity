package token_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/token"
)

// generar produce un par de claves de prueba una sola vez por paquete: RSA es
// caro de generar y ningún test necesita una clave distinta de otro.
func generar(t *testing.T) (privateKeyPEM, publicKeyPEM string) {
	t.Helper()

	priv, pub, err := token.GenerateKeyPair()
	if err != nil {
		t.Fatalf("no se pudo generar el par de claves: %v", err)
	}
	return priv, pub
}

func nuevoGenerador(t *testing.T) (*token.Generator, string) {
	t.Helper()

	privPEM, pubPEM := generar(t)
	g, err := token.New(privPEM, 15*time.Minute, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("error inesperado al construir el generador: %v", err)
	}
	return g, pubPEM
}

func parsePublicKey(t *testing.T, pemStr string) *rsa.PublicKey {
	t.Helper()

	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("la clave pública de prueba no es un PEM válido")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("no se pudo interpretar la clave pública: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatal("la clave pública generada no es RSA")
	}
	return rsaPub
}

// verificar reproduce del lado del "Gateway" lo que este servicio no necesita
// hacer nunca: separar las tres partes, verificar la firma RS256 y devolver
// los claims decodificados.
func verificar(t *testing.T, jwt string, pub *rsa.PublicKey) map[string]any {
	t.Helper()

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("el JWT no tiene tres segmentos: %q", jwt)
	}

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("el header no es base64url válido: %v", err)
	}
	var h struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(header, &h); err != nil {
		t.Fatalf("el header no es JSON válido: %v", err)
	}
	if h.Alg != "RS256" {
		t.Errorf("alg = %q, se esperaba RS256", h.Alg)
	}
	if h.Typ != "JWT" {
		t.Errorf("typ = %q, se esperaba JWT", h.Typ)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("la firma no es base64url válida: %v", err)
	}

	signingInput := parts[0] + "." + parts[1]
	sum := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("la firma RS256 no verifica: %v", err)
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("los claims no son base64url válido: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatalf("los claims no son JSON válido: %v", err)
	}
	return claims
}

func TestNewAccessTokenEmiteUnJWTRS256Verificable(t *testing.T) {
	g, pubPEM := nuevoGenerador(t)
	pub := parsePublicKey(t, pubPEM)
	userID := uuid.New()

	jwt, err := g.NewAccessToken(userID)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	claims := verificar(t, jwt, pub)

	if claims["sub"] != userID.String() {
		t.Errorf("sub = %v, se esperaba %q", claims["sub"], userID.String())
	}
}

// El Access Token nunca lleva PII: solo sub, iat y exp.
func TestNewAccessTokenNoLlevaMasClaimsQueLosMinimos(t *testing.T) {
	g, pubPEM := nuevoGenerador(t)
	pub := parsePublicKey(t, pubPEM)

	jwt, err := g.NewAccessToken(uuid.New())
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	claims := verificar(t, jwt, pub)
	if len(claims) != 3 {
		t.Errorf("claims = %v, se esperaban exactamente sub, iat y exp", claims)
	}
	for _, campo := range []string{"sub", "iat", "exp"} {
		if _, ok := claims[campo]; !ok {
			t.Errorf("falta el claim %q", campo)
		}
	}
}

func TestNewAccessTokenExpiraSegunElTTLConfigurado(t *testing.T) {
	privPEM, pubPEM := generar(t)
	const ttl = 15 * time.Minute
	g, err := token.New(privPEM, ttl, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	pub := parsePublicKey(t, pubPEM)

	before := time.Now().UTC()
	jwt, err := g.NewAccessToken(uuid.New())
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	after := time.Now().UTC()

	claims := verificar(t, jwt, pub)

	iat := time.Unix(int64(claims["iat"].(float64)), 0)
	exp := time.Unix(int64(claims["exp"].(float64)), 0)

	if iat.Before(before.Add(-time.Second)) || iat.After(after.Add(time.Second)) {
		t.Errorf("iat = %v, fuera de la ventana [%v, %v]", iat, before, after)
	}
	if got, want := exp.Sub(iat), ttl; got != want {
		t.Errorf("exp - iat = %v, se esperaba %v", got, want)
	}
}

func TestNewRefreshTokenEsOpacoYSuHashCoincideConSuPropioSHA256(t *testing.T) {
	g, _ := nuevoGenerador(t)

	before := time.Now().UTC()
	tok, hash, expiresAt, err := g.NewRefreshToken()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if tok == "" {
		t.Fatal("se esperaba un token no vacío")
	}
	if _, err := base64.RawURLEncoding.DecodeString(tok); err != nil {
		t.Errorf("el token debería ser base64url sin relleno: %v", err)
	}

	sum := sha256.Sum256([]byte(tok))
	wantHash := hex.EncodeToString(sum[:])
	if hash != wantHash {
		t.Errorf("hash = %q, se esperaba SHA-256(token) = %q", hash, wantHash)
	}
	if len(hash) != 64 {
		t.Errorf("hash de %d caracteres, se esperaban 64 (hex de 32 bytes)", len(hash))
	}

	wantExpiry := before.Add(30 * 24 * time.Hour)
	if diff := expiresAt.Sub(wantExpiry); diff < -2*time.Second || diff > 2*time.Second {
		t.Errorf("expires_at = %v, se esperaba cerca de %v", expiresAt, wantExpiry)
	}
}

func TestNewRefreshTokenGeneraValoresDistintosEnCadaLlamada(t *testing.T) {
	g, _ := nuevoGenerador(t)

	a, hashA, _, err := g.NewRefreshToken()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	b, hashB, _, err := g.NewRefreshToken()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if a == b {
		t.Error("dos refresh tokens no pueden coincidir")
	}
	if hashA == hashB {
		t.Error("dos hashes de tokens distintos no pueden coincidir")
	}
}

// Hash tiene que recomputar exactamente el mismo hash que NewRefreshToken
// persistió: es lo que /refresh (US-03) necesita para encontrar la sesión a
// partir del token que le devuelve el cliente.
func TestHashCoincideConElHashQueDevuelveNewRefreshToken(t *testing.T) {
	g, _ := nuevoGenerador(t)

	tok, hash, _, err := g.NewRefreshToken()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if got := g.Hash(tok); got != hash {
		t.Errorf("Generator.Hash(tok) = %q, se esperaba %q", got, hash)
	}
	if got := token.Hash(tok); got != hash {
		t.Errorf("token.Hash(tok) = %q, se esperaba %q", got, hash)
	}
}

func TestHashEsDeterministico(t *testing.T) {
	const tok = "un-refresh-token-cualquiera"

	if token.Hash(tok) != token.Hash(tok) {
		t.Error("Hash del mismo token debería producir siempre el mismo resultado")
	}
}

func TestNewAceptaPKCS1YPKCS8(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, token.MinRSAKeyBits)
	if err != nil {
		t.Fatalf("no se pudo generar la clave: %v", err)
	}

	pkcs1 := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("no se pudo serializar en PKCS8: %v", err)
	}
	pkcs8 := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER}))

	for name, pemStr := range map[string]string{"PKCS#1": pkcs1, "PKCS#8": pkcs8} {
		t.Run(name, func(t *testing.T) {
			if _, err := token.New(pemStr, 15*time.Minute, 30*24*time.Hour); err != nil {
				t.Errorf("error inesperado con %s: %v", name, err)
			}
		})
	}
}

func TestNewRechazaEntradasInvalidas(t *testing.T) {
	privPEM, _ := generar(t)

	debilKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("no se pudo generar la clave débil: %v", err)
	}
	debilDER, err := x509.MarshalPKCS8PrivateKey(debilKey)
	if err != nil {
		t.Fatalf("no se pudo serializar la clave débil: %v", err)
	}
	debilPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: debilDER}))

	cases := map[string]struct {
		pemStr     string
		accessTTL  time.Duration
		refreshTTL time.Duration
	}{
		"PEM vacío":                {"", 15 * time.Minute, 30 * 24 * time.Hour},
		"PEM basura":               {"esto no es un PEM", 15 * time.Minute, 30 * 24 * time.Hour},
		"clave por debajo del piso": {debilPEM, 15 * time.Minute, 30 * 24 * time.Hour},
		"access TTL cero":          {privPEM, 0, 30 * 24 * time.Hour},
		"access TTL negativo":      {privPEM, -time.Minute, 30 * 24 * time.Hour},
		"refresh TTL cero":         {privPEM, 15 * time.Minute, 0},
		"refresh TTL negativo":     {privPEM, 15 * time.Minute, -time.Hour},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := token.New(tc.pemStr, tc.accessTTL, tc.refreshTTL); err == nil {
				t.Error("se esperaba un error")
			}
		})
	}
}

func TestGenerateKeyPairProduceUnParUtilizable(t *testing.T) {
	privPEM, pubPEM := generar(t)

	if privPEM == "" || pubPEM == "" {
		t.Fatal("se esperaban ambas claves no vacías")
	}

	g, err := token.New(privPEM, 15*time.Minute, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("la clave generada debería ser aceptada por New: %v", err)
	}

	pub := parsePublicKey(t, pubPEM)
	jwt, err := g.NewAccessToken(uuid.New())
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	verificar(t, jwt, pub) // Falla el test si la firma no corresponde a esta pública.
}
