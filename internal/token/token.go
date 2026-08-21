// Package token emite los dos artefactos de una sesión (US-02): el Access
// Token —un JWT RS256 de vida corta— y el Refresh Token —opaco, de vida larga,
// persistido solo como SHA-256—. Implementa domain.TokenGenerator.
//
// El JWT se firma a mano, sin sumar una librería de terceros: RS256 sobre un
// JSON Web Token son tres segmentos en base64url (header.claims.firma) y una
// firma RSASSA-PKCS1-v1_5 sobre el SHA-256 de los dos primeros —RFC 7515 §3.1
// y RFC 7518 §3.3—, algo que la librería estándar cubre por completo. Este
// servicio nunca necesita verificar un JWT propio —Identity firma, Gateway
// verifica—, así que tampoco hace falta un parser de vuelta.
package token

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
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// MinRSAKeyBits es el piso de tamaño de clave que acepta el generador. 2048
// bits es el mínimo que sigue recomendando NIST con horizonte a varios años;
// por debajo de eso, RS256 deja de ser la parte fuerte del esquema.
const MinRSAKeyBits = 2048

// RefreshTokenBytes es la entropía del Refresh Token opaco: 256 bits, muy por
// encima de lo que un ataque de fuerza bruta puede recorrer, y el mismo orden
// de magnitud que las demás claves del servicio.
const RefreshTokenBytes = 32

// Generator implementa domain.TokenGenerator sobre RS256 (JWT) y crypto/rand
// (Refresh Token opaco). Es seguro para uso concurrente: rsa.PrivateKey no
// tiene estado mutable durante la firma.
type Generator struct {
	privateKey *rsa.PrivateKey
	accessTTL  time.Duration
	refreshTTL time.Duration
}

// New construye el generador a partir de la clave privada RSA en PEM
// (PKCS#1 o PKCS#8, se prueban en ese orden) y los TTL de cada token.
//
// Identity es el único custodio de esta clave: firma acá y en ningún otro
// lugar. Gateway y el resto de la plataforma reciben solo la Public Key
// correspondiente, para verificar.
func New(privateKeyPEM string, accessTTL, refreshTTL time.Duration) (*Generator, error) {
	key, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	if key.N.BitLen() < MinRSAKeyBits {
		return nil, fmt.Errorf("token: la clave RSA mide %d bits, se requieren al menos %d", key.N.BitLen(), MinRSAKeyBits)
	}
	if accessTTL <= 0 {
		return nil, errors.New("token: ACCESS_TOKEN_TTL_MINUTES debe ser positivo")
	}
	if refreshTTL <= 0 {
		return nil, errors.New("token: REFRESH_TOKEN_TTL_DAYS debe ser positivo")
	}

	return &Generator{privateKey: key, accessTTL: accessTTL, refreshTTL: refreshTTL}, nil
}

// parsePrivateKey prueba PKCS#1 y, si no matchea, PKCS#8: son los dos
// formatos que produce cualquier herramienta estándar (openssl genrsa produce
// PKCS#1; openssl genpkey y esta misma herramienta —GenerateKeyPair— producen
// PKCS#8), y aceptar los dos evita que la variante usada para generar la clave
// se vuelva un detalle que hay que recordar.
func parsePrivateKey(raw string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, errors.New("token: JWT_PRIVATE_KEY no es un bloque PEM válido")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("token: no se pudo interpretar JWT_PRIVATE_KEY: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("token: JWT_PRIVATE_KEY no es una clave RSA")
	}
	return key, nil
}

// jwtHeader es fijo: este servicio solo emite RS256, así que el header se
// serializa una única vez en lugar de en cada llamada.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

var encodedHeader = base64.RawURLEncoding.EncodeToString(mustMarshalHeader())

func mustMarshalHeader() []byte {
	b, err := json.Marshal(jwtHeader{Alg: "RS256", Typ: "JWT"})
	if err != nil {
		// jwtHeader es un struct fijo de dos strings: no hay entrada variable
		// que pueda hacer fallar el marshal.
		panic(err)
	}
	return b
}

// accessClaims son los únicos claims del Access Token. Deliberadamente no
// lleva nada más: ni DNI, ni email, ni el Blind Index. Sub es el UUID interno
// del usuario, el único identificador transversal que el resto de la
// plataforma puede usar sin comprometer PII.
type accessClaims struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

// NewAccessToken firma un JWT RS256 con TTL accessTTL. El claim `sub` es
// userID en su representación canónica de UUID.
func (g *Generator) NewAccessToken(userID uuid.UUID) (string, error) {
	now := time.Now().UTC()
	claims := accessClaims{
		Sub: userID.String(),
		Iat: now.Unix(),
		Exp: now.Add(g.accessTTL).Unix(),
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("token: no se pudieron serializar los claims: %w", err)
	}

	signingInput := encodedHeader + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)

	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, g.privateKey, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("token: no se pudo firmar el access token: %w", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// NewRefreshToken genera un token opaco de RefreshTokenBytes bytes de
// entropía, codificado en base64 URL-safe sin relleno, junto con su SHA-256 en
// hexadecimal minúscula —la representación que exige refresh_token_hash— y su
// vencimiento absoluto.
func (g *Generator) NewRefreshToken() (token, hash string, expiresAt time.Time, err error) {
	raw := make([]byte, RefreshTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", "", time.Time{}, fmt.Errorf("token: no se pudo generar el refresh token: %w", err)
	}

	token = base64.RawURLEncoding.EncodeToString(raw)
	return token, Hash(token), time.Now().UTC().Add(g.refreshTTL), nil
}

// Hash calcula el SHA-256 en hexadecimal minúscula de un Refresh Token opaco.
// NewRefreshToken usa esta misma función para derivar el hash que persiste,
// así que /refresh (US-03) recomputa acá exactamente la misma cuenta al
// recibir el token de vuelta del cliente: se hashea la representación
// textual, no bytes crudos, y las dos cuentas coinciden byte a byte.
func Hash(refreshToken string) string {
	sum := sha256.Sum256([]byte(refreshToken))
	return hex.EncodeToString(sum[:])
}

// Hash implementa domain.TokenGenerator.Hash delegando en la función Hash de
// este paquete.
func (g *Generator) Hash(refreshToken string) string {
	return Hash(refreshToken)
}

// GenerateKeyPair genera un par RSA de MinRSAKeyBits bits y lo devuelve en PEM
// —privada en PKCS#8, pública en PKIX—, listo para pegar en JWT_PRIVATE_KEY
// (con los saltos de línea escapados; ver cmd/genkeys) y para distribuir como
// JWT_PUBLIC_KEY al resto de la plataforma. Se usa en cmd/genkeys y en los
// tests.
func GenerateKeyPair() (privateKeyPEM, publicKeyPEM string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, MinRSAKeyBits)
	if err != nil {
		return "", "", fmt.Errorf("token: no se pudo generar el par de claves: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("token: no se pudo serializar la clave privada: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("token: no se pudo serializar la clave pública: %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	return string(privPEM), string(pubPEM), nil
}
