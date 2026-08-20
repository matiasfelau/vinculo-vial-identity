// Package signin implementa el caso de uso CU-02: el inicio de sesión de un
// vecino ya registrado.
//
// Orquesta la secuencia completa —descifrar, validar, buscar, verificar,
// emitir— dependiendo únicamente de los puertos de domain, igual que
// internal/service/signup, de modo que se puede ejercitar entera con dobles,
// sin Postgres.
package signin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/secure"
	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/validation"
)

// dummyPassword no es la contraseña de ningún usuario real: existe únicamente
// para pagar el costo de un argon2.Verify cuando el DNI no corresponde a
// ningún usuario, de modo que "DNI inexistente" y "contraseña incorrecta"
// tarden lo mismo. Ver New, donde se deriva el hash dummy una única vez.
const dummyPassword = "defensa-de-timing-vinculo-vial-esto-no-es-una-contraseña-real"

// payload es el contenido descifrado del mensaje HPKE del login, tal como lo
// arma la app.
type payload struct {
	DNI      string `json:"dni"`
	Password string `json:"password"`
}

// Deps son las dependencias del servicio. Todas son puertos de domain.
type Deps struct {
	Decryptor domain.HPKEDecryptor
	Indexer   domain.BlindIndexer
	Hasher    domain.PasswordHasher
	Users     domain.UserRepository
	Sessions  domain.SessionRepository
	Tokens    domain.TokenGenerator
	Logger    *slog.Logger
	// Now permite fijar el reloj en los tests. Si es nil se usa time.Now.
	Now func() time.Time
}

// Service es el caso de uso de login.
type Service struct {
	deps Deps
	// dummyHash es el hash Argon2id de dummyPassword, derivado una única vez en
	// New. Ver la nota de dummyPassword.
	dummyHash string
}

// New valida que estén todas las dependencias y construye el servicio.
//
// Deriva acá el hash dummy de la defensa de timing en lugar de en cada
// petición: derivarlo en cada intento fallido repetiría el costo de Argon2id
// sin necesidad, y derivarlo recién en la primera petición real dejaría esa
// primera respuesta con una latencia distinta a las que siguen.
func New(d Deps) (*Service, error) {
	switch {
	case d.Decryptor == nil:
		return nil, errors.New("signin: falta el descifrador HPKE")
	case d.Indexer == nil:
		return nil, errors.New("signin: falta el generador de Blind Index")
	case d.Hasher == nil:
		return nil, errors.New("signin: falta el hasher de contraseñas")
	case d.Users == nil:
		return nil, errors.New("signin: falta el repositorio de usuarios")
	case d.Sessions == nil:
		return nil, errors.New("signin: falta el repositorio de sesiones")
	case d.Tokens == nil:
		return nil, errors.New("signin: falta el generador de tokens")
	}

	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}

	dummyHash, err := d.Hasher.Hash([]byte(dummyPassword))
	if err != nil {
		return nil, fmt.Errorf("signin: no se pudo preparar la defensa de timing: %w", err)
	}

	return &Service{deps: d, dummyHash: dummyHash}, nil
}

// SignIn autentica a un vecino a partir del mensaje HPKE que envía la app,
// cuyas dos piezas —la clave pública efímera del emisor y el ciphertext—
// llegan separadas desde la capa HTTP.
//
// Devuelve el par de tokens de la sesión nueva y, ante fallos, uno de los
// centinelas de domain: ErrInvalidCryptogram, ErrInvalidInput o
// ErrInvalidCredentials. Este último es deliberadamente el mismo tanto si el
// DNI no corresponde a ningún usuario como si la contraseña no verifica: ver
// la nota de domain.ErrInvalidCredentials.
//
// El DNI y la contraseña en claro solo existen dentro de esta función y se
// limpian antes de volver, tanto si el login falla como si termina en éxito.
func (s *Service) SignIn(ctx context.Context, ephemeralPublicKey, ciphertext []byte) (accessToken, refreshToken string, err error) {
	plaintext, err := s.deps.Decryptor.Decrypt(ephemeralPublicKey, ciphertext)
	if err != nil {
		return "", "", err
	}
	defer secure.Wipe(plaintext)

	var p payload
	if err := json.Unmarshal(plaintext, &p); err != nil {
		// El contenido descifrado es dato del cliente, no un fallo interno: un
		// JSON malformado es un 400, igual que un DNI con letras.
		return "", "", fmt.Errorf("%w: el payload descifrado no es JSON válido", domain.ErrInvalidInput)
	}

	dni := validation.NormalizeDNI([]byte(p.DNI))
	defer secure.Wipe(dni)

	password := []byte(p.Password)
	defer secure.Wipe(password)

	if err := validation.ValidateSignIn(validation.SignInInput{DNI: dni, Password: password}); err != nil {
		return "", "", err
	}

	dniHashed := s.deps.Indexer.Index(dni)

	user, err := s.deps.Users.FindByDNIHashed(ctx, dniHashed)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			// Se paga el costo de un Verify aunque no haya hash real contra el
			// que comparar, para que un DNI inexistente tarde lo mismo que una
			// contraseña incorrecta.
			_, _ = s.deps.Hasher.Verify(password, s.dummyHash)
			s.logFailedAttempt(ctx, dniHashed, "dni inexistente")
			return "", "", domain.ErrInvalidCredentials
		}
		return "", "", fmt.Errorf("signin: no se pudo buscar el usuario: %w", err)
	}

	ok, err := s.deps.Hasher.Verify(password, user.PasswordHash)
	if err != nil {
		// Un hash almacenado que no se puede interpretar es un dato corrupto,
		// no una contraseña incorrecta: no debe colapsarse en el 401 unificado.
		return "", "", fmt.Errorf("signin: no se pudo verificar la contraseña: %w", err)
	}
	if !ok {
		s.logFailedAttempt(ctx, dniHashed, "contraseña incorrecta")
		return "", "", domain.ErrInvalidCredentials
	}

	accessToken, err = s.deps.Tokens.NewAccessToken(user.ID)
	if err != nil {
		return "", "", fmt.Errorf("signin: no se pudo emitir el access token: %w", err)
	}

	refreshToken, hash, expiresAt, err := s.deps.Tokens.NewRefreshToken()
	if err != nil {
		return "", "", fmt.Errorf("signin: no se pudo emitir el refresh token: %w", err)
	}

	session, err := domain.NewSession(user.ID, hash, expiresAt, s.deps.Now())
	if err != nil {
		return "", "", err
	}

	if err := s.deps.Sessions.Create(ctx, session); err != nil {
		// Los tokens ya se generaron, pero sin la sesión persistida el refresh
		// token no verificaría contra nada en /refresh: no tiene sentido
		// devolvérselos al cliente.
		return "", "", fmt.Errorf("signin: no se pudo persistir la sesión: %w", err)
	}

	s.deps.Logger.InfoContext(ctx, "inicio de sesión exitoso", slog.String("user_id", user.ID.String()))

	return accessToken, refreshToken, nil
}

// logFailedAttempt deja constancia de un intento de login rechazado.
//
// Se identifica al usuario por dni_hashed, nunca por el DNI en claro ni por la
// contraseña. El motivo sí se distingue acá porque es un log interno del
// servidor: la respuesta HTTP que recibe el cliente es idéntica en los dos
// casos, que es lo único que importa para no habilitar enumeración.
func (s *Service) logFailedAttempt(ctx context.Context, dniHashed, motivo string) {
	s.deps.Logger.WarnContext(ctx, "intento de inicio de sesión rechazado",
		slog.String("dni_hashed", dniHashed),
		slog.String("motivo", motivo),
	)
}
