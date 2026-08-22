// Package ownership implementa el caso de uso de US-04: confirmar si el DNI
// que Vehicle reenvía corresponde al usuario dueño de la sesión activa, sin
// que Identity vea nunca la patente ni devuelva nada más que un booleano.
//
// Depende únicamente de los puertos de domain, igual que
// internal/service/signin y internal/service/session, para poder ejercitarse
// entero con dobles, sin Postgres.
package ownership

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/secure"
	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/validation"
)

// Deps son las dependencias del servicio. Todas son puertos de domain.
type Deps struct {
	Decryptor domain.HPKEDecryptor
	Indexer   domain.BlindIndexer
	Users     domain.UserRepository
	Logger    *slog.Logger
}

// Service es el caso de uso de /internal/verify-ownership.
type Service struct {
	deps Deps
}

// New valida que estén todas las dependencias y construye el servicio.
func New(d Deps) (*Service, error) {
	switch {
	case d.Decryptor == nil:
		return nil, errors.New("ownership: falta el descifrador HPKE")
	case d.Indexer == nil:
		return nil, errors.New("ownership: falta el generador de Blind Index")
	case d.Users == nil:
		return nil, errors.New("ownership: falta el repositorio de usuarios")
	}

	if d.Logger == nil {
		d.Logger = slog.Default()
	}

	return &Service{deps: d}, nil
}

// VerifyOwnership confirma si el DNI cifrado en cryptogram corresponde al
// usuario ownerID.
//
// cryptogram es dni_enc tal como lo reenvía Vehicle sin abrirlo: un único
// blob HPKE (enc || ciphertext), a diferencia de las dos piezas separadas
// que reciben /signup y /signin — ver domain.HPKEDecryptor.DecryptCombined.
//
// La respuesta es siempre un booleano puro. Que ownerID no corresponda a
// ningún usuario y que corresponda a un usuario con otro DNI producen,
// indistinguiblemente, match=false: los dos son domain.ErrUserNotFound desde
// UserRepository.FindByOwnerAndDNIHash, que combina ambas condiciones en una
// sola consulta (AND) precisamente para no tener que distinguirlas acá. El
// único error que puede devolver esta función es el del descifrado —
// criptograma mal formado o que no autentica—; un fallo al consultar el
// repositorio se envuelve y se propaga como un error de infraestructura, para
// que el handler lo traduzca a 500 sin que se confunda con un match=false.
//
// El DNI en claro existe únicamente durante esta función, como []byte, y se
// limpia con defer antes de volver, tanto si la verificación falla como si
// termina en éxito (Zero-Retention, ver CLAUDE.md). Nunca se convierte a
// string ni se loguea.
func (s *Service) VerifyOwnership(ctx context.Context, ownerID uuid.UUID, cryptogram []byte) (match bool, err error) {
	plaintext, err := s.deps.Decryptor.DecryptCombined(cryptogram)
	if err != nil {
		return false, err
	}
	defer secure.Wipe(plaintext)

	dni := validation.NormalizeDNI(plaintext)
	defer secure.Wipe(dni)

	dniHashed := s.deps.Indexer.Index(dni)

	_, err = s.deps.Users.FindByOwnerAndDNIHash(ctx, ownerID, dniHashed)
	switch {
	case err == nil:
		s.logResult(ctx, ownerID, true)
		return true, nil

	case errors.Is(err, domain.ErrUserNotFound):
		s.logResult(ctx, ownerID, false)
		return false, nil

	default:
		return false, fmt.Errorf("ownership: no se pudo verificar la titularidad: %w", err)
	}
}

// logResult deja constancia de cada verificación, exista o no coincidencia:
// es el endpoint que CLAUDE.md señala como un oráculo potencial de fuerza
// bruta sobre el DNI, y un registro por owner_id (nunca por DNI ni por el
// motivo de un false) es lo que permite detectar un volumen de consultas
// anómalo desde el lado de Identity.
func (s *Service) logResult(ctx context.Context, ownerID uuid.UUID, match bool) {
	s.deps.Logger.InfoContext(ctx, "verificación de titularidad",
		slog.String("owner_id", ownerID.String()),
		slog.Bool("match", match),
	)
}
