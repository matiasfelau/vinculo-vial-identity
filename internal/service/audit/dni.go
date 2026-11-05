// Package audit implementa el lado de Identity del registro de auditoría de
// US-11: sellar el DNI del emisor de una alerta hacia el Audit Service. Alert
// llama a este caso de uso antes de crear la alerta y guarda el criptograma solo
// en su outbox, hasta publicarlo.
//
// Depende únicamente de los puertos de domain, igual que el resto de
// internal/service, para ejercitarse entero con dobles, sin Postgres.
package audit

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/secure"
	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// UserFinder es lo único que el sellado necesita del repositorio de usuarios,
// declarado del lado del consumidor.
type UserFinder interface {
	FindByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
}

// Deps son las dependencias de DNIService.
type Deps struct {
	Users UserFinder
	// Cipher abre users.dni_encrypted: el DNI en claro solo existe un instante,
	// para sellarlo hacia Audit.
	Cipher domain.SymmetricCipher
	Sealer domain.AuditSealer
}

// DNIService es el caso de uso de POST /internal/audit/dni.
type DNIService struct {
	deps Deps
}

// NewDNIService valida las dependencias y construye el servicio. Se falla en el
// arranque y no en la primera alerta: una dependencia faltante es un error de
// cableado.
func NewDNIService(d Deps) (*DNIService, error) {
	switch {
	case d.Users == nil:
		return nil, errors.New("audit: falta el repositorio de usuarios")
	case d.Cipher == nil:
		return nil, errors.New("audit: falta el cifrador at-rest")
	case d.Sealer == nil:
		return nil, errors.New("audit: falta el sellador hacia Audit")
	}
	return &DNIService{deps: d}, nil
}

// SealDNI abre el DNI guardado del usuario userID y lo sella hacia Audit, con el
// `info` atado a alertID.
//
// Devuelve domain.ErrUserNotFound (envuelto) si el usuario no existe, que Alert
// traduce en 403 ACCOUNT_DELETED: es el caso de una baja que se cruzó con el
// envío. Un error de la base llega envuelto en domain.ErrDatabaseUnavailable si
// no respondió.
//
// El DNI en claro existe únicamente durante esta función, como []byte, y se
// limpia con defer antes de volver, tanto si el sellado falla como si termina en
// éxito (Zero-Retention). Nunca se convierte a string ni se loguea, y esta
// función tampoco loguea el criptograma ni el par usuario-alerta: ese vínculo
// solo tiene que existir en el registro de Audit.
func (s *DNIService) SealDNI(ctx context.Context, userID, alertID uuid.UUID) (domain.AuditDNI, error) {
	if userID == uuid.Nil {
		return domain.AuditDNI{}, errors.New("audit: falta el usuario")
	}
	if alertID == uuid.Nil {
		return domain.AuditDNI{}, errors.New("audit: falta la alerta")
	}

	user, err := s.deps.Users.FindByID(ctx, userID)
	if err != nil {
		return domain.AuditDNI{}, fmt.Errorf("audit: no se pudo leer al usuario: %w", err)
	}

	dni, err := s.deps.Cipher.Decrypt(user.DNIEncrypted)
	if err != nil {
		return domain.AuditDNI{}, fmt.Errorf("audit: no se pudo abrir el DNI guardado: %w", err)
	}
	defer secure.Wipe(dni)

	sealed, err := s.deps.Sealer.SealDNI(alertID, dni)
	if err != nil {
		return domain.AuditDNI{}, fmt.Errorf("audit: no se pudo sellar el DNI: %w", err)
	}
	return sealed, nil
}
