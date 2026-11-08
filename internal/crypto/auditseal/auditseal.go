// Package auditseal sella el DNI de un emisor hacia el Audit Service (US-11,
// Audit): Identity lo abre con AES_KEY, lo sella con la clave pública de Audit y
// lo entrega a Alert, que lo guarda solo en su outbox hasta publicarlo.
//
// El mecanismo es HPKE RFC 9180 modo base, la misma suite que el resto del
// servicio (DHKEM X25519 / HKDF-SHA256 / AES-256-GCM), pero con un par de
// claves aparte: este servicio solo conoce la pública (AUDIT_PUBLIC_KEY), así
// que no puede reabrir lo que selló. La privada se genera fuera de línea con
// audit-keygen, la custodia el responsable legal y ningún servicio la carga.
//
// El `info` de cada sellado queda atado a la alerta y al campo
// ("vv-audit:dni:" + alert_id): un criptograma movido al registro de otra
// alerta, o hecho pasar por la patente, no abre.
package auditseal

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/hpke"
	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// infoPrefix es el prefijo del `info` de HPKE del DNI; el contrato lo fija.
const infoPrefix = "vv-audit:dni:"

// probePlaintext es lo que New sella una vez, en el arranque, para comprobar
// que la clave pública es utilizable. No es dato de nadie.
const probePlaintext = "vv-audit-probe"

// MaxKeyIDLength es el largo máximo de AUDIT_KEY_ID: la columna audit_key_id de
// Audit es varchar(32).
const MaxKeyIDLength = 32

// keyIDPattern limita AUDIT_KEY_ID a caracteres que sobreviven a donde viaja:
// audit-open lee las claves privadas como líneas `audit_key_id=base64`, así que
// el id no puede llevar '=' ni espacios.
var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// Info devuelve el `info` de HPKE del DNI de la alerta alertID: UTF-8 de
// "vv-audit:dni:" + alert_id.
func Info(alertID uuid.UUID) []byte {
	return []byte(infoPrefix + alertID.String())
}

// Sealer implementa domain.AuditSealer.
type Sealer struct {
	publicKey string
	keyID     string
}

var _ domain.AuditSealer = (*Sealer)(nil)

// New construye el Sealer con la clave pública X25519 de Audit en base64
// estándar y el id corto que la identifica (por ejemplo, "2026-11").
//
// Sella una vez un valor de prueba: una clave mal formada, con el largo
// equivocado o que no es un punto válido de la curva hace fallar el arranque, no
// la primera alerta de un usuario real.
func New(publicKey, keyID string) (*Sealer, error) {
	if publicKey == "" {
		return nil, errors.New("auditseal: falta la clave pública de Audit")
	}
	if keyID == "" || len(keyID) > MaxKeyIDLength || !keyIDPattern.MatchString(keyID) {
		return nil, fmt.Errorf("auditseal: el id de la clave debe tener entre 1 y %d caracteres de [A-Za-z0-9._-]", MaxKeyIDLength)
	}
	if _, _, err := hpke.Seal(publicKey, Info(uuid.Nil), []byte(probePlaintext)); err != nil {
		return nil, fmt.Errorf("auditseal: la clave pública no es utilizable: %w", err)
	}
	return &Sealer{publicKey: publicKey, keyID: keyID}, nil
}

// SealDNI cifra el DNI hacia Audit y devuelve base64 de enc‖ct, el formato de
// dni_enc_audit, junto con el id de la clave.
func (s *Sealer) SealDNI(alertID uuid.UUID, dni []byte) (domain.AuditDNI, error) {
	if alertID == uuid.Nil {
		return domain.AuditDNI{}, errors.New("auditseal: falta la alerta")
	}
	if len(dni) == 0 {
		return domain.AuditDNI{}, errors.New("auditseal: no hay DNI que sellar")
	}

	enc, ct, err := hpke.Seal(s.publicKey, Info(alertID), dni)
	if err != nil {
		return domain.AuditDNI{}, fmt.Errorf("auditseal: no se pudo sellar el DNI: %w", err)
	}

	sealed := make([]byte, 0, len(enc)+len(ct))
	sealed = append(sealed, enc...)
	sealed = append(sealed, ct...)
	return domain.AuditDNI{Sealed: base64.StdEncoding.EncodeToString(sealed), KeyID: s.keyID}, nil
}
