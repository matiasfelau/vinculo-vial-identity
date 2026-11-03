// Package legalhold sella el DNI de un usuario dado de baja hacia el
// responsable legal (US-11) y lo abre con la clave privada que ese responsable
// custodia fuera de línea.
//
// El mecanismo es HPKE RFC 9180 modo base, la misma suite que el resto del
// servicio (DHKEM X25519 / HKDF-SHA256 / AES-256-GCM), pero con un par de
// claves aparte: este servicio solo conoce la pública (LEGAL_HOLD_PUBLIC_KEY),
// así que no puede reabrir lo que selló. Eso es lo que hace que el hold sea
// ilegible para cualquiera que acceda a la base.
//
// El `info` de cada sellado queda atado al usuario ("vv-legal-hold:" +
// user_id): un criptograma copiado a la fila de otro usuario no abre.
package legalhold

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/hpke"
	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// infoPrefix es el prefijo del `info` de HPKE; el contrato lo fija.
const infoPrefix = "vv-legal-hold:"

// probePlaintext es lo que New sella una vez, en el arranque, para comprobar
// que la clave pública es utilizable. No es dato de nadie.
const probePlaintext = "vv-legal-hold-probe"

// Info devuelve el `info` de HPKE del hold de userID: UTF-8 de
// "vv-legal-hold:" + user_id.
func Info(userID uuid.UUID) []byte {
	return []byte(infoPrefix + userID.String())
}

// Sealer implementa domain.LegalHoldSealer.
type Sealer struct {
	publicKey string
}

var _ domain.LegalHoldSealer = (*Sealer)(nil)

// New construye el Sealer con la clave pública X25519 en base64 estándar.
//
// Sella una vez un valor de prueba: una clave mal formada, con el largo
// equivocado o que no es un punto válido de la curva hace fallar el arranque, no
// la primera baja de un usuario real.
func New(publicKey string) (*Sealer, error) {
	if publicKey == "" {
		return nil, errors.New("legalhold: falta la clave pública del responsable legal")
	}
	if _, _, err := hpke.Seal(publicKey, Info(uuid.Nil), []byte(probePlaintext)); err != nil {
		return nil, fmt.Errorf("legalhold: la clave pública no es utilizable: %w", err)
	}
	return &Sealer{publicKey: publicKey}, nil
}

// Seal cifra el DNI hacia el responsable legal y devuelve base64 de enc‖ct,
// el formato de legal_hold.user_holds.dni_sealed.
func (s *Sealer) Seal(userID uuid.UUID, dni []byte) (string, error) {
	if userID == uuid.Nil {
		return "", errors.New("legalhold: falta el usuario")
	}
	if len(dni) == 0 {
		return "", errors.New("legalhold: no hay DNI que sellar")
	}

	enc, ct, err := hpke.Seal(s.publicKey, Info(userID), dni)
	if err != nil {
		return "", fmt.Errorf("legalhold: no se pudo sellar el DNI: %w", err)
	}

	sealed := make([]byte, 0, len(enc)+len(ct))
	sealed = append(sealed, enc...)
	sealed = append(sealed, ct...)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Open revierte Seal con la clave privada X25519 en base64 estándar. Solo lo
// usa la herramienta fuera de línea cmd/legalhold-open, ante un requerimiento
// judicial; el servicio nunca lo llama.
//
// Todo fallo de apertura devuelve el mismo error, sin detalle criptográfico.
// El llamador es responsable de limpiar el DNI devuelto.
func Open(privateKey string, userID uuid.UUID, sealed string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return nil, errors.New("legalhold: el criptograma no es base64 estándar válido")
	}

	dec, err := hpke.NewDecryptorFromBase64(privateKey, Info(userID))
	if err != nil {
		return nil, fmt.Errorf("legalhold: clave privada inválida: %w", err)
	}

	dni, err := dec.DecryptCombined(raw)
	if err != nil {
		return nil, errors.New("legalhold: no se pudo abrir el criptograma: clave, usuario o criptograma no coinciden")
	}
	return dni, nil
}
