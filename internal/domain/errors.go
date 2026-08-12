package domain

import (
	"errors"
	"fmt"
)

// Errores centinela del dominio. La capa de delivery los traduce a códigos HTTP
// con errors.Is; ninguna capa externa debería inspeccionar el texto del error.
var (
	// ErrDuplicateUser indica que el email o el Blind Index del DNI ya existen.
	// Se devuelve de forma deliberadamente ambigua (sin decir cuál de los dos
	// colisionó) para no habilitar enumeración de usuarios. → 409 Conflict.
	ErrDuplicateUser = errors.New("domain: el usuario ya existe")

	// ErrInvalidInput indica que el payload, una vez descifrado, no pasó las
	// validaciones de formato o fortaleza. → 400 Bad Request.
	ErrInvalidInput = errors.New("domain: datos de registro inválidos")

	// ErrInvalidCryptogram indica que el criptograma HPKE no pudo descifrarse:
	// clave equivocada, wire format corrupto o AEAD que no autentica.
	//
	// Se mapea a 500 por decisión de US-01: el cliente legítimo siempre cifra
	// con la clave pública vigente del servicio, así que un fallo acá es una
	// desincronización de claves o una manipulación. La respuesta nunca expone
	// el detalle criptográfico.
	ErrInvalidCryptogram = errors.New("domain: no se pudo descifrar el criptograma")

	// ErrInvalidUser indica que se intentó construir una entidad inconsistente.
	// Es un error de programación, no un dato inválido del cliente. → 500.
	ErrInvalidUser = errors.New("domain: usuario inconsistente")
)

func invalidUser(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalidUser, reason)
}
