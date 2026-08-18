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

	// ErrInvalidCryptogram indica que el mensaje HPKE no pudo descifrarse pese a
	// estar bien formado: clave equivocada o AEAD que no autentica.
	//
	// Se mapea a 500 por decisión de US-01: el cliente legítimo siempre cifra
	// con la clave pública vigente del servicio, así que un fallo acá es una
	// desincronización de claves o una manipulación. La respuesta nunca expone
	// el detalle criptográfico.
	ErrInvalidCryptogram = errors.New("domain: no se pudo descifrar el criptograma")

	// ErrMalformedCryptogram indica que el mensaje ni siquiera tiene la forma de
	// un mensaje HPKE: la clave pública efímera no mide lo que el KEM define, o
	// falta una de las dos piezas. → 400 Bad Request.
	//
	// Se distingue de ErrInvalidCryptogram porque son fallos de naturaleza
	// distinta y merecen respuestas distintas. Un largo equivocado es
	// verificable sin tocar la clave privada y sin intentar abrir nada: es un
	// cliente mal implementado, y decírselo con un 400 le ahorra perseguir un
	// fallo del servidor que no existe. Tampoco filtra nada, porque la longitud
	// que se rechaza es la que el propio cliente acaba de enviar.
	ErrMalformedCryptogram = errors.New("domain: el criptograma está mal formado")

	// ErrInvalidUser indica que se intentó construir una entidad inconsistente.
	// Es un error de programación, no un dato inválido del cliente. → 500.
	ErrInvalidUser = errors.New("domain: usuario inconsistente")

	// ErrIdentityNotVerified indica que RenaperService respondió pero no pudo
	// confirmar que dni, tramite, sexo y selfie corresponden a la misma persona
	// real. A diferencia de ErrInvalidInput, los datos están bien formados: es
	// una autoridad externa la que no los validó. → 400 Bad Request, con mensaje
	// genérico: precisar si falló el trámite, el sexo o la selfie facilitaría
	// tantear los datos de otra persona hasta acertar.
	ErrIdentityNotVerified = errors.New("domain: RENAPER no pudo verificar la identidad")
)

func invalidUser(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalidUser, reason)
}
