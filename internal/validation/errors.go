package validation

import (
	"strings"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// Códigos de error estables. Viajan en el cuerpo del 400 para que la app pueda
// resaltar el campo y mostrar su propio mensaje traducido, sin parsear texto.
const (
	CodeRequired   = "requerido"
	CodeFormat     = "formato_invalido"
	CodeLength     = "longitud_invalida"
	CodeWeak       = "password_debil"
	CodeSimilarity = "password_predecible"
)

// FieldError describe el rechazo de un campo concreto.
//
// Nunca incluye el valor rechazado: el DNI y la contraseña no pueden aparecer
// en una respuesta HTTP ni, por transitividad, en los logs de acceso del gateway.
type FieldError struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Errors es el conjunto de rechazos de una validación.
//
// Se acumulan todos en lugar de cortar en el primero para que la app pueda
// corregir el formulario completo en un solo intento.
type Errors []FieldError

func (e Errors) Error() string {
	if len(e) == 0 {
		return "validación exitosa"
	}

	var sb strings.Builder
	sb.WriteString("datos de registro inválidos: ")
	for i, fe := range e {
		if i > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString(fe.Field)
		sb.WriteString(": ")
		sb.WriteString(fe.Message)
	}
	return sb.String()
}

// Is hace que errors.Is(err, domain.ErrInvalidInput) sea verdadero, de modo que
// la capa de delivery mapee a 400 sin conocer este paquete.
func (e Errors) Is(target error) bool {
	return target == domain.ErrInvalidInput
}

// OrNil devuelve nil cuando no hubo rechazos, para poder asignar el resultado
// directamente a un error sin caer en el clásico nil-interface no nulo.
func (e Errors) OrNil() error {
	if len(e) == 0 {
		return nil
	}
	return e
}

func (e *Errors) add(field, code, message string) {
	*e = append(*e, FieldError{Field: field, Code: code, Message: message})
}
