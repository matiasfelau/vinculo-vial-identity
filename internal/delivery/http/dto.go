package http

import "github.com/matiasfelau/vinculo-vial-identity/internal/validation"

// signUpRequest es el único dato que este servicio acepta en el alta.
//
// El cuerpo no lleva email, DNI ni contraseña: los tres viajan dentro del
// criptograma, cifrados extremo a extremo desde el dispositivo. Ni el gateway ni
// los logs de acceso ven nada más que un blob opaco en base64.
type signUpRequest struct {
	Cryptogram string `json:"cryptogram"`
}

// signUpResponse acompaña al 201. No incluye tokens: la emisión de sesión es
// US-02. El identificador es opaco y solo sirve para que la app correlacione el
// alta con sus propios logs.
type signUpResponse struct {
	UserID string `json:"userId"`
}

// Códigos de error de la API. Son estables y la app decide el texto a mostrar;
// el campo `error` es para diagnóstico humano, no para parsear.
const (
	codeInvalidRequest = "solicitud_invalida"
	codeInvalidInput   = "datos_invalidos"
	codeConflict       = "registro_no_disponible"
	codeInternal       = "error_interno"
)

// errorResponse es la forma única de todos los errores de la API.
type errorResponse struct {
	Code    string                  `json:"code"`
	Error   string                  `json:"error"`
	Details []validation.FieldError `json:"details,omitempty"`
	// RequestID permite correlacionar la respuesta con el log del servidor sin
	// exponer nada del fallo en el cuerpo.
	RequestID string `json:"requestId,omitempty"`
}
