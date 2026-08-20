package http

import "github.com/matiasfelau/vinculo-vial-identity/internal/validation"

// signUpRequest es el único dato que este servicio acepta en el alta: un
// mensaje HPKE en modo BASE, en las dos piezas que fija el contrato compartido.
//
// El cuerpo no lleva email, DNI ni contraseña: los tres viajan dentro del
// ciphertext, cifrados extremo a extremo desde el dispositivo. Ni el gateway ni
// los logs de acceso ven nada más que dos blobs opacos en base64.
type signUpRequest struct {
	// EphemeralPublicKey es el encapsulado del KEM (`enc` en RFC 9180).
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	// Ciphertext es el sellado del AEAD, con su tag.
	Ciphertext string `json:"ciphertext"`
}

// signUpResponse acompaña al 201. No incluye tokens: la emisión de sesión es
// US-02. El identificador es opaco y solo sirve para que la app correlacione el
// alta con sus propios logs.
type signUpResponse struct {
	UserID string `json:"userId"`
}

// signInRequest es el único dato que el login acepta: el mismo wrapper HPKE
// del alta, en las dos piezas que fija el contrato compartido.
//
// El cuerpo no lleva DNI ni contraseña: los dos viajan dentro del ciphertext,
// cifrados extremo a extremo desde el dispositivo — la contraseña es una
// credencial reutilizable, y merece la misma protección de transporte que el
// DNI del alta, a diferencia del refresh token de un solo uso de US-03.
type signInRequest struct {
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	Ciphertext         string `json:"ciphertext"`
}

// signInResponse acompaña al 200: el par de tokens de la sesión recién
// creada.
type signInResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// Códigos de error de la API. Son estables y la app decide el texto a mostrar;
// el campo `error` es para diagnóstico humano, no para parsear.
const (
	codeInvalidRequest      = "solicitud_invalida"
	codeInvalidInput        = "datos_invalidos"
	codeIdentityNotVerified = "identidad_no_verificada"
	codeConflict            = "registro_no_disponible"
	// codeInvalidCredentials es el código único del 401 de /signin, tanto para
	// un DNI inexistente como para una contraseña incorrecta: distinguirlos
	// habilitaría enumerar qué DNIs están registrados.
	codeInvalidCredentials = "credenciales_invalidas"
	codeInternal           = "error_interno"
)

// errorResponse es la forma única de todos los errores de la API.
type errorResponse struct {
	Code  string `json:"code"`
	Error string `json:"error"`
	// Message repite el contenido de Error bajo una clave más explícita. No es
	// información nueva —son deliberadamente el mismo texto—, se agrega porque
	// varios clientes HTTP (y desarrolladores) buscan `message` por convención
	// y no siempre asocian `error` con "acá está el motivo legible". Error se
	// mantiene tal cual para no romper a nadie que ya lo esté leyendo.
	Message string                  `json:"message"`
	Details []validation.FieldError `json:"details,omitempty"`
	// RequestID permite correlacionar la respuesta con el log del servidor sin
	// exponer nada del fallo en el cuerpo.
	RequestID string `json:"requestId,omitempty"`
}
