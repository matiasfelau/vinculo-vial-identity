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

// refreshRequest es el único dato que /refresh acepta: el Refresh Token
// opaco en JSON plano, sin el wrapper HPKE de dos piezas que sí usan
// /signup y /signin.
//
// Es una diferencia deliberada del contrato de US-03: el token es de un
// solo uso y la confidencialidad la aporta HTTPS, no un cifrado de
// aplicación adicional.
type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// refreshResponse acompaña al 200: el par de tokens rotado.
type refreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// logoutRequest es el único dato que /logout acepta: el mismo Refresh Token
// opaco en JSON plano que /refresh, sin el wrapper HPKE.
type logoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// verifyOwnershipRequest es el payload interno de US-04 que envía
// vinculo-vial-vehicle: el contrato compartido lo transporta tal cual, sin
// que Vehicle lo abra. DNIEnc es un único blob HPKE (enc || ciphertext), a
// diferencia de las dos piezas separadas de /signup y /signin.
type verifyOwnershipRequest struct {
	OwnerID string `json:"owner_id"`
	DNIEnc  string `json:"dni_enc"`
}

// verifyOwnershipResponse es la única forma de respuesta de
// /internal/verify-ownership: un booleano y nada más.
type verifyOwnershipResponse struct {
	Match bool `json:"match"`
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
	// codeInvalidSession es el código único del 401 de /refresh, tanto para un
	// Refresh Token inexistente como para uno expirado.
	codeInvalidSession = "sesion_invalida"
	// codeSessionCompromised es el código del 403 que produce la Defensa
	// Activa de /refresh ante el reúso de un Refresh Token ya rotado.
	codeSessionCompromised = "sesion_comprometida"
	// codeUnauthorizedService es el código del 401 que produce el router
	// interno de US-04 (/internal/*) cuando la petición no trae el secreto
	// de servicio a servicio configurado en INTERNAL_SERVICE_TOKEN.
	codeUnauthorizedService = "servicio_no_autorizado"
	codeInternal            = "error_interno"
	// codeUpstreamUnavailable es el código del 503 que produce el registro
	// cuando RENAPER no respondió: timeout, conexión rechazada o circuito
	// abierto. Contrato de resiliencia común a toda la plataforma.
	codeUpstreamUnavailable = "dependencia_no_disponible"
	// codeUpstreamError es el código del 502 que produce el registro cuando
	// RENAPER sí respondió, pero con un error de su lado o un cuerpo fuera de
	// contrato.
	codeUpstreamError = "upstream_invalido"
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
