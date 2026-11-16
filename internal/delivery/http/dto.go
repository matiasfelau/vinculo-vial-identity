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

// deleteAccountRequest es el único dato que la baja de cuenta (US-11) acepta:
// la contraseña actual, en JSON plano, sin el wrapper HPKE. La baja es una
// reautenticación sobre una sesión ya validada por Kong, y la confidencialidad
// la aporta HTTPS, igual que con el Refresh Token de /refresh.
type deleteAccountRequest struct {
	Password string `json:"password"`
}

// auditDNIRequest es el payload interno de POST /internal/audit/dni que envía
// vinculo-vial-alert antes de crear una alerta: el usuario cuyo DNI se sella y la
// alerta a la que queda atado el criptograma.
type auditDNIRequest struct {
	UserID  string `json:"user_id"`
	AlertID string `json:"alert_id"`
}

// auditDNIResponse es la única forma de respuesta de /internal/audit/dni: el DNI
// sellado hacia Audit (base64 de enc‖ct) y el id de la clave con que se selló.
type auditDNIResponse struct {
	DNIEncAudit string `json:"dni_enc_audit"`
	AuditKeyID  string `json:"audit_key_id"`
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
	// interno (/internal/*) cuando la petición no trae el secreto
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

// Códigos de error de la baja de cuenta (US-11). A diferencia de los de arriba,
// los fija el contrato compartido de esa US, en mayúsculas, y no son
// intercambiables con los de las rutas de autenticación.
const (
	// codeInvalidBody es el 400 de la baja: body ausente, ilegible, sin password
	// o con una contraseña que ninguna cuenta puede tener.
	codeInvalidBody = "INVALID_BODY"
	// codeInvalidPassword es el 401 de la baja cuando la contraseña no coincide.
	codeInvalidPassword = "INVALID_PASSWORD"
	// codeUnauthorized es el 401 de la baja cuando la petición no trae un
	// X-User-Id válido: no pasó por Kong. Kong ya rechaza antes un JWT ausente o
	// inválido, así que acá solo llega una petición que se saltó el gateway.
	codeUnauthorized = "UNAUTHORIZED"
	// codeDependencyUnavailable es el 503 de la baja cuando la base no responde.
	codeDependencyUnavailable = "DEPENDENCY_UNAVAILABLE"
)

// Códigos de error de POST /internal/audit/dni (US-11, Audit). Los fija el
// contrato compartido, en mayúsculas. INVALID_BODY y DEPENDENCY_UNAVAILABLE son
// los mismos de la baja.
const (
	// codeUserNotFound es el 404 cuando el usuario del sellado no existe: Alert lo
	// traduce en 403 ACCOUNT_DELETED.
	codeUserNotFound = "USER_NOT_FOUND"
)

// Códigos de error de la verificación de email y la recuperación de contraseña
// (US-13). Los fija el contrato compartido, en mayúsculas, como los de US-11.
const (
	// codeInvalidCode es el 400 de las confirmaciones: el código es incorrecto,
	// venció, ya se usó, nunca se emitió o agotó sus intentos. Los cinco casos
	// son indistinguibles a propósito.
	codeInvalidCode = "INVALID_CODE"
	// codeEmailNotVerified es el 400 del alta sin un token de verificación de
	// email utilizable.
	codeEmailNotVerified = "EMAIL_NOT_VERIFIED"
	// codeInvalidResetToken es el 400 de la revalidación con un reset_token
	// ausente, vencido, usado o sin intentos.
	codeInvalidResetToken = "INVALID_RESET_TOKEN"
)

// hpkeRequest es el único dato que aceptan los endpoints de US-13: el mismo
// sobre HPKE del alta y el login, en las dos piezas que fija el contrato
// compartido. Nada personal viaja en el cuerpo: ni el email, ni el DNI, ni el
// código, ni la contraseña.
type hpkeRequest struct {
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	Ciphertext         string `json:"ciphertext"`
}

// emailVerificationConfirmResponse acompaña al 200 de la confirmación del email.
type emailVerificationConfirmResponse struct {
	VerificationToken string `json:"verification_token"`
	// ExpiresIn son los segundos de vida del token.
	ExpiresIn int64 `json:"expires_in"`
}

// passwordResetConfirmResponse acompaña al 200 de la confirmación de la
// recuperación.
type passwordResetConfirmResponse struct {
	ResetToken string `json:"reset_token"`
	// ExpiresIn son los segundos de vida del token.
	ExpiresIn int64 `json:"expires_in"`
}

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
