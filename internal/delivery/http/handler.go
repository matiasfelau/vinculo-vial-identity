// Package http expone los casos de uso de registro (US-01) e inicio de sesión
// (US-02) sobre HTTP/REST.
//
// El servicio vive detrás de vinculo-vial-gateway: Kong ya validó App
// Attestation antes de que la petición llegue acá, así que este handler no
// revalida atestación. Sí asume que todo lo demás puede ser hostil.
package http

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/validation"
)

// SignUpService es el puerto que necesita el handler, declarado del lado del
// consumidor para no arrastrar el paquete de servicio en los tests.
type SignUpService interface {
	SignUp(ctx context.Context, ephemeralPublicKey, ciphertext []byte) (uuid.UUID, error)
}

// SignInService es el puerto que necesita el handler para el login (US-02),
// declarado del lado del consumidor por el mismo motivo que SignUpService.
type SignInService interface {
	SignIn(ctx context.Context, ephemeralPublicKey, ciphertext []byte) (accessToken, refreshToken string, err error)
}

// RefreshService es el puerto que necesita el handler para la rotación de
// Refresh Token (US-03), declarado del lado del consumidor por el mismo
// motivo que SignUpService.
type RefreshService interface {
	Refresh(ctx context.Context, refreshToken string) (accessToken, newRefreshToken string, err error)
}

// LogoutService es el puerto que necesita el handler para el cierre de
// sesión (US-03), declarado del lado del consumidor por el mismo motivo que
// SignUpService.
type LogoutService interface {
	Logout(ctx context.Context, refreshToken string) error
}

// Handler atiende el alta, el inicio de sesión y la gestión de sesión de
// vecinos.
type Handler struct {
	signUp  SignUpService
	signIn  SignInService
	refresh RefreshService
	logout  LogoutService
	logger  *slog.Logger
}

// NewHandler construye el handler.
func NewHandler(signUp SignUpService, signIn SignInService, refresh RefreshService, logout LogoutService, logger *slog.Logger) (*Handler, error) {
	if signUp == nil {
		return nil, errors.New("http: falta el servicio de registro")
	}
	if signIn == nil {
		return nil, errors.New("http: falta el servicio de inicio de sesión")
	}
	if refresh == nil {
		return nil, errors.New("http: falta el servicio de refresh")
	}
	if logout == nil {
		return nil, errors.New("http: falta el servicio de logout")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{signUp: signUp, signIn: signIn, refresh: refresh, logout: logout, logger: logger}, nil
}

// SignUp atiende POST /api/v1/auth/signup.
//
//	201 — alta exitosa, sin tokens (la sesión es US-02).
//	400 — el cuerpo no es interpretable, los datos descifrados no validan, o
//	      RENAPER no pudo confirmar la identidad (dni+tramite+sexo+selfie).
//	409 — el email o el DNI ya existen, con mensaje genérico.
//	500 — el mensaje HPKE no descifra, RENAPER no pudo consultarse, o falla algo
//	      interno.
//
// El 403 que enumera el contrato lo produce el gateway cuando la atestación de
// la app no convence; nunca llega a este handler.
func (h *Handler) SignUp(c *gin.Context) {
	var req signUpRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Acá todavía no hay nada descifrado: dni/tramite/sexo/selfie viven
		// dentro del ciphertext y ni siquiera se intentó abrirlos. err.Error()
		// de un bind fallido describe sintaxis JSON o un tipo que no matchea
		// (p. ej. "cannot unmarshal number into ... of type string"), nunca el
		// contenido de un campo — es seguro loguearlo tal cual.
		h.logger.WarnContext(c.Request.Context(), "cuerpo del signup no es JSON interpretable",
			slog.String("request_id", requestIDOf(c)),
			slog.String("error", err.Error()),
		)
		h.abort(c, http.StatusBadRequest, codeInvalidRequest,
			"el cuerpo debe ser un JSON con los campos ephemeral_public_key y ciphertext", nil)
		return
	}

	ephemeralPublicKey, ok := h.decodeField(c, "ephemeral_public_key", req.EphemeralPublicKey)
	if !ok {
		return
	}

	ciphertext, ok := h.decodeField(c, "ciphertext", req.Ciphertext)
	if !ok {
		return
	}

	userID, err := h.signUp.SignUp(c.Request.Context(), ephemeralPublicKey, ciphertext)
	if err != nil {
		h.abortWithDomainError(c, err)
		return
	}

	c.JSON(http.StatusCreated, signUpResponse{UserID: userID.String()})
}

// SignIn atiende POST /api/v1/auth/signin.
//
//	200 — login exitoso, con el par de tokens de la sesión nueva.
//	400 — el cuerpo no es interpretable, o los datos descifrados no validan
//	      (DNI mal formado, contraseña vacía).
//	401 — el DNI no corresponde a ningún usuario o la contraseña no verifica,
//	      con la misma respuesta en los dos casos (anti-enumeración).
//	500 — el mensaje HPKE no descifra, o falla algo interno.
//
// El 403 que enumera el contrato lo produce el gateway cuando la atestación de
// la app no convence; nunca llega a este handler.
func (h *Handler) SignIn(c *gin.Context) {
	var req signInRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Igual que en SignUp: acá todavía no hay nada descifrado, así que
		// err.Error() de un bind fallido describe sintaxis JSON o un tipo que no
		// matchea, nunca el contenido de un campo — es seguro loguearlo tal cual.
		h.logger.WarnContext(c.Request.Context(), "cuerpo del signin no es JSON interpretable",
			slog.String("request_id", requestIDOf(c)),
			slog.String("error", err.Error()),
		)
		h.abort(c, http.StatusBadRequest, codeInvalidRequest,
			"el cuerpo debe ser un JSON con los campos ephemeral_public_key y ciphertext", nil)
		return
	}

	ephemeralPublicKey, ok := h.decodeField(c, "ephemeral_public_key", req.EphemeralPublicKey)
	if !ok {
		return
	}

	ciphertext, ok := h.decodeField(c, "ciphertext", req.Ciphertext)
	if !ok {
		return
	}

	accessToken, refreshToken, err := h.signIn.SignIn(c.Request.Context(), ephemeralPublicKey, ciphertext)
	if err != nil {
		h.abortWithDomainError(c, err)
		return
	}

	c.JSON(http.StatusOK, signInResponse{AccessToken: accessToken, RefreshToken: refreshToken})
}

// Refresh atiende POST /api/v1/auth/refresh.
//
//	200 — rotación exitosa: par de tokens nuevo.
//	401 — el refresh token no existe, expiró, o ambos casos combinados: la
//	      misma respuesta para los dos, igual que el 401 de SignIn.
//	403 — Defensa Activa: el refresh token ya había sido rotado (reúso
//	      detectado), y la sesión completa del usuario quedó revocada.
//	500 — falla algo interno, incluida la propia Defensa Activa si no se pudo
//	      persistir la revocación masiva.
//
// A diferencia de SignUp y SignIn, el cuerpo es JSON plano, sin el wrapper
// HPKE: el Refresh Token es de un solo uso y la confidencialidad la aporta
// HTTPS, no un cifrado de aplicación adicional (ver el contrato de US-03).
//
// El 403 que produce una atestación de app rechazada lo genera el gateway;
// nunca llega a este handler.
func (h *Handler) Refresh(c *gin.Context) {
	var req refreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WarnContext(c.Request.Context(), "cuerpo del refresh no es JSON interpretable",
			slog.String("request_id", requestIDOf(c)),
			slog.String("error", err.Error()),
		)
		h.abort(c, http.StatusBadRequest, codeInvalidRequest,
			"el cuerpo debe ser un JSON con el campo refresh_token", nil)
		return
	}

	accessToken, refreshToken, err := h.refresh.Refresh(c.Request.Context(), req.RefreshToken)
	if err != nil {
		h.abortRefreshError(c, err)
		return
	}

	c.JSON(http.StatusOK, refreshResponse{AccessToken: accessToken, RefreshToken: refreshToken})
}

// abortRefreshError traduce los centinelas de domain que puede devolver
// RefreshService a códigos HTTP.
//
// ErrSessionNotFound y ErrSessionExpired producen la misma respuesta: el
// cliente no tiene por qué distinguir "el token no existe" de "el token
// venció". ErrSessionReused sí se distingue con un status propio: a
// diferencia de los otros dos, es la señal de una brecha de seguridad
// contenida (Defensa Activa), no la de un token simplemente inválido.
func (h *Handler) abortRefreshError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, domain.ErrSessionNotFound), errors.Is(err, domain.ErrSessionExpired):
		h.abort(c, http.StatusUnauthorized, codeInvalidSession, "sesión inválida", nil)

	case errors.Is(err, domain.ErrSessionReused):
		h.abort(c, http.StatusForbidden, codeSessionCompromised, "sesión comprometida", nil)

	case errors.Is(err, domain.ErrDatabaseUnavailable):
		// 503: la base propia no respondió, no es un defecto de este servicio.
		h.logger.WarnContext(c.Request.Context(), "base de datos no disponible",
			slog.String("request_id", requestIDOf(c)),
			slog.String("error", err.Error()),
		)
		h.abort(c, http.StatusServiceUnavailable, codeUpstreamUnavailable, "el servicio no está disponible, reintentar en unos segundos", nil)

	default:
		h.logger.ErrorContext(c.Request.Context(), "fallo no esperado en el refresh",
			slog.String("request_id", requestIDOf(c)),
			slog.String("error", err.Error()),
		)
		h.abort(c, http.StatusInternalServerError, codeInternal, "error interno", nil)
	}
}

// Logout atiende POST /api/v1/auth/logout.
//
//	200 — siempre, exista o no una sesión con ese Refresh Token, esté o no ya
//	      revocada (anti-enumeración): nunca 401, nunca 404.
//	400 — el cuerpo no es JSON interpretable.
//	503 — la base de datos propia no está disponible.
//	500 — falla algo interno distinto (la revocación no se pudo persistir).
//
// A diferencia de /refresh, este endpoint no exige X-App-Attestation: si la
// atestación de la app falla, el usuario tiene que poder cerrar sesión igual
// y no quedar atrapado sin forma de terminarla (decisión del gateway).
func (h *Handler) Logout(c *gin.Context) {
	var req logoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WarnContext(c.Request.Context(), "cuerpo del logout no es JSON interpretable",
			slog.String("request_id", requestIDOf(c)),
			slog.String("error", err.Error()),
		)
		h.abort(c, http.StatusBadRequest, codeInvalidRequest,
			"el cuerpo debe ser un JSON con el campo refresh_token", nil)
		return
	}

	if err := h.logout.Logout(c.Request.Context(), req.RefreshToken); err != nil {
		if errors.Is(err, domain.ErrDatabaseUnavailable) {
			h.logger.WarnContext(c.Request.Context(), "base de datos no disponible",
				slog.String("request_id", requestIDOf(c)),
				slog.String("error", err.Error()),
			)
			h.abort(c, http.StatusServiceUnavailable, codeUpstreamUnavailable, "el servicio no está disponible, reintentar en unos segundos", nil)
			return
		}
		h.logger.ErrorContext(c.Request.Context(), "fallo no esperado en el logout",
			slog.String("request_id", requestIDOf(c)),
			slog.String("error", err.Error()),
		)
		h.abort(c, http.StatusInternalServerError, codeInternal, "error interno", nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

// decodeField exige que el campo esté presente y sea base64, y aborta la
// petición con un 400 si no lo es. La usan tanto SignUp como SignIn: los dos
// reciben el mismo sobre HPKE de dos piezas.
//
// El nombre del campo se nombra en el mensaje pero nunca su valor: es material
// criptográfico y no tiene por qué aparecer en una respuesta ni en un log.
func (h *Handler) decodeField(c *gin.Context, name, value string) ([]byte, bool) {
	return decodeField(c, h.logger, name, value)
}

// decodeField es el cuerpo de Handler.decodeField, para los handlers que
// reciben el mismo sobre HPKE sin ser el Handler de /auth.
func decodeField(c *gin.Context, logger *slog.Logger, name, value string) ([]byte, bool) {
	if value == "" {
		logger.WarnContext(c.Request.Context(), "campo del sobre HPKE vacío",
			slog.String("request_id", requestIDOf(c)),
			slog.String("field", name),
		)
		abortRequest(c, http.StatusBadRequest, codeInvalidRequest, "el campo "+name+" es obligatorio", nil)
		return nil, false
	}

	raw, err := decodeBase64(value)
	if err != nil {
		// La longitud del string recibido, no su contenido: sigue siendo
		// material criptográfico (la clave efímera o el ciphertext), y ni
		// siquiera decodificó, así que tampoco hay un payload interno que
		// proteger acá — solo no hay motivo para loguear un blob opaco entero.
		logger.WarnContext(c.Request.Context(), "campo del sobre HPKE no es base64 válido",
			slog.String("request_id", requestIDOf(c)),
			slog.String("field", name),
			slog.Int("longitud_recibida", len(value)),
		)
		abortRequest(c, http.StatusBadRequest, codeInvalidRequest, "el campo "+name+" debe ser base64", nil)
		return nil, false
	}

	return raw, true
}

// decodeBase64 acepta las cuatro variantes de base64 que produce el ecosistema:
// alfabeto estándar o URL-safe, con o sin relleno.
//
// El contrato compartido dice "base64" sin más, y cada plataforma elige por su
// cuenta: la familia Base64.URL_SAFE de Android y buena parte del tooling web
// emiten el alfabeto URL-safe, a menudo sin `=`. Ser estricto acá convertiría esa
// diferencia en un 400 que el equipo del frontend tendría que diagnosticar
// cruzando repositorios.
//
// Aceptar de más no debilita nada: los cuatro alfabetos decodifican a los mismos
// bytes y lo que se valida después es el mensaje HPKE, no su transporte.
func decodeBase64(value string) ([]byte, error) {
	// Se prueban en orden en lugar de deducir la variante por inspección: son
	// operaciones baratas y así no hay que razonar sobre casos borde de relleno
	// para convencerse de que la selección es correcta.
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}

	var err error
	for _, enc := range encodings {
		var raw []byte
		if raw, err = enc.DecodeString(value); err == nil {
			return raw, nil
		}
	}
	return nil, err
}

// abortWithDomainError traduce los centinelas de domain a códigos HTTP.
//
// Ninguna rama devuelve el error subyacente: el detalle queda en el log del
// servidor, correlacionable por request id, y el cliente solo recibe la
// categoría del fallo.
func (h *Handler) abortWithDomainError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalidInput):
		// Es el único caso en que se detalla algo: los campos rechazados, con
		// su código, para que la app corrija el formulario en un solo intento.
		// Los valores rechazados nunca se incluyen.
		var verrs validation.Errors
		_ = errors.As(err, &verrs)
		h.logInvalidInput(c, verrs)
		h.abort(c, http.StatusBadRequest, codeInvalidInput, "los datos de registro no son válidos", verrs)

	case errors.Is(err, domain.ErrDuplicateUser):
		// Mensaje deliberadamente ambiguo: decir si colisionó el email o el DNI
		// permitiría averiguar si una persona concreta está registrada.
		h.abort(c, http.StatusConflict, codeConflict, "no es posible completar el registro con los datos provistos", nil)

	case errors.Is(err, domain.ErrInvalidCredentials):
		// 401 unificado: mismo status, mismo código, mismo mensaje tanto si el
		// DNI no corresponde a ningún usuario como si la contraseña no
		// verifica. Distinguirlos en la respuesta habilitaría enumerar qué
		// DNIs están registrados; el motivo real ya quedó en el log del
		// servicio, identificado por dni_hashed.
		h.abort(c, http.StatusUnauthorized, codeInvalidCredentials, "credenciales inválidas", nil)

	case errors.Is(err, domain.ErrTermsNotAccepted):
		// US-19: el alta sin la versión vigente de los términos. La app lo trata
		// como "pedile que los acepte de nuevo", así que alcanza con el código.
		h.abort(c, http.StatusBadRequest, codeTermsNotAccepted, "no se aceptó la versión vigente de los términos y condiciones", nil)

	case errors.Is(err, domain.ErrEmailNotVerified):
		// US-13: el alta sin un token de verificación de email utilizable. Un solo
		// código para ausente, vencido, usado o de otro email: decir cuál de los
		// cuatro permitiría tantear tokens ajenos.
		h.abort(c, http.StatusBadRequest, codeEmailNotVerified, "el email no está verificado", nil)

	case errors.Is(err, domain.ErrIdentityNotVerified):
		// 400 y no 409: no hay ningún otro registro con el que haya colisionado,
		// es este intento el que no se pudo confirmar contra RENAPER. Mensaje
		// genérico por la misma razón que el de arriba: precisar si falló el
		// trámite, el sexo o la selfie facilitaría tantear los datos de otra
		// persona hasta acertar.
		h.abort(c, http.StatusBadRequest, codeIdentityNotVerified, "no fue posible verificar la identidad", nil)

	case errors.Is(err, domain.ErrUpstreamUnavailable):
		// 503, no 500: RENAPER es quien no responde, no este servicio. El
		// cliente puede reintentar razonablemente ante este código, que es
		// justamente la distinción que un 500 genérico no comunica.
		h.logger.WarnContext(c.Request.Context(), "dependencia no disponible",
			slog.String("request_id", requestIDOf(c)),
			slog.String("error", err.Error()),
		)
		h.abort(c, http.StatusServiceUnavailable, codeUpstreamUnavailable, "el servicio no está disponible, reintentar en unos segundos", nil)

	case errors.Is(err, domain.ErrUpstreamInvalidResponse):
		// 502: RENAPER respondió, pero con un error de su lado o un cuerpo
		// fuera de contrato. Se distingue de ErrUpstreamUnavailable porque acá
		// sí hubo respuesta; el detalle queda en el log, nunca en el cuerpo.
		h.logger.ErrorContext(c.Request.Context(), "respuesta inválida del upstream",
			slog.String("request_id", requestIDOf(c)),
			slog.String("error", err.Error()),
		)
		h.abort(c, http.StatusBadGateway, codeUpstreamError, "el servicio no está disponible, reintentar en unos segundos", nil)

	case errors.Is(err, domain.ErrDatabaseUnavailable):
		// 503: la base propia no está disponible, no RENAPER, pero el mismo
		// motivo aplica para no mapearlo a 500 — sección Postgres del
		// contrato de resiliencia.
		h.logger.WarnContext(c.Request.Context(), "base de datos no disponible",
			slog.String("request_id", requestIDOf(c)),
			slog.String("error", err.Error()),
		)
		h.abort(c, http.StatusServiceUnavailable, codeUpstreamUnavailable, "el servicio no está disponible, reintentar en unos segundos", nil)

	case errors.Is(err, domain.ErrMalformedCryptogram):
		// El mensaje no tiene la forma de un mensaje HPKE. Es un cliente mal
		// implementado, no un fallo del servicio: un 500 lo mandaría a buscar el
		// problema del lado equivocado. El motivo concreto queda en el log.
		h.logger.WarnContext(c.Request.Context(), "mensaje HPKE mal formado",
			slog.String("request_id", requestIDOf(c)),
			slog.String("error", err.Error()),
		)
		h.abort(c, http.StatusBadRequest, codeInvalidRequest, "el mensaje cifrado no tiene el formato esperado", nil)

	case errors.Is(err, domain.ErrInvalidCryptogram):
		// 500 por decisión de US-01: un cliente legítimo siempre cifra con la
		// clave pública vigente, así que un fallo acá es desincronización de
		// claves o manipulación. El cuerpo no revela nada criptográfico.
		h.logger.ErrorContext(c.Request.Context(), "no se pudo descifrar el mensaje HPKE",
			slog.String("request_id", requestIDOf(c)),
		)
		h.abort(c, http.StatusInternalServerError, codeInternal, "error interno", nil)

	default:
		h.logger.ErrorContext(c.Request.Context(), "fallo no esperado en el registro",
			slog.String("request_id", requestIDOf(c)),
			slog.String("error", err.Error()),
		)
		h.abort(c, http.StatusInternalServerError, codeInternal, "error interno", nil)
	}
}

// logInvalidInput deja constancia en el log de qué campo se rechazó y por qué,
// con el mismo detalle que ya viaja en la respuesta al cliente: código y
// mensaje por campo, agrupados bajo el nombre del campo para que el agregador
// de logs los pueda filtrar.
//
// Nunca incluye el valor rechazado, y no es una omisión a mantener a mano:
// validation.FieldError no tiene ningún campo donde guardar un valor aunque
// quisiera (ver el comentario en su definición), así que este log es
// estructuralmente tan seguro como la respuesta HTTP que ya se probaba.
func (h *Handler) logInvalidInput(c *gin.Context, verrs validation.Errors) {
	attrs := make([]slog.Attr, 0, len(verrs)+1)
	attrs = append(attrs, slog.String("request_id", requestIDOf(c)))
	for _, fe := range verrs {
		attrs = append(attrs, slog.Group(fe.Field,
			slog.String("code", fe.Code),
			slog.String("message", fe.Message),
		))
	}

	h.logger.LogAttrs(c.Request.Context(), slog.LevelWarn, "registro rechazado por validación", attrs...)
}

func (h *Handler) abort(c *gin.Context, status int, code, message string, details validation.Errors) {
	abortRequest(c, status, code, message, details)
}

// abortRequest responde con el formato de error uniforme de la API. Lo
// comparten todos los handlers de este paquete.
func abortRequest(c *gin.Context, status int, code, message string, details validation.Errors) {
	c.AbortWithStatusJSON(status, errorResponse{
		Code: code,
		// Error y Message llevan el mismo texto a propósito: ver el comentario
		// en errorResponse.
		Error:     message,
		Message:   message,
		Details:   details,
		RequestID: requestIDOf(c),
	})
}
