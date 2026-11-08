package http_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/auditseal"
	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/hpke"
	delivery "github.com/matiasfelau/vinculo-vial-identity/internal/delivery/http"
	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/audit"
)

const pathAuditDNI = "/internal/audit/dni"

func auditDNIBody(userID, alertID string) string {
	payload, _ := json.Marshal(map[string]string{"user_id": userID, "alert_id": alertID})
	return string(payload)
}

func TestAuditDNIDevuelve200ConElContrato(t *testing.T) {
	ts := newInternalTestServer(t)
	userID, alertID := uuid.New(), uuid.New()

	rec := ts.post(t, pathAuditDNI, auditDNIBody(userID.String(), alertID.String()))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, se esperaba 200 (%s)", rec.Code, rec.Body.String())
	}
	body := decodeError(t, rec)
	if body["dni_enc_audit"] != "c2VsbGFkbw==" || body["audit_key_id"] != "2026-11" {
		t.Errorf("respuesta = %v", body)
	}
	// El contrato es estrictamente {dni_enc_audit, audit_key_id}: nada más.
	if len(body) != 2 {
		t.Errorf("la respuesta trae campos de más: %v", body)
	}
	if ts.auditDNI.userID != userID || ts.auditDNI.alertID != alertID {
		t.Errorf("el servicio recibió usuario=%v alerta=%v", ts.auditDNI.userID, ts.auditDNI.alertID)
	}
	if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Errorf("Cache-Control = %q, la respuesta lleva un criptograma y no se cachea", got)
	}
}

func TestAuditDNISinElSecretoDeServicioDevuelve401(t *testing.T) {
	ts := newInternalTestServer(t)

	req := httptest.NewRequest(http.MethodPost, pathAuditDNI,
		strings.NewReader(auditDNIBody(uuid.NewString(), uuid.NewString())))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, se esperaba 401 (%s)", rec.Code, rec.Body.String())
	}
	if ts.auditDNI.calls != 0 {
		t.Error("el servicio no debería invocarse sin el secreto de servicio")
	}
}

func TestAuditDNIConElSecretoIncorrectoDevuelve401(t *testing.T) {
	ts := newInternalTestServer(t)

	req := httptest.NewRequest(http.MethodPost, pathAuditDNI,
		strings.NewReader(auditDNIBody(uuid.NewString(), uuid.NewString())))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(delivery.HeaderInternalServiceToken, "otro-secreto")
	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, se esperaba 401 (%s)", rec.Code, rec.Body.String())
	}
	if ts.auditDNI.calls != 0 {
		t.Error("el servicio no debería invocarse con un secreto incorrecto")
	}
}

func TestAuditDNIRechazaUnCuerpoInvalido(t *testing.T) {
	casos := map[string]string{
		"no es JSON":          "esto no es json",
		"cuerpo vacío":        "",
		"sin campos":          "{}",
		"sin alert_id":        `{"user_id":"` + uuid.NewString() + `"}`,
		"sin user_id":         `{"alert_id":"` + uuid.NewString() + `"}`,
		"user_id no es UUID":  auditDNIBody("no-es-un-uuid", uuid.NewString()),
		"alert_id no es UUID": auditDNIBody(uuid.NewString(), "no-es-un-uuid"),
		"user_id nulo":        auditDNIBody(uuid.Nil.String(), uuid.NewString()),
		"alert_id nulo":       auditDNIBody(uuid.NewString(), uuid.Nil.String()),
		"tipos equivocados":   `{"user_id":1,"alert_id":2}`,
	}

	for nombre, cuerpo := range casos {
		t.Run(nombre, func(t *testing.T) {
			ts := newInternalTestServer(t)

			rec := ts.post(t, pathAuditDNI, cuerpo)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, se esperaba 400 (%s)", rec.Code, rec.Body.String())
			}
			if got := decodeError(t, rec)["code"]; got != "INVALID_BODY" {
				t.Errorf("code = %v, se esperaba INVALID_BODY", got)
			}
			if ts.auditDNI.calls != 0 {
				t.Error("con un cuerpo inválido no se debe sellar nada")
			}
		})
	}
}

func TestAuditDNITraduceLosErroresDeDominio(t *testing.T) {
	casos := map[string]struct {
		err        error
		status     int
		code       string
		retryAfter bool
	}{
		"usuario inexistente": {fmt.Errorf("audit: %w", domain.ErrUserNotFound), http.StatusNotFound, "USER_NOT_FOUND", false},
		"base no disponible":  {fmt.Errorf("audit: %w", domain.ErrDatabaseUnavailable), http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", true},
		"fallo interno":       {errors.New("hpke: algo inesperado"), http.StatusInternalServerError, "error_interno", false},
	}

	for nombre, caso := range casos {
		t.Run(nombre, func(t *testing.T) {
			ts := newInternalTestServer(t)
			ts.auditDNI.err = caso.err

			rec := ts.post(t, pathAuditDNI, auditDNIBody(uuid.NewString(), uuid.NewString()))

			if rec.Code != caso.status {
				t.Fatalf("status = %d, se esperaba %d (%s)", rec.Code, caso.status, rec.Body.String())
			}
			body := decodeError(t, rec)
			if body["code"] != caso.code {
				t.Errorf("code = %v, se esperaba %s", body["code"], caso.code)
			}
			if got := rec.Header().Get("Retry-After") != ""; got != caso.retryAfter {
				t.Errorf("Retry-After presente = %v, se esperaba %v", got, caso.retryAfter)
			}
			// Ninguna respuesta de error devuelve el detalle del fallo interno.
			if strings.Contains(rec.Body.String(), "hpke") || strings.Contains(rec.Body.String(), "audit:") {
				t.Errorf("la respuesta filtra el error subyacente: %s", rec.Body.String())
			}
		})
	}
}

// Ninguna rama del handler loguea el criptograma ni el par usuario-alerta: ese
// vínculo solo tiene que existir en el registro de Audit.
func TestAuditDNINoLogueaElCriptogramaNiElParUsuarioAlerta(t *testing.T) {
	var logs bytes.Buffer
	audit := &auditDNIServiceMock{result: domain.AuditDNI{Sealed: "criptograma-secreto-en-base64", KeyID: "2026-11"}}
	router, err := delivery.NewInternalRouter(delivery.InternalRouterConfig{
		VerifyOwnership: &verifyOwnershipServiceMock{},
		AuditDNI:        audit,
		ServiceToken:    secretoDePrueba,
		Logger:          slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatalf("no se pudo armar el router interno: %v", err)
	}
	ts := &internalTestServer{handler: router, verifyOwnership: &verifyOwnershipServiceMock{}, auditDNI: audit}
	userID, alertID := uuid.NewString(), uuid.NewString()

	ts.post(t, pathAuditDNI, auditDNIBody(userID, alertID))
	audit.err = fmt.Errorf("audit: %w", domain.ErrUserNotFound)
	ts.post(t, pathAuditDNI, auditDNIBody(userID, alertID))
	audit.err = fmt.Errorf("audit: %w", domain.ErrDatabaseUnavailable)
	ts.post(t, pathAuditDNI, auditDNIBody(userID, alertID))
	audit.err = errors.New("fallo interno")
	ts.post(t, pathAuditDNI, auditDNIBody(userID, alertID))
	ts.post(t, pathAuditDNI, "esto no es json")

	log := logs.String()
	for _, prohibido := range []string{userID, alertID, "criptograma-secreto-en-base64"} {
		if strings.Contains(log, prohibido) {
			t.Errorf("el log contiene %q: %s", prohibido, log)
		}
	}
	if !strings.Contains(log, "request_id=") {
		t.Errorf("los fallos deben poder correlacionarse por request id: %s", log)
	}
}

// usersFake y cipherFake arman el caso de uso real para probar el endpoint de
// punta a punta, con el sellador real: lo que sale por HTTP se abre con la
// clave privada y el `info` de la alerta.
type endToEndUsers struct{ user *domain.User }

func (f endToEndUsers) FindByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	if f.user == nil || f.user.ID != id {
		return nil, domain.ErrUserNotFound
	}
	return f.user, nil
}

type endToEndCipher struct{ dni string }

func (endToEndCipher) Encrypt([]byte) (string, error) { panic("no se usa") }
func (c endToEndCipher) Decrypt(string) ([]byte, error) {
	return []byte(c.dni), nil
}

func TestAuditDNIDeExtremoAExtremoSeAbreConLaClavePrivadaYElInfoDeLaAlerta(t *testing.T) {
	const dni = "30123456"
	privada, publica, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatalf("no se pudo generar el par de claves: %v", err)
	}
	sealer, err := auditseal.New(publica, "2026-11")
	if err != nil {
		t.Fatalf("no se pudo armar el sellador: %v", err)
	}
	user := &domain.User{ID: uuid.New(), DNIEncrypted: "dni-cifrado-at-rest"}
	service, err := audit.NewDNIService(audit.Deps{Users: endToEndUsers{user}, Cipher: endToEndCipher{dni}, Sealer: sealer})
	if err != nil {
		t.Fatalf("no se pudo armar el servicio: %v", err)
	}
	router, err := delivery.NewInternalRouter(delivery.InternalRouterConfig{
		VerifyOwnership: &verifyOwnershipServiceMock{},
		AuditDNI:        service,
		ServiceToken:    secretoDePrueba,
	})
	if err != nil {
		t.Fatalf("no se pudo armar el router interno: %v", err)
	}
	ts := &internalTestServer{handler: router}
	alerta := uuid.New()

	rec := ts.post(t, pathAuditDNI, auditDNIBody(user.ID.String(), alerta.String()))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, se esperaba 200 (%s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		DNIEncAudit string `json:"dni_enc_audit"`
		AuditKeyID  string `json:"audit_key_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("la respuesta no es JSON: %v", err)
	}
	if resp.AuditKeyID != "2026-11" {
		t.Errorf("audit_key_id = %q", resp.AuditKeyID)
	}
	if strings.Contains(rec.Body.String(), dni) {
		t.Error("la respuesta contiene el DNI en claro")
	}

	raw, err := base64.StdEncoding.DecodeString(resp.DNIEncAudit)
	if err != nil {
		t.Fatalf("dni_enc_audit no es base64 estándar: %v", err)
	}
	abrir := func(alert uuid.UUID) ([]byte, error) {
		dec, err := hpke.NewDecryptorFromBase64(privada, auditseal.Info(alert))
		if err != nil {
			t.Fatalf("clave privada inválida: %v", err)
		}
		return dec.DecryptCombined(raw)
	}

	got, err := abrir(alerta)
	if err != nil {
		t.Fatalf("no abrió con la clave privada y el alert_id correctos: %v", err)
	}
	if string(got) != dni {
		t.Errorf("DNI = %q, se esperaba %q", got, dni)
	}
	if opened, err := abrir(uuid.New()); err == nil {
		t.Fatalf("se abrió con el alert_id de otra alerta: %q", opened)
	}
}

func TestAuditDNIDeExtremoAExtremoConUsuarioInexistenteDevuelve404(t *testing.T) {
	_, publica, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatalf("no se pudo generar el par de claves: %v", err)
	}
	sealer, err := auditseal.New(publica, "2026-11")
	if err != nil {
		t.Fatalf("no se pudo armar el sellador: %v", err)
	}
	service, err := audit.NewDNIService(audit.Deps{Users: endToEndUsers{}, Cipher: endToEndCipher{"30123456"}, Sealer: sealer})
	if err != nil {
		t.Fatalf("no se pudo armar el servicio: %v", err)
	}
	router, err := delivery.NewInternalRouter(delivery.InternalRouterConfig{
		VerifyOwnership: &verifyOwnershipServiceMock{},
		AuditDNI:        service,
		ServiceToken:    secretoDePrueba,
	})
	if err != nil {
		t.Fatalf("no se pudo armar el router interno: %v", err)
	}
	ts := &internalTestServer{handler: router}

	rec := ts.post(t, pathAuditDNI, auditDNIBody(uuid.NewString(), uuid.NewString()))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, se esperaba 404 (%s)", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec)["code"]; got != "USER_NOT_FOUND" {
		t.Errorf("code = %v, se esperaba USER_NOT_FOUND", got)
	}
}
