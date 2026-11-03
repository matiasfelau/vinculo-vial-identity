package signup_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// Un alta sin hold previo nace limpia, y el servicio igual entrega al
// repositorio el user.status.changed por si hubiera herencia: solo se persiste
// si el repositorio la encuentra.
func TestSignUpSinHoldNaceLimpia(t *testing.T) {
	h := newHarness(t)

	if _, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext)); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	u := h.repo.last()
	if u.AccountStatus != domain.AccountStatusActive || u.ReputationScore != 0 || u.ReportCount != 0 {
		t.Errorf("la cuenta nació con estado=%q reputación=%d reportes=%d, se esperaba limpia", u.AccountStatus, u.ReputationScore, u.ReportCount)
	}
}

// El user.status.changed que el servicio arma para la herencia es el del
// contrato: el usuario recién creado, UNDER_REVIEW, INHERITED_ON_SIGNUP, listo
// para el outbox y con la hora del reloj del servicio.
func TestSignUpEntregaAlRepositorioElEventoDeLaSancionHeredada(t *testing.T) {
	h := newHarness(t)

	id, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext))
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if len(h.repo.inheritedStatus) != 1 {
		t.Fatalf("eventos entregados = %d, se esperaba 1", len(h.repo.inheritedStatus))
	}
	evt := h.repo.inheritedStatus[0]

	if evt.Type != domain.EventTypeUserStatusChanged {
		t.Errorf("tipo = %q, se esperaba %q", evt.Type, domain.EventTypeUserStatusChanged)
	}
	if evt.ID == uuid.Nil {
		t.Errorf("el evento no tiene ID propio")
	}
	if !evt.CreatedAt.Equal(fijo) {
		t.Errorf("CreatedAt = %v, se esperaba el reloj inyectado %v", evt.CreatedAt, fijo)
	}

	var payload map[string]string
	if err := json.Unmarshal(evt.Payload, &payload); err != nil {
		t.Fatalf("payload ilegible: %v", err)
	}
	if payload["user_id"] != id.String() {
		t.Errorf("user_id = %q, se esperaba el del usuario creado %q", payload["user_id"], id)
	}
	if payload["account_status"] != "UNDER_REVIEW" || payload["reason"] != "INHERITED_ON_SIGNUP" {
		t.Errorf("payload = %v, se esperaba UNDER_REVIEW e INHERITED_ON_SIGNUP", payload)
	}
}

// Con un hold vigente que dejó la cuenta en revisión, el alta nace en revisión
// con la reputación y los reportes heredados.
func TestSignUpHeredaLaSancionDelHold(t *testing.T) {
	h := newHarness(t)
	h.repo.inherit = &domain.HoldSanction{
		AccountStatus:   domain.AccountStatusUnderReview,
		ReputationScore: -30,
		ReportCount:     2,
	}

	id, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext))
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	u := h.repo.last()
	if u.ID != id {
		t.Fatalf("id devuelto = %v, el persistido es %v", id, u.ID)
	}
	if u.AccountStatus != domain.AccountStatusUnderReview || u.ReputationScore != -30 || u.ReportCount != 2 {
		t.Errorf("la cuenta nació con estado=%q reputación=%d reportes=%d", u.AccountStatus, u.ReputationScore, u.ReportCount)
	}
}

// La herencia deja constancia en el log con el estado resultante, sin el
// Blind Index del DNI ni nada que identifique la sanción previa.
func TestSignUpLogueaElEstadoSinDatosDelHold(t *testing.T) {
	h := newHarness(t)
	h.repo.inherit = &domain.HoldSanction{
		DNIHMAC:         "hmac-del-dni-que-no-debe-loguearse",
		AccountStatus:   domain.AccountStatusUnderReview,
		ReputationScore: -30,
		ReportCount:     2,
	}

	if _, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext)); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	log := h.logs.String()
	if !strings.Contains(log, "account_status=UNDER_REVIEW") {
		t.Errorf("el log debería informar el estado de la cuenta nueva: %s", log)
	}
	for _, prohibido := range []string{"hmac-del-dni", "blind-index-de:", "30123456", "Rosario-2026"} {
		if strings.Contains(log, prohibido) {
			t.Errorf("el log contiene %q: %s", prohibido, log)
		}
	}
}

// Un alta que falla no devuelve usuario ni deja el evento colgado: el error del
// repositorio sale tal cual.
func TestSignUpConErrorDelRepositorioNoHeredaNada(t *testing.T) {
	h := newHarness(t)
	h.repo.err = domain.ErrDuplicateUser
	h.repo.inherit = &domain.HoldSanction{AccountStatus: domain.AccountStatusUnderReview}

	if _, err := h.svc.SignUp(t.Context(), []byte(ephemeralPublicKey), []byte(ciphertext)); err == nil {
		t.Fatal("se esperaba un error")
	}
	if len(h.repo.created) != 0 {
		t.Errorf("no debería haberse creado ningún usuario")
	}
}
