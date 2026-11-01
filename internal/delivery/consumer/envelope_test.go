package consumer

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestParseEnvelopeValido(t *testing.T) {
	id := uuid.New()
	actor := uuid.NewString()
	body := []byte(`{"eventId":"` + id.String() + `","eventType":"alert.rejected","timestamp":"2026-10-09T10:00:00Z","producer":"vinculo-vial-alert","actor":"` + actor + `","payload":{"alert_id":"a"}}`)

	got, err := ParseEnvelope(body)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if got.EventID != id || got.EventType != "alert.rejected" {
		t.Errorf("sobre = %+v", got)
	}
	if got.Actor == nil || *got.Actor != actor {
		t.Errorf("actor = %v, se esperaba %q", got.Actor, actor)
	}
	if string(got.Payload) != `{"alert_id":"a"}` {
		t.Errorf("payload = %s", got.Payload)
	}
}

// El contrato distingue "sin actor" (null) de un actor informado: el sobre
// tiene que conservar esa diferencia para que el handler decida.
func TestParseEnvelopeConservaElActorNulo(t *testing.T) {
	cuerpos := map[string]string{
		"null explícito": `{"eventId":"` + uuid.NewString() + `","eventType":"user.status.changed","actor":null,"payload":{}}`,
		"ausente":        `{"eventId":"` + uuid.NewString() + `","eventType":"user.status.changed","payload":{}}`,
	}
	for nombre, body := range cuerpos {
		t.Run(nombre, func(t *testing.T) {
			got, err := ParseEnvelope([]byte(body))
			if err != nil {
				t.Fatalf("error inesperado: %v", err)
			}
			if got.Actor != nil {
				t.Errorf("actor = %q, se esperaba nil", *got.Actor)
			}
		})
	}
}

func TestParseEnvelopeInvalidoEsPermanente(t *testing.T) {
	casos := map[string]string{
		"json ilegible":   `{`,
		"vacío":           ``,
		"sin eventId":     `{"eventType":"x"}`,
		"eventId no uuid": `{"eventId":"abc","eventType":"x"}`,
		"eventId nulo":    `{"eventId":"00000000-0000-0000-0000-000000000000","eventType":"x"}`,
		"sin eventType":   `{"eventId":"` + uuid.NewString() + `"}`,
	}
	for nombre, body := range casos {
		t.Run(nombre, func(t *testing.T) {
			_, err := ParseEnvelope([]byte(body))
			if !errors.Is(err, ErrPermanent) {
				t.Errorf("err = %v, se esperaba un fallo permanente: reintentar no lo arregla", err)
			}
		})
	}
}

func TestPermanentConservaLaCausa(t *testing.T) {
	causa := errors.New("causa original")
	err := Permanent(causa)

	if !errors.Is(err, ErrPermanent) {
		t.Errorf("debería ser ErrPermanent")
	}
	if !errors.Is(err, causa) {
		t.Errorf("la causa debería seguir siendo alcanzable")
	}
}
