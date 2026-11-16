package postgres

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// El cursor viaja de ida y vuelta sin perder la clave de orden ni el id, con la
// precisión de timestamptz (microsegundos).
func TestReviewCursorEsReversible(t *testing.T) {
	key := time.Date(2026, 11, 15, 12, 30, 45, 123456000, time.UTC)
	id := uuid.New()

	gotKey, gotID, err := decodeReviewCursor(encodeReviewCursor(key, id))
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if !gotKey.Equal(key) || gotID != id {
		t.Errorf("cursor = (%v, %s), se esperaba (%v, %s)", gotKey, gotID, key, id)
	}
}

func TestReviewCursorEsOpacoYSeguroEnUnaURL(t *testing.T) {
	cursor := encodeReviewCursor(time.Now(), uuid.New())

	for _, c := range cursor {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
		if !ok {
			t.Fatalf("el cursor %q tiene un carácter que necesita escapado: %q", cursor, c)
		}
	}
}

func TestReviewCursorRechazaValoresQueNoSonDelServicio(t *testing.T) {
	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

	cases := map[string]string{
		"texto que no es base64":  "###",
		"vacío codificado":        b64(""),
		"sin separador":           b64("1700000000000000"),
		"fecha no numérica":       b64("ayer." + uuid.NewString()),
		"id que no es uuid":       b64("1700000000000000.no-es-uuid"),
		"id vacío":                b64("1700000000000000."),
		"base64 con relleno":      base64.StdEncoding.EncodeToString([]byte("1.x")) + "==",
		"fecha desbordada int64":  b64("99999999999999999999." + uuid.NewString()),
		"solo el separador":       b64("."),
		"uuid sin fecha":          b64("." + uuid.NewString()),
		"cursor con espacios":     " " + encodeReviewCursor(time.Now(), uuid.New()),
		"estándar con + y /":      "+/+/",
		"separador de más":        b64("1.2." + uuid.NewString()),
		"fecha con signo y letra": b64("+1x." + uuid.NewString()),
	}
	for nombre, cursor := range cases {
		t.Run(nombre, func(t *testing.T) {
			if _, _, err := decodeReviewCursor(cursor); !errors.Is(err, domain.ErrInvalidCursor) {
				t.Errorf("error = %v, se esperaba ErrInvalidCursor", err)
			}
		})
	}
}
