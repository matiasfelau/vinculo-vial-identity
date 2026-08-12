package events

import (
	"log/slog"
	"strings"
	"testing"
)

func TestNoopPublisherNoFallaYDejaConstancia(t *testing.T) {
	logs := &strings.Builder{}
	p := NewNoopPublisher(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))

	evt := eventoDeAlta()
	if err := p.PublishUserRegistered(t.Context(), evt); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	// El alta no puede fallar por no tener broker, pero cada evento descartado
	// tiene que ser visible: es un modo de desarrollo, no de producción.
	registro := logs.String()
	if !strings.Contains(registro, EventTypeUserRegistered) {
		t.Errorf("el log debería nombrar el evento descartado: %s", registro)
	}
	if !strings.Contains(registro, evt.UserID.String()) {
		t.Errorf("el log debería identificar el alta afectada: %s", registro)
	}
	if !strings.Contains(registro, "WARN") {
		t.Errorf("descartar un evento merece al menos nivel WARN: %s", registro)
	}
}

func TestNoopPublisherToleraLoggerNulo(t *testing.T) {
	p := NewNoopPublisher(nil)

	if err := p.PublishUserRegistered(t.Context(), eventoDeAlta()); err != nil {
		t.Errorf("error inesperado: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("error inesperado al cerrar: %v", err)
	}
}
