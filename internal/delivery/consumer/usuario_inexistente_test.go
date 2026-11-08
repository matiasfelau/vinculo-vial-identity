package consumer

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/reputation"
)

// repositorioSinUsuario implementa domain.ReputationRepository para un usuario
// que ya no existe (dado de baja): registra el evento como procesado pero no
// encuentra a quién aplicarlo.
type repositorioSinUsuario struct {
	mu       sync.Mutex
	rechazos []domain.ProcessedEvent
	reportes []domain.ProcessedEvent
}

var _ domain.ReputationRepository = (*repositorioSinUsuario)(nil)

func (r *repositorioSinUsuario) ApplyRejection(_ context.Context, event domain.ProcessedEvent, _ uuid.UUID, _ int) (domain.RejectionResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rechazos = append(r.rechazos, event)
	return domain.RejectionUserNotFound, nil
}

func (r *repositorioSinUsuario) ApplyReport(_ context.Context, event domain.ProcessedEvent, _ uuid.UUID, _ int, _ domain.OutboxEvent) (domain.ReportOutcome, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reportes = append(r.reportes, event)
	return domain.ReportUserNotFound, nil
}

// Un alert.rejected cuyo actor ya no existe (la baja llegó antes que el evento)
// se confirma sin efecto: ni nack, ni reintento, ni DLQ. Se ejercita el handler
// y el caso de uso reales; solo la base está doblada.
func TestAlertRejectedDeUsuarioInexistenteSeConfirmaSinEfecto(t *testing.T) {
	repo := &repositorioSinUsuario{}
	servicio, err := reputation.NewRejectionService(reputation.RejectionDeps{
		Repo: repo, Consumer: colaDePrueba, FraudPenalty: 10, Logger: loggerMudo(),
	})
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	handler, err := NewAlertRejectedHandler(servicio, loggerMudo())
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	dlq := &dlqFalsa{}
	c, err := NewConsumer(nuevoCanalFalso(), dlq, Spec{
		Queue: colaDePrueba, EventType: tipoDePrueba, MaxRetries: maxReintentosDePrueba, Handler: handler,
	}, loggerMudo())
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	d, a := entrega(cuerpoRechazo(t, uuid.New(), uuid.NewString(), payloadDeRechazo("NO_VEHICLE")), 0)
	c.process(t.Context(), d)

	if acks, nacks, _ := a.contadores(); acks != 1 || nacks != 0 {
		t.Errorf("acks=%d nacks=%d, se esperaba un único ack", acks, nacks)
	}
	if dlq.llamadas != 0 {
		t.Errorf("un usuario inexistente no manda el mensaje a la dlq")
	}
	if len(repo.rechazos) != 1 {
		t.Errorf("el evento debía registrarse una vez como procesado, se registró %d", len(repo.rechazos))
	}
}

// Un alert.reported cuyo actor ya no existe se confirma sin efecto: nadie queda
// en revisión y no se encola ningún user.status.changed.
func TestAlertReportedDeUsuarioInexistenteSeConfirmaSinEfecto(t *testing.T) {
	repo := &repositorioSinUsuario{}
	servicio, err := reputation.NewReportService(reputation.ReportDeps{
		Repo: repo, Consumer: colaDeReportes, ReviewThreshold: 1, Logger: loggerMudo(),
	})
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	handler, err := NewAlertReportedHandler(servicio, loggerMudo())
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	dlq := &dlqFalsa{}
	c, err := NewConsumer(nuevoCanalFalso(), dlq, Spec{
		Queue: colaDeReportes, EventType: "alert.reported", MaxRetries: maxReintentosDePrueba, Handler: handler,
	}, loggerMudo())
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	d, a := entrega(cuerpoReporte(t, uuid.New(), uuid.NewString(), payloadDeReporte("SPAM")), 0)
	c.process(t.Context(), d)

	if acks, nacks, _ := a.contadores(); acks != 1 || nacks != 0 {
		t.Errorf("acks=%d nacks=%d, se esperaba un único ack", acks, nacks)
	}
	if dlq.llamadas != 0 {
		t.Errorf("un usuario inexistente no manda el mensaje a la dlq")
	}
	if len(repo.reportes) != 1 {
		t.Errorf("el evento debía registrarse una vez como procesado, se registró %d", len(repo.reportes))
	}
}
