//go:build integration

// Pruebas de integración contra un PostgreSQL real de ReputationRepository.
// ApplyReport (US-08): el conteo de reportes, el paso a UNDER_REVIEW y el
// evento user.status.changed del outbox, que tienen que confirmarse juntos.
// Mismas reglas que outbox_migration_test.go.
package postgres

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

const consumidorDeReportes = "identity.alert-reported.q"

func repositorioDeReportes(t *testing.T, db *gorm.DB) *ReputationRepository {
	t.Helper()

	repo := repositorioDeReputacion(t, db)
	if _, err := NewOutboxRepository(t.Context(), db); err != nil {
		t.Fatalf("migración de outbox_events: %v", err)
	}
	return repo
}

func eventoDeReporte() domain.ProcessedEvent {
	e := eventoDePrueba(consumidorDeReportes)
	e.EventType = "alert.reported"
	return e
}

func cambioDeEstadoParaOutbox(t *testing.T, userID uuid.UUID) domain.OutboxEvent {
	t.Helper()

	evt, err := domain.NewOutboxEvent(domain.EventTypeUserStatusChanged, map[string]string{
		"user_id":        userID.String(),
		"account_status": "UNDER_REVIEW",
		"reason":         "REPORTS_THRESHOLD",
	})
	if err != nil {
		t.Fatalf("no se pudo armar el evento: %v", err)
	}
	evt.CreatedAt = time.Now().UTC()
	return evt
}

func reportar(t *testing.T, repo *ReputationRepository, userID uuid.UUID, umbral int) domain.ReportOutcome {
	t.Helper()
	return reportarEvento(t, repo, eventoDeReporte(), userID, umbral)
}

func reportarEvento(t *testing.T, repo *ReputationRepository, evento domain.ProcessedEvent, userID uuid.UUID, umbral int) domain.ReportOutcome {
	t.Helper()

	res, err := repo.ApplyReport(t.Context(), evento, userID, umbral, cambioDeEstadoParaOutbox(t, userID))
	if err != nil {
		t.Fatalf("ApplyReport falló: %v", err)
	}
	return res
}

type filaOutbox struct {
	ID      uuid.UUID
	Type    string
	Payload []byte
	Status  string
}

func leerOutbox(t *testing.T, db *gorm.DB) []filaOutbox {
	t.Helper()

	var filas []filaOutbox
	if err := db.Raw(`SELECT id, type, payload, status FROM outbox_events ORDER BY created_at`).Scan(&filas).Error; err != nil {
		t.Fatalf("no se pudo leer outbox_events: %v", err)
	}
	return filas
}

// Con umbral 1 el primer reporte pone al usuario en revisión y escribe el
// outbox en la misma transacción.
func TestIntegracionApplyReportConUmbral1EscalaAlPrimerReporte(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo := repositorioDeReportes(t, db)
	id := usuarioNuevo(t, db)

	if res := reportar(t, repo, id, 1); res != domain.ReportEscalated {
		t.Fatalf("resultado = %v, se esperaba ReportEscalated", res)
	}

	f := leerReputacion(t, db, id)
	if f.ReportCount != 1 || f.AccountStatus != "UNDER_REVIEW" {
		t.Errorf("usuario = %+v, se esperaba report_count=1 y UNDER_REVIEW", f)
	}

	filas := leerOutbox(t, db)
	if len(filas) != 1 {
		t.Fatalf("filas de outbox = %d, se esperaba 1", len(filas))
	}
	if filas[0].Type != "user.status.changed" || filas[0].Status != "pending" {
		t.Errorf("outbox = %+v, se esperaba user.status.changed pendiente", filas[0])
	}
	var payload map[string]string
	if err := json.Unmarshal(filas[0].Payload, &payload); err != nil {
		t.Fatalf("payload ilegible: %v", err)
	}
	if payload["user_id"] != id.String() || payload["account_status"] != "UNDER_REVIEW" || payload["reason"] != "REPORTS_THRESHOLD" {
		t.Errorf("payload = %v", payload)
	}
	if n := contarEventos(t, db); n != 1 {
		t.Errorf("processed_events = %d filas, se esperaba 1", n)
	}
}

// Un segundo reporte cuenta, pero no vuelve a publicar.
func TestIntegracionApplyReportUnSegundoReporteNoVuelveAPublicar(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo := repositorioDeReportes(t, db)
	id := usuarioNuevo(t, db)

	if res := reportar(t, repo, id, 1); res != domain.ReportEscalated {
		t.Fatalf("primer reporte = %v, se esperaba ReportEscalated", res)
	}
	if res := reportar(t, repo, id, 1); res != domain.ReportCounted {
		t.Fatalf("segundo reporte = %v, se esperaba ReportCounted", res)
	}

	f := leerReputacion(t, db, id)
	if f.ReportCount != 2 || f.AccountStatus != "UNDER_REVIEW" {
		t.Errorf("usuario = %+v, se esperaba report_count=2 y UNDER_REVIEW", f)
	}
	if n := len(leerOutbox(t, db)); n != 1 {
		t.Errorf("filas de outbox = %d, se esperaba 1: no se vuelve a publicar", n)
	}
}

// Con umbral 3 recién el tercer reporte dispara el cambio.
func TestIntegracionApplyReportConUmbral3RecienEscalaElTercero(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo := repositorioDeReportes(t, db)
	id := usuarioNuevo(t, db)

	for i := 1; i <= 2; i++ {
		if res := reportar(t, repo, id, 3); res != domain.ReportCounted {
			t.Fatalf("reporte %d = %v, se esperaba ReportCounted", i, res)
		}
		f := leerReputacion(t, db, id)
		if f.ReportCount != i || f.AccountStatus != "ACTIVE" {
			t.Fatalf("tras el reporte %d: %+v, se esperaba ACTIVE con %d reportes", i, f, i)
		}
		if n := len(leerOutbox(t, db)); n != 0 {
			t.Fatalf("tras el reporte %d hay %d filas de outbox, se esperaba 0", i, n)
		}
	}

	if res := reportar(t, repo, id, 3); res != domain.ReportEscalated {
		t.Fatalf("tercer reporte = %v, se esperaba ReportEscalated", res)
	}
	f := leerReputacion(t, db, id)
	if f.ReportCount != 3 || f.AccountStatus != "UNDER_REVIEW" {
		t.Errorf("usuario = %+v, se esperaba report_count=3 y UNDER_REVIEW", f)
	}
	if n := len(leerOutbox(t, db)); n != 1 {
		t.Errorf("filas de outbox = %d, se esperaba 1", n)
	}
}

// Un duplicado no incrementa, ni siquiera cuando el original fue el que
// disparó la revisión.
func TestIntegracionApplyReportUnDuplicadoNoIncrementaNiVuelveAPublicar(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo := repositorioDeReportes(t, db)
	id := usuarioNuevo(t, db)

	evento := eventoDeReporte()
	if res := reportarEvento(t, repo, evento, id, 3); res != domain.ReportCounted {
		t.Fatalf("primera entrega = %v, se esperaba ReportCounted", res)
	}
	if res := reportarEvento(t, repo, evento, id, 3); res != domain.ReportDuplicate {
		t.Fatalf("segunda entrega = %v, se esperaba ReportDuplicate", res)
	}
	if f := leerReputacion(t, db, id); f.ReportCount != 1 {
		t.Errorf("report_count = %d, se esperaba 1: el duplicado no debe incrementar", f.ReportCount)
	}

	// Ahora el duplicado del evento que escaló.
	disparador := eventoDeReporte()
	if res := reportarEvento(t, repo, disparador, id, 2); res != domain.ReportEscalated {
		t.Fatalf("reporte que escala = %v, se esperaba ReportEscalated", res)
	}
	if res := reportarEvento(t, repo, disparador, id, 2); res != domain.ReportDuplicate {
		t.Fatalf("reentrega = %v, se esperaba ReportDuplicate", res)
	}
	if f := leerReputacion(t, db, id); f.ReportCount != 2 {
		t.Errorf("report_count = %d, se esperaba 2", f.ReportCount)
	}
	if n := len(leerOutbox(t, db)); n != 1 {
		t.Errorf("filas de outbox = %d, se esperaba 1", n)
	}
}

// Reportes distintos y concurrentes sobre el mismo usuario: todos cuentan y
// solo uno hace la transición y publica.
func TestIntegracionApplyReportConcurrentePublicaUnaSolaVez(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo := repositorioDeReportes(t, db)
	id := usuarioNuevo(t, db)

	const reportes = 10
	resultados := make([]domain.ReportOutcome, reportes)
	errores := make([]error, reportes)
	var wg sync.WaitGroup
	for i := range reportes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resultados[i], errores[i] = repo.ApplyReport(t.Context(), eventoDeReporte(), id, 3, cambioDeEstadoParaOutbox(t, id))
		}()
	}
	wg.Wait()

	escalados := 0
	for i := range reportes {
		if errores[i] != nil {
			t.Fatalf("reporte %d: %v", i, errores[i])
		}
		if resultados[i] == domain.ReportEscalated {
			escalados++
		}
	}
	if escalados != 1 {
		t.Errorf("reportes que escalaron = %d, se esperaba 1", escalados)
	}
	if f := leerReputacion(t, db, id); f.ReportCount != reportes || f.AccountStatus != "UNDER_REVIEW" {
		t.Errorf("usuario = %+v, se esperaba %d reportes y UNDER_REVIEW", f, reportes)
	}
	if n := len(leerOutbox(t, db)); n != 1 {
		t.Errorf("filas de outbox = %d, se esperaba 1", n)
	}
}

// Un usuario que ya estaba en revisión (por ejemplo, desde antes de este
// reporte) sigue contando pero no publica.
func TestIntegracionApplyReportDeUnUsuarioYaEnRevisionNoPublica(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo := repositorioDeReportes(t, db)
	id := usuarioNuevo(t, db)
	if err := db.Exec(`UPDATE users SET account_status = 'UNDER_REVIEW' WHERE id = ?`, id).Error; err != nil {
		t.Fatalf("no se pudo preparar el usuario: %v", err)
	}

	if res := reportar(t, repo, id, 1); res != domain.ReportCounted {
		t.Fatalf("resultado = %v, se esperaba ReportCounted", res)
	}
	if n := len(leerOutbox(t, db)); n != 0 {
		t.Errorf("filas de outbox = %d, se esperaba 0", n)
	}
}

func TestIntegracionApplyReportDeUnUsuarioInexistente(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo := repositorioDeReportes(t, db)

	if res := reportar(t, repo, uuid.New(), 1); res != domain.ReportUserNotFound {
		t.Fatalf("resultado = %v, se esperaba ReportUserNotFound", res)
	}
	if n := len(leerOutbox(t, db)); n != 0 {
		t.Errorf("filas de outbox = %d, se esperaba 0", n)
	}
}

// Si no se puede escribir el outbox, nada de lo demás se confirma: ni el
// conteo, ni el estado, ni la marca de deduplicación. El reintento tiene que
// poder procesar el reporte entero. Un trigger que rechaza todo INSERT en
// outbox_events fuerza el fallo.
func TestIntegracionApplyReportEsAtomicoConElOutbox(t *testing.T) {
	db := baseConEsquemaAislado(t)
	repo := repositorioDeReportes(t, db)
	id := usuarioNuevo(t, db)

	err := db.Exec(`
		CREATE FUNCTION rechazar_insert() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'insert rechazado por la prueba'; END $$;
		CREATE TRIGGER outbox_sin_insert BEFORE INSERT ON outbox_events
			FOR EACH ROW EXECUTE FUNCTION rechazar_insert();`).Error
	if err != nil {
		t.Fatalf("no se pudo armar el trigger: %v", err)
	}

	evento := eventoDeReporte()
	if _, err := repo.ApplyReport(t.Context(), evento, id, 1, cambioDeEstadoParaOutbox(t, id)); err == nil {
		t.Fatal("se esperaba un error al fallar el outbox")
	}
	f := leerReputacion(t, db, id)
	if f.ReportCount != 0 || f.AccountStatus != "ACTIVE" {
		t.Fatalf("usuario = %+v: el conteo y el estado debieron deshacerse", f)
	}
	if n := contarEventos(t, db); n != 0 {
		t.Fatalf("processed_events = %d filas: la marca debió deshacerse", n)
	}

	if err := db.Exec(`DROP TRIGGER outbox_sin_insert ON outbox_events`).Error; err != nil {
		t.Fatalf("no se pudo quitar el trigger: %v", err)
	}
	if res := reportarEvento(t, repo, evento, id, 1); res != domain.ReportEscalated {
		t.Fatalf("el reintento = %v, se esperaba ReportEscalated", res)
	}
	if n := len(leerOutbox(t, db)); n != 1 {
		t.Errorf("filas de outbox = %d, se esperaba 1", n)
	}
}
