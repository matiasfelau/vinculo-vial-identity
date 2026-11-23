//go:build integration

// Pruebas de integración contra un PostgreSQL real de la verificación de email y
// la recuperación de contraseña (US-13): la tabla email_challenges, la
// mutación atómica de los desafíos, la transacción que completa la recuperación,
// el consumo del grant en el alta, el barrido y el borrado de las filas de
// email.requested al enviarse. Mismas reglas que outbox_migration_test.go:
// requieren TEST_DATABASE_URL y trabajan en un esquema propio que se borra al
// terminar.
package postgres

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/matiasfelau/vinculo-vial-identity/internal/crypto/emailcode"
	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/emailchallenge"
)

// reposDeRecuperacion agrupa los repositorios que toca US-13, ya migrados en el
// orden en que los arma cmd/api.
type reposDeRecuperacion struct {
	db         *gorm.DB
	users      *UserRepository
	sessions   *SessionRepository
	outbox     *OutboxRepository
	challenges *EmailChallengeRepository
}

func nuevosReposDeRecuperacion(t *testing.T) reposDeRecuperacion {
	t.Helper()

	db := baseConEsquemaAislado(t)
	ctx := t.Context()

	users, err := NewUserRepository(ctx, db)
	if err != nil {
		t.Fatalf("NewUserRepository: %v", err)
	}
	sessions, err := NewSessionRepository(ctx, db)
	if err != nil {
		t.Fatalf("NewSessionRepository: %v", err)
	}
	challenges, err := NewEmailChallengeRepository(ctx, db)
	if err != nil {
		t.Fatalf("NewEmailChallengeRepository: %v", err)
	}
	outbox, err := NewOutboxRepository(ctx, db)
	if err != nil {
		t.Fatalf("NewOutboxRepository: %v", err)
	}
	return reposDeRecuperacion{db: db, users: users, sessions: sessions, outbox: outbox, challenges: challenges}
}

// ahoraUTC es "ahora" truncado a microsegundos, la precisión de timestamptz: así
// lo escrito se puede comparar con lo leído.
func ahoraUTC() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

func desafioDe(purpose domain.EmailChallengePurpose, subject string) *domain.EmailChallenge {
	return &domain.EmailChallenge{Purpose: purpose, SubjectHMAC: subject}
}

// guardarDesafio inserta un desafío ya armado, para preparar un estado de partida.
func guardarDesafio(t *testing.T, db *gorm.DB, c domain.EmailChallenge) domain.EmailChallenge {
	t.Helper()

	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = ahoraUTC()
	}
	if err := db.Create(toEmailChallengeModel(&c)).Error; err != nil {
		t.Fatalf("no se pudo insertar el desafío: %v", err)
	}
	return c
}

func leerDesafio(t *testing.T, db *gorm.DB, purpose domain.EmailChallengePurpose, subject string) *domain.EmailChallenge {
	t.Helper()

	var m emailChallengeModel
	err := db.Where("purpose = ? AND subject_hmac = ?", string(purpose), subject).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	if err != nil {
		t.Fatalf("no se pudo leer el desafío: %v", err)
	}
	return m.toDomain()
}

func enOutbox(t *testing.T, db *gorm.DB, tipo string) int64 {
	t.Helper()
	return contar(t, db, `SELECT count(*) FROM outbox_events WHERE type = ?`, tipo)
}

func usuarioVerificado(t *testing.T, db *gorm.DB) *domain.User {
	t.Helper()

	u, err := domain.NewUser(uuid.NewString()+"@example.com", "hash-viejo", uuid.NewString(), "dni-cifrado", ahoraUTC())
	if err != nil {
		t.Fatalf("no se pudo armar el usuario: %v", err)
	}
	verificado := ahoraUTC()
	u.EmailVerifiedAt = &verificado
	if err := db.Create(toModel(u)).Error; err != nil {
		t.Fatalf("no se pudo insertar el usuario: %v", err)
	}
	return u
}

func eventoDeEmail(t *testing.T, template domain.EmailTemplate) domain.OutboxEvent {
	t.Helper()

	evt, err := domain.NewEmailRequestedOutboxEvent(domain.EmailRequest{Template: template, To: "vecino@example.com"}, ahoraUTC())
	if err != nil {
		t.Fatalf("no se pudo armar email.requested: %v", err)
	}
	return evt
}

func eventoDeSesiones(t *testing.T, userID uuid.UUID) domain.OutboxEvent {
	t.Helper()

	evt, err := domain.NewOutboxEvent(domain.EventTypeUserSessionsRevoked, map[string]string{
		"user_id": userID.String(), "reason": string(domain.SessionsRevokedReasonPasswordReset),
	})
	if err != nil {
		t.Fatalf("no se pudo armar user.sessions.revoked: %v", err)
	}
	evt.CreatedAt = ahoraUTC()
	return evt
}

// ── Esquema ──────────────────────────────────────────────────────────────────

func TestIntegracionEmailChallengesCumpleElContratoDeDatos(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)

	type col struct {
		ColumnName string
		DataType   string
		IsNullable string
		Longitud   *int `gorm:"column:character_maximum_length"`
	}
	var cols []col
	if err := r.db.Raw(`SELECT column_name, data_type, is_nullable, character_maximum_length
		FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'email_challenges'`).Scan(&cols).Error; err != nil {
		t.Fatalf("no se pudo consultar el catálogo: %v", err)
	}

	// La tabla del contrato: nombre → (tipo, nulable, largo).
	want := map[string]struct {
		tipo     string
		nulable  bool
		longitud int
	}{
		"id":                      {"uuid", false, 0},
		"purpose":                 {"character varying", false, 32},
		"subject_hmac":            {"character varying", false, 64},
		"user_id":                 {"uuid", true, 0},
		"code_hmac":               {"character varying", true, 64},
		"code_expires_at":         {"timestamp with time zone", true, 0},
		"code_attempts":           {"integer", false, 0},
		"grant_hash":              {"character varying", true, 64},
		"grant_expires_at":        {"timestamp with time zone", true, 0},
		"grant_attempts":          {"integer", false, 0},
		"sends_count":             {"integer", false, 0},
		"sends_window_started_at": {"timestamp with time zone", true, 0},
		"last_sent_at":            {"timestamp with time zone", true, 0},
		"consumed_at":             {"timestamp with time zone", true, 0},
		"created_at":              {"timestamp with time zone", false, 0},
	}
	got := map[string]col{}
	for _, c := range cols {
		got[c.ColumnName] = c
	}
	if len(got) != len(want) {
		t.Errorf("la tabla tiene %d columnas, el contrato define %d", len(got), len(want))
	}
	for name, w := range want {
		c, ok := got[name]
		if !ok {
			t.Errorf("falta la columna %s", name)
			continue
		}
		if c.DataType != w.tipo {
			t.Errorf("%s: tipo %q, se esperaba %q", name, c.DataType, w.tipo)
		}
		if (c.IsNullable == "YES") != w.nulable {
			t.Errorf("%s: nulable=%s, se esperaba %v", name, c.IsNullable, w.nulable)
		}
		if w.longitud != 0 && (c.Longitud == nil || *c.Longitud != w.longitud) {
			t.Errorf("%s: largo %v, se esperaba %d", name, c.Longitud, w.longitud)
		}
	}

	// users.email_verified_at: timestamptz nulable.
	var tipo, nulable string
	if err := r.db.Raw(`SELECT data_type, is_nullable FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 'email_verified_at'`).
		Row().Scan(&tipo, &nulable); err != nil {
		t.Fatalf("users.email_verified_at no existe: %v", err)
	}
	if tipo != "timestamp with time zone" || nulable != "YES" {
		t.Errorf("users.email_verified_at = (%s, nulable=%s), se esperaba timestamptz nulable", tipo, nulable)
	}
}

func TestIntegracionEmailChallengesTieneLasUnicidadesYLaClaveForanea(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	db := r.db
	u := usuarioVerificado(t, db)

	// (purpose, subject_hmac) es único.
	guardarDesafio(t, db, domain.EmailChallenge{Purpose: domain.EmailChallengePurposePasswordReset, SubjectHMAC: "s"})
	dup := domain.EmailChallenge{ID: uuid.New(), Purpose: domain.EmailChallengePurposePasswordReset, SubjectHMAC: "s", CreatedAt: ahoraUTC()}
	if err := db.Create(toEmailChallengeModel(&dup)).Error; err == nil {
		t.Error("se aceptó un segundo desafío con el mismo (purpose, subject_hmac)")
	}
	// El mismo subject con otro propósito sí.
	guardarDesafio(t, db, domain.EmailChallenge{Purpose: domain.EmailChallengePurposeEmailVerification, SubjectHMAC: "s"})

	// grant_hash es único, pero varias filas sin grant conviven.
	guardarDesafio(t, db, domain.EmailChallenge{Purpose: domain.EmailChallengePurposeEmailVerification, SubjectHMAC: "g1", GrantHash: "h"})
	otro := domain.EmailChallenge{ID: uuid.New(), Purpose: domain.EmailChallengePurposeEmailVerification, SubjectHMAC: "g2", GrantHash: "h", CreatedAt: ahoraUTC()}
	if err := db.Create(toEmailChallengeModel(&otro)).Error; err == nil {
		t.Error("se aceptaron dos desafíos con el mismo grant_hash")
	}
	guardarDesafio(t, db, domain.EmailChallenge{Purpose: domain.EmailChallengePurposeEmailVerification, SubjectHMAC: "sin-grant-1"})
	guardarDesafio(t, db, domain.EmailChallenge{Purpose: domain.EmailChallengePurposeEmailVerification, SubjectHMAC: "sin-grant-2"})

	// user_id referencia a users: un usuario inexistente se rechaza, y la baja de la
	// cuenta se lleva sus desafíos.
	huerfano := domain.EmailChallenge{ID: uuid.New(), Purpose: domain.EmailChallengePurposePasswordReset, SubjectHMAC: "x",
		UserID: ptr(uuid.New()), CreatedAt: ahoraUTC()}
	if err := db.Create(toEmailChallengeModel(&huerfano)).Error; err == nil {
		t.Error("se aceptó un desafío de un usuario inexistente")
	}
	guardarDesafio(t, db, domain.EmailChallenge{Purpose: domain.EmailChallengePurposePasswordReset, SubjectHMAC: "del-usuario", UserID: &u.ID})
	if err := db.Exec(`DELETE FROM users WHERE id = ?`, u.ID).Error; err != nil {
		t.Fatalf("no se pudo borrar el usuario: %v", err)
	}
	if leerDesafio(t, db, domain.EmailChallengePurposePasswordReset, "del-usuario") != nil {
		t.Error("el desafío sobrevivió a la baja de la cuenta: la clave foránea tiene que ser ON DELETE CASCADE")
	}
}

func ptr[T any](v T) *T { return &v }

func TestIntegracionLaMigracionDeEmailChallengesEsIdempotenteYSegura(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	ctx := t.Context()

	// Repetirla no falla ni pierde datos.
	guardarDesafio(t, r.db, domain.EmailChallenge{Purpose: domain.EmailChallengePurposePasswordReset, SubjectHMAC: "persiste"})
	for range 2 {
		if _, err := NewEmailChallengeRepository(ctx, r.db); err != nil {
			t.Fatalf("repetir NewEmailChallengeRepository: %v", err)
		}
		if _, err := NewUserRepository(ctx, r.db); err != nil {
			t.Fatalf("repetir NewUserRepository: %v", err)
		}
	}
	if leerDesafio(t, r.db, domain.EmailChallengePurposePasswordReset, "persiste") == nil {
		t.Error("la migración repetida borró datos")
	}

	// Con varias réplicas arrancando a la vez: el advisory lock las serializa.
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := NewEmailChallengeRepository(ctx, r.db)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("migración concurrente: %v", err)
		}
	}
}

func TestIntegracionElRepositorioExigeUnaConexion(t *testing.T) {
	if _, err := NewEmailChallengeRepository(t.Context(), nil); err == nil {
		t.Error("se aceptó una conexión nil")
	}
}

// ── Mutate ───────────────────────────────────────────────────────────────────

func TestIntegracionMutateCreaElDesafioYEncolaSusEventosJuntos(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	u := usuarioVerificado(t, r.db)
	ahora := ahoraUTC()
	expira := ahora.Add(10 * time.Minute)

	err := r.challenges.Mutate(t.Context(), domain.EmailChallengePurposePasswordReset, "subject-1", true,
		func(c *domain.EmailChallenge) ([]domain.OutboxEvent, error) {
			if c.ID == uuid.Nil || c.CodeHMAC != "" || c.CodeAttempts != 0 || c.SendsCount != 0 {
				t.Errorf("el desafío nuevo no llegó vacío: %+v", c)
			}
			c.UserID = &u.ID
			c.CodeHMAC, c.CodeExpiresAt, c.CodeAttempts = "hmac-del-codigo", &expira, 2
			c.SendsCount, c.SendsWindowStartedAt, c.LastSentAt = 1, &ahora, &ahora
			return []domain.OutboxEvent{eventoDeEmail(t, domain.EmailTemplatePasswordReset)}, nil
		})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}

	got := leerDesafio(t, r.db, domain.EmailChallengePurposePasswordReset, "subject-1")
	if got == nil {
		t.Fatal("el desafío no se guardó")
	}
	if got.UserID == nil || *got.UserID != u.ID || got.CodeHMAC != "hmac-del-codigo" || got.CodeAttempts != 2 || got.SendsCount != 1 {
		t.Errorf("desafío guardado = %+v", got)
	}
	if got.CodeExpiresAt == nil || !got.CodeExpiresAt.Equal(expira) || got.LastSentAt == nil || !got.LastSentAt.Equal(ahora) {
		t.Errorf("fechas guardadas = %+v", got)
	}
	if got.GrantHash != "" || got.GrantExpiresAt != nil || got.ConsumedAt != nil {
		t.Errorf("los campos sin valor tienen que quedar en NULL: %+v", got)
	}
	if n := enOutbox(t, r.db, domain.EventTypeEmailRequested); n != 1 {
		t.Errorf("hay %d email.requested en el outbox, se esperaba 1", n)
	}
}

// Los NULL se escriben de verdad: vaciar un campo con valor lo deja en NULL, no en
// la cadena vacía (que rompería la unicidad de grant_hash).
func TestIntegracionMutateVaciarUnCampoLoDejaEnNull(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	ahora := ahoraUTC()
	guardarDesafio(t, r.db, domain.EmailChallenge{
		Purpose: domain.EmailChallengePurposeEmailVerification, SubjectHMAC: "s",
		CodeHMAC: "c", CodeExpiresAt: &ahora, GrantHash: "g", GrantExpiresAt: &ahora, ConsumedAt: &ahora,
	})

	err := r.challenges.Mutate(t.Context(), domain.EmailChallengePurposeEmailVerification, "s", false,
		func(c *domain.EmailChallenge) ([]domain.OutboxEvent, error) {
			c.CodeHMAC, c.CodeExpiresAt = "", nil
			c.GrantHash, c.GrantExpiresAt, c.ConsumedAt = "", nil, nil
			return nil, nil
		})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}

	if n := contar(t, r.db, `SELECT count(*) FROM email_challenges
		WHERE code_hmac IS NULL AND code_expires_at IS NULL AND grant_hash IS NULL AND grant_expires_at IS NULL AND consumed_at IS NULL`); n != 1 {
		t.Errorf("los campos vaciados no quedaron en NULL (filas que cumplen: %d)", n)
	}
}

func TestIntegracionMutateSinCrearNoEncuentraYNoCreaNada(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)

	err := r.challenges.Mutate(t.Context(), domain.EmailChallengePurposePasswordReset, "no-existe", false,
		func(*domain.EmailChallenge) ([]domain.OutboxEvent, error) {
			t.Error("la mutación no tendría que ejecutarse sin desafío")
			return nil, nil
		})

	if !errors.Is(err, domain.ErrChallengeNotFound) {
		t.Fatalf("error = %v, se esperaba ErrChallengeNotFound", err)
	}
	if n := contar(t, r.db, `SELECT count(*) FROM email_challenges`); n != 0 {
		t.Errorf("quedaron %d desafíos", n)
	}
}

// Si la mutación falla, no queda nada hecho: ni el desafío nuevo, ni los cambios
// a uno existente, ni los eventos.
func TestIntegracionMutateQueFallaNoDejaNadaHecho(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	boom := errors.New("boom")

	t.Run("desafío nuevo", func(t *testing.T) {
		err := r.challenges.Mutate(t.Context(), domain.EmailChallengePurposeEmailVerification, "nuevo", true,
			func(c *domain.EmailChallenge) ([]domain.OutboxEvent, error) {
				c.CodeHMAC = "x"
				return []domain.OutboxEvent{eventoDeEmail(t, domain.EmailTemplateEmailVerification)}, boom
			})
		if !errors.Is(err, boom) {
			t.Fatalf("error = %v, se esperaba el de la mutación", err)
		}
		if leerDesafio(t, r.db, domain.EmailChallengePurposeEmailVerification, "nuevo") != nil {
			t.Error("quedó el desafío creado antes del fallo")
		}
		if n := enOutbox(t, r.db, domain.EventTypeEmailRequested); n != 0 {
			t.Errorf("quedaron %d eventos en el outbox", n)
		}
	})

	t.Run("desafío existente", func(t *testing.T) {
		guardarDesafio(t, r.db, domain.EmailChallenge{Purpose: domain.EmailChallengePurposeEmailVerification, SubjectHMAC: "viejo", CodeAttempts: 1})
		err := r.challenges.Mutate(t.Context(), domain.EmailChallengePurposeEmailVerification, "viejo", false,
			func(c *domain.EmailChallenge) ([]domain.OutboxEvent, error) {
				c.CodeAttempts = 99
				return nil, boom
			})
		if !errors.Is(err, boom) {
			t.Fatalf("error = %v", err)
		}
		if got := leerDesafio(t, r.db, domain.EmailChallengePurposeEmailVerification, "viejo").CodeAttempts; got != 1 {
			t.Errorf("code_attempts = %d, el cambio debió deshacerse", got)
		}
	})

	t.Run("falla el outbox", func(t *testing.T) {
		evt := eventoDeEmail(t, domain.EmailTemplateEmailVerification)
		guardarDesafio(t, r.db, domain.EmailChallenge{Purpose: domain.EmailChallengePurposeEmailVerification, SubjectHMAC: "outbox"})
		// Dos eventos con el mismo ID violan la clave primaria del segundo INSERT.
		err := r.challenges.Mutate(t.Context(), domain.EmailChallengePurposeEmailVerification, "outbox", false,
			func(c *domain.EmailChallenge) ([]domain.OutboxEvent, error) {
				c.CodeAttempts = 7
				return []domain.OutboxEvent{evt, evt}, nil
			})
		if err == nil {
			t.Fatal("se esperaba el error del outbox")
		}
		if got := leerDesafio(t, r.db, domain.EmailChallengePurposeEmailVerification, "outbox").CodeAttempts; got != 0 {
			t.Errorf("code_attempts = %d: el cambio se confirmó sin su evento", got)
		}
		if n := enOutbox(t, r.db, domain.EventTypeEmailRequested); n != 0 {
			t.Errorf("quedaron %d eventos", n)
		}
	})
}

func TestIntegracionMutateRechazaArgumentosInvalidos(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	ok := func(*domain.EmailChallenge) ([]domain.OutboxEvent, error) { return nil, nil }

	if err := r.challenges.Mutate(t.Context(), "OTRO", "s", true, ok); err == nil {
		t.Error("propósito inválido aceptado")
	}
	if err := r.challenges.Mutate(t.Context(), domain.EmailChallengePurposePasswordReset, "", true, ok); err == nil {
		t.Error("subject vacío aceptado")
	}
	if err := r.challenges.Mutate(t.Context(), domain.EmailChallengePurposePasswordReset, "s", true, nil); err == nil {
		t.Error("mutación nil aceptada")
	}
}

// Dos pedidos concurrentes del mismo subject se serializan: no hay una fila
// duplicada ni actualizaciones perdidas.
func TestIntegracionMutateSerializaLosPedidosConcurrentesDelMismoSubject(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)

	const goroutines = 16
	var wg sync.WaitGroup
	var fallos atomic.Int64
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := r.challenges.Mutate(t.Context(), domain.EmailChallengePurposeEmailVerification, "concurrente", true,
				func(c *domain.EmailChallenge) ([]domain.OutboxEvent, error) {
					c.CodeAttempts++
					return nil, nil
				})
			if err != nil {
				fallos.Add(1)
				t.Errorf("Mutate: %v", err)
			}
		}()
	}
	wg.Wait()

	if fallos.Load() != 0 {
		t.FailNow()
	}
	if n := contar(t, r.db, `SELECT count(*) FROM email_challenges WHERE subject_hmac = 'concurrente'`); n != 1 {
		t.Fatalf("hay %d filas para el subject, se esperaba 1", n)
	}
	if got := leerDesafio(t, r.db, domain.EmailChallengePurposeEmailVerification, "concurrente").CodeAttempts; got != goroutines {
		t.Errorf("code_attempts = %d, se esperaban %d: se perdieron actualizaciones", got, goroutines)
	}
}

// El throttle no se puede saltear con paralelismo: con el motor real sobre
// Postgres, dieciséis pedidos simultáneos del mismo email producen un único mail.
func TestIntegracionElThrottleNoSeSalteaConPedidosParalelos(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	codec, err := emailcode.New(make([]byte, emailcode.KeyLength))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := emailchallenge.New(emailchallenge.Deps{
		Challenges: r.challenges, Codec: codec,
		Settings: emailchallenge.Settings{CodeTTL: 10 * time.Minute, MaxCodeAttempts: 5, ResendInterval: time.Minute, MaxSendsPerDay: 5},
	})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var enviados atomic.Int64
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outcome, err := engine.Issue(t.Context(), emailchallenge.IssueParams{
				Purpose: domain.EmailChallengePurposeEmailVerification, Subject: "vecino@example.com",
				To: "vecino@example.com", Template: domain.EmailTemplateEmailVerification, WithCode: true,
			})
			if err != nil {
				t.Errorf("Issue: %v", err)
			}
			if outcome == emailchallenge.Sent {
				enviados.Add(1)
			}
		}()
	}
	wg.Wait()

	if enviados.Load() != 1 {
		t.Errorf("%d pedidos pasaron el throttle, se esperaba 1", enviados.Load())
	}
	if n := enOutbox(t, r.db, domain.EventTypeEmailRequested); n != 1 {
		t.Errorf("hay %d mails en el outbox, se esperaba 1", n)
	}
}

// ── Grants ───────────────────────────────────────────────────────────────────

func TestIntegracionFindByGrantHash(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	expira := ahoraUTC().Add(time.Hour)
	guardarDesafio(t, r.db, domain.EmailChallenge{
		Purpose: domain.EmailChallengePurposeEmailVerification, SubjectHMAC: "s", GrantHash: "el-hash", GrantExpiresAt: &expira,
	})

	got, err := r.challenges.FindByGrantHash(t.Context(), "el-hash")
	if err != nil {
		t.Fatalf("FindByGrantHash: %v", err)
	}
	if got.SubjectHMAC != "s" || got.GrantHash != "el-hash" || got.GrantExpiresAt == nil || !got.GrantExpiresAt.Equal(expira) {
		t.Errorf("desafío = %+v", got)
	}

	if _, err := r.challenges.FindByGrantHash(t.Context(), "otro"); !errors.Is(err, domain.ErrChallengeNotFound) {
		t.Errorf("hash desconocido: error = %v, se esperaba ErrChallengeNotFound", err)
	}
}

func TestIntegracionAddGrantAttemptSumaAtomicamenteYNoTocaLosConsumidos(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	consumido := ahoraUTC()
	guardarDesafio(t, r.db, domain.EmailChallenge{Purpose: domain.EmailChallengePurposePasswordReset, SubjectHMAC: "vivo", GrantHash: "vivo"})
	guardarDesafio(t, r.db, domain.EmailChallenge{Purpose: domain.EmailChallengePurposePasswordReset, SubjectHMAC: "usado", GrantHash: "usado", ConsumedAt: &consumido})

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := r.challenges.AddGrantAttempt(t.Context(), "vivo"); err != nil {
				t.Errorf("AddGrantAttempt: %v", err)
			}
		}()
	}
	wg.Wait()
	if err := r.challenges.AddGrantAttempt(t.Context(), "usado"); err != nil {
		t.Fatalf("AddGrantAttempt sobre el consumido: %v", err)
	}
	if err := r.challenges.AddGrantAttempt(t.Context(), "no-existe"); err != nil {
		t.Errorf("un hash desconocido no es un error: %v", err)
	}

	if got := leerDesafio(t, r.db, domain.EmailChallengePurposePasswordReset, "vivo").GrantAttempts; got != 10 {
		t.Errorf("grant_attempts = %d, se esperaban 10 (sin pérdidas)", got)
	}
	if got := leerDesafio(t, r.db, domain.EmailChallengePurposePasswordReset, "usado").GrantAttempts; got != 0 {
		t.Errorf("el grant consumido sumó %d intentos", got)
	}
}

// ── Alta con verificación de email ───────────────────────────────────────────

func aspiranteAUsuario(t *testing.T) *domain.User {
	t.Helper()
	u, err := domain.NewUser(uuid.NewString()+"@example.com", "hash", uuid.NewString(), "dni-cifrado", ahoraUTC())
	if err != nil {
		t.Fatalf("no se pudo armar el usuario: %v", err)
	}
	return u
}

func grantDeVerificacion(t *testing.T, db *gorm.DB, subject, hash string, tune ...func(*domain.EmailChallenge)) *domain.GrantConsumption {
	t.Helper()

	expira := ahoraUTC().Add(30 * time.Minute)
	c := domain.EmailChallenge{
		Purpose: domain.EmailChallengePurposeEmailVerification, SubjectHMAC: subject, GrantHash: hash, GrantExpiresAt: &expira,
	}
	for _, f := range tune {
		f(&c)
	}
	guardarDesafio(t, db, c)
	return &domain.GrantConsumption{
		Purpose: domain.EmailChallengePurposeEmailVerification, SubjectHMAC: subject, GrantHash: hash, Now: ahoraUTC(),
	}
}

func TestIntegracionElAltaConsumeElGrantYGuardaElEmailVerificado(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	grant := grantDeVerificacion(t, r.db, "email-hmac", "grant-1")
	u := aspiranteAUsuario(t)
	verificado := grant.Now
	u.EmailVerifiedAt = &verificado

	if err := r.users.Create(t.Context(), u, domain.OutboxEvent{}, grant); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := r.users.FindByID(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.EmailVerifiedAt == nil || !got.EmailVerifiedAt.Equal(verificado) {
		t.Errorf("email_verified_at = %v, se esperaba %v", got.EmailVerifiedAt, verificado)
	}
	if c := leerDesafio(t, r.db, domain.EmailChallengePurposeEmailVerification, "email-hmac"); c.ConsumedAt == nil {
		t.Error("el grant no quedó consumido")
	}
}

func TestIntegracionElAltaSinGrantNaceConElEmailSinVerificar(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	u := aspiranteAUsuario(t)

	if err := r.users.Create(t.Context(), u, domain.OutboxEvent{}, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, _ := r.users.FindByID(t.Context(), u.ID)
	if got.EmailVerifiedAt != nil {
		t.Errorf("email_verified_at = %v, se esperaba NULL", got.EmailVerifiedAt)
	}
}

// US-19: la versión de los términos y su fecha se guardan con el usuario, en la
// misma inserción del alta, y vuelven al leerlo.
func TestIntegracionElAltaGuardaLaVersionYLaFechaDeLosTerminos(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	u := aspiranteAUsuario(t)
	aceptado := ahoraUTC()
	u.AcceptTerms("1.0", aceptado)

	if err := r.users.Create(t.Context(), u, domain.OutboxEvent{}, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := r.users.FindByID(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.TermsVersion != "1.0" {
		t.Errorf("terms_version = %q, se esperaba \"1.0\"", got.TermsVersion)
	}
	if got.TermsAcceptedAt == nil || !got.TermsAcceptedAt.Equal(aceptado) {
		t.Errorf("terms_accepted_at = %v, se esperaba %v", got.TermsAcceptedAt, aceptado)
	}
}

// Un alta sin términos —flag apagado— deja las dos columnas en NULL, no en "".
func TestIntegracionElAltaSinTerminosDejaLasColumnasEnNull(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	u := aspiranteAUsuario(t)

	if err := r.users.Create(t.Context(), u, domain.OutboxEvent{}, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}

	var version *string
	var aceptados *time.Time
	row := r.db.Raw("SELECT terms_version, terms_accepted_at FROM users WHERE id = ?", u.ID).Row()
	if err := row.Scan(&version, &aceptados); err != nil {
		t.Fatalf("no se pudo leer las columnas: %v", err)
	}
	if version != nil || aceptados != nil {
		t.Errorf("terms = (%v, %v), se esperaba NULL y NULL", version, aceptados)
	}
}

// Un alta que falla no deja el consentimiento a medias: el grant inválido deshace
// la transacción entera, con los términos incluidos.
func TestIntegracionUnAltaRechazadaNoDejaTerminosGuardados(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	u := aspiranteAUsuario(t)
	u.AcceptTerms("1.0", ahoraUTC())
	grantInexistente := &domain.GrantConsumption{
		Purpose: domain.EmailChallengePurposeEmailVerification, SubjectHMAC: "no-existe", GrantHash: "no-existe", Now: ahoraUTC(),
	}

	err := r.users.Create(t.Context(), u, domain.OutboxEvent{}, grantInexistente)
	if !errors.Is(err, domain.ErrEmailNotVerified) {
		t.Fatalf("Create = %v, se esperaba ErrEmailNotVerified", err)
	}

	var cuantos int64
	if err := r.db.Raw("SELECT count(*) FROM users WHERE id = ?", u.ID).Row().Scan(&cuantos); err != nil {
		t.Fatalf("no se pudo contar: %v", err)
	}
	if cuantos != 0 {
		t.Errorf("hay %d usuarios, se esperaba 0", cuantos)
	}
}

// Un grant que ya no sirve —usado, vencido, de otro email, inexistente— frena el
// alta entera: ni usuario ni nada consumido.
func TestIntegracionElAltaRechazaUnGrantQueNoSirveSinCrearElUsuario(t *testing.T) {
	pasado := ahoraUTC().Add(-time.Minute)
	usado := ahoraUTC()

	casos := map[string]struct {
		tune  func(c *domain.EmailChallenge)
		grant func(g *domain.GrantConsumption)
	}{
		"vencido":           {func(c *domain.EmailChallenge) { c.GrantExpiresAt = &pasado }, nil},
		"usado":             {func(c *domain.EmailChallenge) { c.ConsumedAt = &usado }, nil},
		"de otro email":     {nil, func(g *domain.GrantConsumption) { g.SubjectHMAC = "otro-email" }},
		"hash desconocido":  {nil, func(g *domain.GrantConsumption) { g.GrantHash = "desconocido" }},
		"de otro propósito": {nil, func(g *domain.GrantConsumption) { g.Purpose = domain.EmailChallengePurposePasswordReset }},
	}
	for name, tc := range casos {
		t.Run(name, func(t *testing.T) {
			r := nuevosReposDeRecuperacion(t)
			var tunes []func(*domain.EmailChallenge)
			if tc.tune != nil {
				tunes = append(tunes, tc.tune)
			}
			grant := grantDeVerificacion(t, r.db, "email-hmac", "grant-1", tunes...)
			if tc.grant != nil {
				tc.grant(grant)
			}
			u := aspiranteAUsuario(t)

			err := r.users.Create(t.Context(), u, domain.OutboxEvent{}, grant)

			if !errors.Is(err, domain.ErrEmailNotVerified) {
				t.Fatalf("error = %v, se esperaba ErrEmailNotVerified", err)
			}
			if existeUsuario(t, r.db, u.ID) {
				t.Error("se creó el usuario pese al grant inválido")
			}
		})
	}
}

// Un alta que falla —aquí, por email duplicado— no gasta el grant: el vecino puede
// corregir y reintentar con el mismo token.
func TestIntegracionUnAltaDuplicadaNoConsumeElGrant(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	existente := aspiranteAUsuario(t)
	if err := r.users.Create(t.Context(), existente, domain.OutboxEvent{}, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	grant := grantDeVerificacion(t, r.db, "email-hmac", "grant-1")

	repetido := aspiranteAUsuario(t)
	repetido.Email = existente.Email
	err := r.users.Create(t.Context(), repetido, domain.OutboxEvent{}, grant)

	if !errors.Is(err, domain.ErrDuplicateUser) {
		t.Fatalf("error = %v, se esperaba ErrDuplicateUser", err)
	}
	if c := leerDesafio(t, r.db, domain.EmailChallengePurposeEmailVerification, "email-hmac"); c.ConsumedAt != nil {
		t.Error("el alta que falló consumió el grant")
	}
}

// Dos altas con el mismo token: una sola pasa.
func TestIntegracionUnGrantNoSirveParaDosAltas(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	grant := grantDeVerificacion(t, r.db, "email-hmac", "grant-1")

	const goroutines = 8
	var wg sync.WaitGroup
	var exitos, rechazos atomic.Int64
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := r.users.Create(t.Context(), aspiranteAUsuario(t), domain.OutboxEvent{}, grant)
			switch {
			case err == nil:
				exitos.Add(1)
			case errors.Is(err, domain.ErrEmailNotVerified):
				rechazos.Add(1)
			default:
				t.Errorf("error inesperado: %v", err)
			}
		}()
	}
	wg.Wait()

	if exitos.Load() != 1 || rechazos.Load() != goroutines-1 {
		t.Errorf("éxitos=%d rechazos=%d, se esperaban 1 y %d", exitos.Load(), rechazos.Load(), goroutines-1)
	}
	if n := contar(t, r.db, `SELECT count(*) FROM users`); n != 1 {
		t.Errorf("hay %d usuarios, se esperaba 1", n)
	}
}

func TestIntegracionExistsByEmail(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	u := aspiranteAUsuario(t)
	if err := r.users.Create(t.Context(), u, domain.OutboxEvent{}, nil); err != nil {
		t.Fatal(err)
	}

	if ok, err := r.users.ExistsByEmail(t.Context(), u.Email); err != nil || !ok {
		t.Errorf("ExistsByEmail(existente) = (%v, %v), se esperaba (true, nil)", ok, err)
	}
	if ok, err := r.users.ExistsByEmail(t.Context(), "nadie@example.com"); err != nil || ok {
		t.Errorf("ExistsByEmail(inexistente) = (%v, %v), se esperaba (false, nil)", ok, err)
	}
}

// ── Completar la recuperación ────────────────────────────────────────────────

// unaRecuperacion deja listo un usuario con sesiones, un reset_token vigente y la
// recuperación armada.
func unaRecuperacion(t *testing.T, r reposDeRecuperacion) (*domain.User, domain.PasswordResetCompletion) {
	t.Helper()

	u := usuarioVerificado(t, r.db)
	conSesiones(t, r.db, u.ID, 3)
	expira := ahoraUTC().Add(15 * time.Minute)
	guardarDesafio(t, r.db, domain.EmailChallenge{
		Purpose: domain.EmailChallengePurposePasswordReset, SubjectHMAC: "reset-" + u.ID.String(),
		UserID: &u.ID, GrantHash: "reset-grant", GrantExpiresAt: &expira,
	})

	return u, domain.PasswordResetCompletion{
		GrantHash: "reset-grant", MaxIdentityAttempts: 3, UserID: u.ID, PasswordHash: "hash-nuevo", Now: ahoraUTC(),
		SessionsRevoked: eventoDeSesiones(t, u.ID),
		PasswordChanged: eventoDeEmail(t, domain.EmailTemplatePasswordChanged),
	}
}

func sesionesVivas(t *testing.T, db *gorm.DB, userID uuid.UUID) int64 {
	t.Helper()
	return contar(t, db, `SELECT count(*) FROM sessions WHERE user_id = ? AND is_revoked = false`, userID)
}

func hashDeLaContrasena(t *testing.T, db *gorm.DB, userID uuid.UUID) string {
	t.Helper()
	var h string
	if err := db.Raw(`SELECT password FROM users WHERE id = ?`, userID).Scan(&h).Error; err != nil {
		t.Fatal(err)
	}
	return h
}

func TestIntegracionCompletarLaRecuperacionHaceTodoEnUnaTransaccion(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	u, c := unaRecuperacion(t, r)

	if err := r.challenges.CompletePasswordReset(t.Context(), c); err != nil {
		t.Fatalf("CompletePasswordReset: %v", err)
	}

	if got := hashDeLaContrasena(t, r.db, u.ID); got != "hash-nuevo" {
		t.Errorf("password = %q, se esperaba el hash nuevo", got)
	}
	if n := sesionesVivas(t, r.db, u.ID); n != 0 {
		t.Errorf("quedaron %d sesiones vivas", n)
	}
	if n := contar(t, r.db, `SELECT count(*) FROM sessions WHERE user_id = ? AND is_revoked = true`, u.ID); n != 3 {
		t.Errorf("hay %d sesiones revocadas, se esperaban 3", n)
	}
	if ch := leerDesafio(t, r.db, domain.EmailChallengePurposePasswordReset, "reset-"+u.ID.String()); ch.ConsumedAt == nil {
		t.Error("el reset_token no quedó consumido")
	}
	if n := enOutbox(t, r.db, domain.EventTypeUserSessionsRevoked); n != 1 {
		t.Errorf("hay %d user.sessions.revoked, se esperaba 1", n)
	}
	if n := enOutbox(t, r.db, domain.EventTypeEmailRequested); n != 1 {
		t.Errorf("hay %d email.requested, se esperaba 1", n)
	}

	var payload string
	if err := r.db.Raw(`SELECT payload::text FROM outbox_events WHERE type = ?`, domain.EventTypeUserSessionsRevoked).Scan(&payload).Error; err != nil {
		t.Fatal(err)
	}
	if want := `"reason": "PASSWORD_RESET"`; !strings.Contains(payload, want) {
		t.Errorf("payload = %s, se esperaba el motivo PASSWORD_RESET", payload)
	}
}

// Si cualquier paso falla, no queda nada hecho: la contraseña, las sesiones, el
// token y el outbox siguen como estaban.
func TestIntegracionSiFallaCompletarLaRecuperacionNoQuedaNadaHecho(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	u, c := unaRecuperacion(t, r)
	// El segundo evento repite el ID del primero: viola la clave primaria del
	// outbox en el último paso de la transacción.
	c.PasswordChanged.ID = c.SessionsRevoked.ID

	err := r.challenges.CompletePasswordReset(t.Context(), c)

	if err == nil {
		t.Fatal("se esperaba el error del outbox")
	}
	if got := hashDeLaContrasena(t, r.db, u.ID); got != "hash-viejo" {
		t.Errorf("password = %q: el cambio se confirmó pese al fallo", got)
	}
	if n := sesionesVivas(t, r.db, u.ID); n != 3 {
		t.Errorf("hay %d sesiones vivas, se esperaban 3: la revocación se confirmó pese al fallo", n)
	}
	if ch := leerDesafio(t, r.db, domain.EmailChallengePurposePasswordReset, "reset-"+u.ID.String()); ch.ConsumedAt != nil {
		t.Error("el token quedó consumido pese al fallo")
	}
	if n := contar(t, r.db, `SELECT count(*) FROM outbox_events`); n != 0 {
		t.Errorf("quedaron %d eventos en el outbox", n)
	}
}

func TestIntegracionCompletarLaRecuperacionConUnTokenQueNoSirveNoCambiaNada(t *testing.T) {
	pasado := ahoraUTC().Add(-time.Minute)
	usado := ahoraUTC()

	casos := map[string]func(t *testing.T, r reposDeRecuperacion, u *domain.User, c *domain.PasswordResetCompletion){
		"desconocido": func(t *testing.T, _ reposDeRecuperacion, _ *domain.User, c *domain.PasswordResetCompletion) {
			c.GrantHash = "nadie"
		},
		"vencido": func(t *testing.T, r reposDeRecuperacion, _ *domain.User, _ *domain.PasswordResetCompletion) {
			r.db.Exec(`UPDATE email_challenges SET grant_expires_at = ?`, pasado)
		},
		"usado": func(t *testing.T, r reposDeRecuperacion, _ *domain.User, _ *domain.PasswordResetCompletion) {
			r.db.Exec(`UPDATE email_challenges SET consumed_at = ?`, usado)
		},
		"sin intentos": func(t *testing.T, r reposDeRecuperacion, _ *domain.User, _ *domain.PasswordResetCompletion) {
			r.db.Exec(`UPDATE email_challenges SET grant_attempts = 3`)
		},
		"de otro usuario": func(t *testing.T, r reposDeRecuperacion, _ *domain.User, c *domain.PasswordResetCompletion) {
			c.UserID = usuarioVerificado(t, r.db).ID
		},
		"de verificación de email": func(t *testing.T, r reposDeRecuperacion, _ *domain.User, _ *domain.PasswordResetCompletion) {
			r.db.Exec(`UPDATE email_challenges SET purpose = 'EMAIL_VERIFICATION'`)
		},
	}
	for name, mutar := range casos {
		t.Run(name, func(t *testing.T) {
			r := nuevosReposDeRecuperacion(t)
			u, c := unaRecuperacion(t, r)
			mutar(t, r, u, &c)

			err := r.challenges.CompletePasswordReset(t.Context(), c)

			if !errors.Is(err, domain.ErrInvalidResetToken) {
				t.Fatalf("error = %v, se esperaba ErrInvalidResetToken", err)
			}
			if got := hashDeLaContrasena(t, r.db, u.ID); got != "hash-viejo" {
				t.Errorf("password = %q, no debió cambiar", got)
			}
			if n := sesionesVivas(t, r.db, u.ID); n != 3 {
				t.Errorf("hay %d sesiones vivas, se esperaban 3", n)
			}
			if n := contar(t, r.db, `SELECT count(*) FROM outbox_events`); n != 0 {
				t.Errorf("se encolaron %d eventos", n)
			}
		})
	}
}

// Dos recuperaciones concurrentes con el mismo token: una sola cambia la
// contraseña.
func TestIntegracionUnResetTokenNoSirveParaDosRecuperaciones(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	u, c := unaRecuperacion(t, r)

	const goroutines = 8
	var wg sync.WaitGroup
	var exitos, rechazos atomic.Int64
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mine := c
			mine.PasswordHash = "hash-" + uuid.NewString()[:8]
			mine.SessionsRevoked = eventoDeSesiones(t, u.ID)
			mine.PasswordChanged = eventoDeEmail(t, domain.EmailTemplatePasswordChanged)
			switch err := r.challenges.CompletePasswordReset(t.Context(), mine); {
			case err == nil:
				exitos.Add(1)
			case errors.Is(err, domain.ErrInvalidResetToken):
				rechazos.Add(1)
			default:
				t.Errorf("error inesperado: %v", err)
			}
		}()
	}
	wg.Wait()

	if exitos.Load() != 1 || rechazos.Load() != goroutines-1 {
		t.Errorf("éxitos=%d rechazos=%d, se esperaban 1 y %d", exitos.Load(), rechazos.Load(), goroutines-1)
	}
	if n := enOutbox(t, r.db, domain.EventTypeEmailRequested); n != 1 {
		t.Errorf("hay %d avisos PASSWORD_CHANGED, se esperaba 1", n)
	}
}

func TestIntegracionCompletarLaRecuperacionExigeLosDatos(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	_, c := unaRecuperacion(t, r)

	for name, tune := range map[string]func(*domain.PasswordResetCompletion){
		"sin grant":      func(c *domain.PasswordResetCompletion) { c.GrantHash = "" },
		"sin usuario":    func(c *domain.PasswordResetCompletion) { c.UserID = uuid.Nil },
		"sin contraseña": func(c *domain.PasswordResetCompletion) { c.PasswordHash = "" },
	} {
		mine := c
		tune(&mine)
		if err := r.challenges.CompletePasswordReset(t.Context(), mine); err == nil {
			t.Errorf("%s: se aceptó una recuperación incompleta", name)
		}
	}
}

// ── Barrido ──────────────────────────────────────────────────────────────────

func TestIntegracionElBarridoBorraSoloLoQueVencioPorCompleto(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	ahora := ahoraUTC()
	viejo := ahora.Add(-48 * time.Hour)
	futuro := ahora.Add(time.Hour)
	ventanaViva := ahora.Add(-time.Hour) // la ventana de 24 h sigue abierta

	guardarDesafio(t, r.db, domain.EmailChallenge{Purpose: domain.EmailChallengePurposeEmailVerification, SubjectHMAC: "vencido",
		CodeExpiresAt: &viejo, GrantExpiresAt: &viejo, SendsWindowStartedAt: &viejo})
	guardarDesafio(t, r.db, domain.EmailChallenge{Purpose: domain.EmailChallengePurposeEmailVerification, SubjectHMAC: "sin-plazos"})
	guardarDesafio(t, r.db, domain.EmailChallenge{Purpose: domain.EmailChallengePurposeEmailVerification, SubjectHMAC: "codigo-vivo",
		CodeExpiresAt: &futuro, GrantExpiresAt: &viejo, SendsWindowStartedAt: &viejo})
	guardarDesafio(t, r.db, domain.EmailChallenge{Purpose: domain.EmailChallengePurposeEmailVerification, SubjectHMAC: "grant-vivo",
		CodeExpiresAt: &viejo, GrantExpiresAt: &futuro, SendsWindowStartedAt: &viejo})
	guardarDesafio(t, r.db, domain.EmailChallenge{Purpose: domain.EmailChallengePurposeEmailVerification, SubjectHMAC: "ventana-viva",
		CodeExpiresAt: &viejo, GrantExpiresAt: &viejo, SendsWindowStartedAt: &ventanaViva})

	borrados, err := r.challenges.DeleteExpired(t.Context(), ahora, 100)
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}

	if borrados != 2 {
		t.Errorf("borró %d, se esperaban 2 (vencido y sin-plazos)", borrados)
	}
	for _, s := range []string{"vencido", "sin-plazos"} {
		if leerDesafio(t, r.db, domain.EmailChallengePurposeEmailVerification, s) != nil {
			t.Errorf("%s no se borró", s)
		}
	}
	for _, s := range []string{"codigo-vivo", "grant-vivo", "ventana-viva"} {
		if leerDesafio(t, r.db, domain.EmailChallengePurposeEmailVerification, s) == nil {
			t.Errorf("%s se borró pese a tener un plazo vigente", s)
		}
	}
}

func TestIntegracionElBarridoRespetaElLimiteDelLote(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	viejo := ahoraUTC().Add(-48 * time.Hour)
	for _, s := range []string{"a", "b", "c", "d", "e"} {
		guardarDesafio(t, r.db, domain.EmailChallenge{Purpose: domain.EmailChallengePurposeEmailVerification, SubjectHMAC: s,
			CodeExpiresAt: &viejo, GrantExpiresAt: &viejo, SendsWindowStartedAt: &viejo})
	}

	borrados, err := r.challenges.DeleteExpired(t.Context(), ahoraUTC(), 2)
	if err != nil || borrados != 2 {
		t.Fatalf("DeleteExpired = (%d, %v), se esperaba (2, nil)", borrados, err)
	}
	if n := contar(t, r.db, `SELECT count(*) FROM email_challenges`); n != 3 {
		t.Errorf("quedan %d, se esperaban 3", n)
	}
	if _, err := r.challenges.DeleteExpired(t.Context(), ahoraUTC(), 0); err == nil {
		t.Error("un lote de 0 debería rechazarse")
	}
}

// Dos réplicas barriendo a la vez reparten el trabajo: lo borrado entre las dos es
// exactamente lo que había, sin duplicar ni dejar nada.
func TestIntegracionDosBarridosConcurrentesRepartenElTrabajo(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	viejo := ahoraUTC().Add(-48 * time.Hour)
	const filas = 40
	for i := range filas {
		guardarDesafio(t, r.db, domain.EmailChallenge{Purpose: domain.EmailChallengePurposeEmailVerification, SubjectHMAC: uuid.NewString() + string(rune('a'+i%26)),
			CodeExpiresAt: &viejo, GrantExpiresAt: &viejo, SendsWindowStartedAt: &viejo})
	}

	var wg sync.WaitGroup
	var total atomic.Int64
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				n, err := r.challenges.DeleteExpired(t.Context(), ahoraUTC(), 5)
				if err != nil {
					t.Errorf("DeleteExpired: %v", err)
					return
				}
				total.Add(n)
				if n < 5 {
					return
				}
			}
		}()
	}
	wg.Wait()

	if total.Load() != filas {
		t.Errorf("entre las dos borraron %d, se esperaban %d", total.Load(), filas)
	}
	if n := contar(t, r.db, `SELECT count(*) FROM email_challenges`); n != 0 {
		t.Errorf("quedaron %d filas", n)
	}
}

// ── Outbox: borrado al enviar ────────────────────────────────────────────────

func TestIntegracionLasFilasDeEmailRequestedSeBorranAlMarcarseEnviadas(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	ctx := t.Context()

	email := eventoDeEmail(t, domain.EmailTemplatePasswordReset)
	sesiones := eventoDeSesiones(t, uuid.New())
	for _, e := range []domain.OutboxEvent{email, sesiones} {
		if err := r.db.Create(toOutboxModel(&e)).Error; err != nil {
			t.Fatalf("no se pudo encolar: %v", err)
		}
	}

	if err := r.outbox.MarkSent(ctx, email.ID); err != nil {
		t.Fatalf("MarkSent(email.requested): %v", err)
	}
	if err := r.outbox.MarkSent(ctx, sesiones.ID); err != nil {
		t.Fatalf("MarkSent(user.sessions.revoked): %v", err)
	}

	// La del email se borró (lleva el email y el código en claro)...
	if n := contar(t, r.db, `SELECT count(*) FROM outbox_events WHERE id = ?`, email.ID); n != 0 {
		t.Error("la fila de email.requested sigue en el outbox tras enviarse")
	}
	// ...y la de otro tipo se marcó como enviada, como siempre.
	var estado string
	if err := r.db.Raw(`SELECT status FROM outbox_events WHERE id = ?`, sesiones.ID).Scan(&estado).Error; err != nil || estado != outboxStatusSent {
		t.Errorf("estado de user.sessions.revoked = %q (err %v), se esperaba %q", estado, err, outboxStatusSent)
	}
}

func TestIntegracionUnEmailRequestedPendienteSeguiraPendienteHastaEnviarse(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	email := eventoDeEmail(t, domain.EmailTemplateEmailVerification)
	if err := r.db.Create(toOutboxModel(&email)).Error; err != nil {
		t.Fatal(err)
	}

	if err := r.outbox.MarkFailed(t.Context(), email.ID, "el broker no responde"); err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}

	pend, err := r.outbox.FetchPending(t.Context(), 10)
	if err != nil || len(pend) != 1 || pend[0].ID != email.ID {
		t.Fatalf("FetchPending = (%v, %v), se esperaba el evento fallido, aún pendiente", pend, err)
	}

	// Marcar como enviado un id que no existe no es un error.
	if err := r.outbox.MarkSent(t.Context(), uuid.New()); err != nil {
		t.Errorf("MarkSent sobre un id inexistente: %v", err)
	}
}

// La revocación de sesiones sigue funcionando por su propio camino, que ahora
// comparte el cuerpo con la recuperación.
func TestIntegracionRevokeAllByUserIDSigueRevocandoYEncolando(t *testing.T) {
	r := nuevosReposDeRecuperacion(t)
	u := usuarioVerificado(t, r.db)
	conSesiones(t, r.db, u.ID, 2)
	evt := eventoDeSesiones(t, u.ID)

	if err := r.sessions.RevokeAllByUserID(t.Context(), u.ID, &evt); err != nil {
		t.Fatalf("RevokeAllByUserID: %v", err)
	}

	if n := sesionesVivas(t, r.db, u.ID); n != 0 {
		t.Errorf("quedaron %d sesiones vivas", n)
	}
	if n := enOutbox(t, r.db, domain.EventTypeUserSessionsRevoked); n != 1 {
		t.Errorf("hay %d eventos, se esperaba 1", n)
	}
}
