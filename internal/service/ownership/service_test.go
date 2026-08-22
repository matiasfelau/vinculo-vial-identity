package ownership_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
	"github.com/matiasfelau/vinculo-vial-identity/internal/service/ownership"
)

const validDNI = "30123456"

func validUser(ownerID uuid.UUID) *domain.User {
	return &domain.User{
		ID:            ownerID,
		Email:         "vecino@vinculovial.ar",
		DNIHashed:     "blind-index-de:" + validDNI,
		AccountStatus: domain.AccountStatusActive,
	}
}

// harness agrupa los tres dobles y el logger, para que cada test arme la vía
// feliz completa y degrade solo lo que le interesa ejercitar.
type harness struct {
	decryptor *decryptorMock
	indexer   *indexerMock
	users     *usersMock
	logs      *strings.Builder
}

func newHarness(ownerID uuid.UUID) *harness {
	return &harness{
		decryptor: &decryptorMock{plaintext: []byte(validDNI)},
		indexer:   &indexerMock{},
		users:     &usersMock{user: validUser(ownerID)},
		logs:      &strings.Builder{},
	}
}

func (h *harness) service(t *testing.T) *ownership.Service {
	t.Helper()

	svc, err := ownership.New(ownership.Deps{
		Decryptor: h.decryptor,
		Indexer:   h.indexer,
		Users:     h.users,
		Logger:    slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatalf("no se pudo construir el servicio: %v", err)
	}
	return svc
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func TestVerifyOwnershipConMatchDevuelveTrue(t *testing.T) {
	ownerID := uuid.New()
	h := newHarness(ownerID)
	svc := h.service(t)

	match, err := svc.VerifyOwnership(context.Background(), ownerID, []byte("criptograma"))
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if !match {
		t.Error("match = false, se esperaba true")
	}

	if h.users.calls != 1 {
		t.Fatalf("se consultó %d veces, se esperaba 1", h.users.calls)
	}
	if h.users.ownerIDs[0] != ownerID {
		t.Errorf("owner_id consultado = %v, se esperaba %v", h.users.ownerIDs[0], ownerID)
	}
	if want := "blind-index-de:" + validDNI; h.users.dniHashes[0] != want {
		t.Errorf("dni_hashed consultado = %q, se esperaba %q", h.users.dniHashes[0], want)
	}
}

// Que el owner_id no corresponda a ningún usuario y que corresponda a un
// usuario con otro DNI tienen que producir exactamente el mismo resultado:
// distinguirlos habilitaría usar este endpoint como oráculo de verificación
// de DNI.
func TestVerifyOwnershipSinMatchDevuelveFalseSinError(t *testing.T) {
	cases := map[string]error{
		"el DNI pertenece a otro owner_id": domain.ErrUserNotFound,
		"el owner_id no existe":            domain.ErrUserNotFound,
	}

	for name, repoErr := range cases {
		t.Run(name, func(t *testing.T) {
			ownerID := uuid.New()
			h := newHarness(ownerID)
			h.users.err = repoErr
			svc := h.service(t)

			match, err := svc.VerifyOwnership(context.Background(), ownerID, []byte("criptograma"))
			if err != nil {
				t.Fatalf("error inesperado: %v", err)
			}
			if match {
				t.Error("match = true, se esperaba false")
			}
		})
	}
}

// El único error que puede devolver VerifyOwnership es el del descifrado, y
// se propaga sin traducir: la clasificación en 400/500 es responsabilidad del
// handler HTTP (feature/verify-ownership-endpoint), no de este servicio.
func TestVerifyOwnershipPropagaElErrorDeDescifradoSinTraducirlo(t *testing.T) {
	ownerID := uuid.New()
	h := newHarness(ownerID)
	h.decryptor.err = domain.ErrMalformedCryptogram
	svc := h.service(t)

	_, err := svc.VerifyOwnership(context.Background(), ownerID, []byte("criptograma"))
	if !errors.Is(err, domain.ErrMalformedCryptogram) {
		t.Errorf("error = %v, se esperaba ErrMalformedCryptogram", err)
	}

	if h.users.calls != 0 {
		t.Error("no debería consultarse el repositorio si el descifrado falló")
	}
}

// Un fallo de infraestructura al consultar el repositorio no es lo mismo que
// un match=false: tiene que propagarse como error, para que el handler lo
// traduzca a 500 y no a la respuesta booleana normal del endpoint.
func TestVerifyOwnershipPropagaUnFalloDeInfraestructuraDelRepositorio(t *testing.T) {
	ownerID := uuid.New()
	h := newHarness(ownerID)
	h.users.err = errors.New("connection reset by peer")
	svc := h.service(t)

	match, err := svc.VerifyOwnership(context.Background(), ownerID, []byte("criptograma"))
	if err == nil {
		t.Fatal("se esperaba un error")
	}
	if match {
		t.Error("match = true ante un fallo de infraestructura")
	}
	if errors.Is(err, domain.ErrUserNotFound) {
		t.Error("un fallo de infraestructura no debe colapsar en ErrUserNotFound")
	}
}

// El Blind Index tiene que calcularse sobre el mismo DNI normalizado que usan
// /signup y /signin (sin puntos ni espacios): si no, un DNI que el QR
// codificó con separadores nunca matchearía contra el hash ya persistido.
func TestVerifyOwnershipNormalizaElDNIAntesDeCalcularElBlindIndex(t *testing.T) {
	ownerID := uuid.New()
	h := newHarness(ownerID)
	h.decryptor.plaintext = []byte("30.123.456")
	svc := h.service(t)

	if _, err := svc.VerifyOwnership(context.Background(), ownerID, []byte("criptograma")); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if len(h.indexer.values) != 1 || h.indexer.values[0] != validDNI {
		t.Errorf("Index recibió %v, se esperaba [%q] (normalizado, sin puntos)", h.indexer.values, validDNI)
	}
}

// Zero-Retention: tanto el plaintext que devuelve el descifrador como el DNI
// normalizado que se deriva de él tienen que quedar en ceros después de la
// llamada, exista o no coincidencia y falle o no la consulta.
func TestVerifyOwnershipLimpiaLosBuffersEnClaroEnTodosLosCaminos(t *testing.T) {
	cases := map[string]error{
		"match exitoso":                    nil,
		"sin match":                        domain.ErrUserNotFound,
		"falla la consulta al repositorio": errors.New("connection reset by peer"),
	}

	for name, repoErr := range cases {
		t.Run(name, func(t *testing.T) {
			ownerID := uuid.New()
			h := newHarness(ownerID)
			h.users.err = repoErr
			svc := h.service(t)

			if _, err := svc.VerifyOwnership(context.Background(), ownerID, []byte("criptograma")); repoErr == nil && err != nil {
				t.Fatalf("error inesperado: %v", err)
			}

			if !allZero(h.decryptor.returned) {
				t.Error("el plaintext descifrado no quedó en ceros")
			}
			if !allZero(h.indexer.received) {
				t.Error("el DNI normalizado no quedó en ceros")
			}
		})
	}
}

// Ningún camino de esta función debe devolver el error crudo de dominio
// ErrUserNotFound hacia arriba: el llamador tiene que recibir match=false, no
// un error que podría filtrarse en una respuesta o distinguirse de otro tipo
// de fallo.
func TestVerifyOwnershipNuncaPropagaErrUserNotFound(t *testing.T) {
	ownerID := uuid.New()
	h := newHarness(ownerID)
	h.users.err = domain.ErrUserNotFound
	svc := h.service(t)

	_, err := svc.VerifyOwnership(context.Background(), ownerID, []byte("criptograma"))
	if errors.Is(err, domain.ErrUserNotFound) {
		t.Errorf("ErrUserNotFound no debería salir de VerifyOwnership, se obtuvo: %v", err)
	}
}

func TestNewValidaLasDependencias(t *testing.T) {
	ownerID := uuid.New()
	completo := newHarness(ownerID)

	cases := map[string]ownership.Deps{
		"sin descifrador": {Indexer: completo.indexer, Users: completo.users},
		"sin indexador":   {Decryptor: completo.decryptor, Users: completo.users},
		"sin repositorio": {Decryptor: completo.decryptor, Indexer: completo.indexer},
	}

	for name, deps := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ownership.New(deps); err == nil {
				t.Error("se esperaba un error por dependencias incompletas")
			}
		})
	}
}

// El registro deja constancia de toda verificación —con y sin match— por
// owner_id: es la señal que permite detectar un volumen anómalo de consultas
// sobre este endpoint, que CLAUDE.md señala como un oráculo potencial de
// fuerza bruta. El DNI en claro nunca debe aparecer en el log.
func TestVerifyOwnershipRegistraElResultadoSinFiltrarElDNI(t *testing.T) {
	ownerID := uuid.New()
	h := newHarness(ownerID)
	svc := h.service(t)

	if _, err := svc.VerifyOwnership(context.Background(), ownerID, []byte("criptograma")); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	logged := h.logs.String()
	if !strings.Contains(logged, ownerID.String()) {
		t.Error("el log debería referenciar el owner_id")
	}
	if strings.Contains(logged, validDNI) {
		t.Errorf("el log filtra el DNI en claro: %s", logged)
	}
}
