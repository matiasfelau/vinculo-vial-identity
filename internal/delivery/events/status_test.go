package events

import "testing"

// Un Publisher sin conexión —nunca conectó, o la perdió— informa down. La
// conexión viva se ejerce contra un broker real (ver README, Eventos
// publicados).
func TestPublisherSinConexionInformaDown(t *testing.T) {
	p := &Publisher{}

	if estado, ok := p.Status(); estado != "down" || ok {
		t.Errorf("Status = (%q, %v), se esperaba (down, false)", estado, ok)
	}
}

func TestPublisherCerradoInformaDown(t *testing.T) {
	p := &Publisher{}
	if err := p.Close(); err != nil {
		t.Fatalf("Close sin conexión no debería fallar: %v", err)
	}

	if estado, ok := p.Status(); estado != "down" || ok {
		t.Errorf("Status = (%q, %v), se esperaba (down, false)", estado, ok)
	}
}

// Deshabilitado es el modo de desarrollo, no una degradación.
func TestNoopPublisherInformaDeshabilitadoPeroSano(t *testing.T) {
	p := NewNoopPublisher(nil)

	if estado, ok := p.Status(); estado != "disabled" || !ok {
		t.Errorf("Status = (%q, %v), se esperaba (disabled, true)", estado, ok)
	}
}

// Tras Close el publisher no debe reconectarse por su cuenta: el worker puede
// estar a mitad de un ciclo durante el apagado, y reabrir la conexión la
// dejaría huérfana.
func TestEnsureConnectedNoReconectaUnPublisherCerrado(t *testing.T) {
	p := &Publisher{cfg: Config{URL: "amqp://localhost:1"}}
	if err := p.Close(); err != nil {
		t.Fatalf("Close no debería fallar: %v", err)
	}

	if err := p.EnsureConnected(t.Context()); err == nil {
		t.Error("se esperaba un error al reconectar un publisher cerrado")
	}
}
