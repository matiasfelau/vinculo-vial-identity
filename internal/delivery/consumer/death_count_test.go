package consumer

import (
	"testing"

	amqp "github.com/rabbitmq/amqp091-go"
)

func TestDeathCount(t *testing.T) {
	const otraCola = "notification.alert-created.q"

	casos := []struct {
		nombre  string
		headers amqp.Table
		want    int64
	}{
		{"sin headers", nil, 0},
		{"sin x-death", amqp.Table{"otro": "valor"}, 0},
		{"x-death de tipo inesperado", amqp.Table{"x-death": "roto"}, 0},
		{
			"cuenta de la cola de trabajo",
			amqp.Table{"x-death": []any{amqp.Table{"queue": colaDePrueba, "count": int64(3)}}},
			3,
		},
		{
			// El mensaje murió también en la cola .retry por vencimiento del
			// TTL: esa entrada describe el mismo reintento y no se suma.
			"ignora la entrada de la cola de reintento",
			amqp.Table{"x-death": []any{
				amqp.Table{"queue": colaDePrueba, "reason": "rejected", "count": int64(2)},
				amqp.Table{"queue": colaDePrueba + ".retry", "reason": "expired", "count": int64(2)},
			}},
			2,
		},
		{
			"ignora las colas de otros consumidores",
			amqp.Table{"x-death": []any{amqp.Table{"queue": otraCola, "count": int64(9)}}},
			0,
		},
		{
			"toma la cuenta mayor entre las entradas de la misma cola",
			amqp.Table{"x-death": []any{
				amqp.Table{"queue": colaDePrueba, "reason": "rejected", "count": int64(4)},
				amqp.Table{"queue": colaDePrueba, "reason": "expired", "count": int64(1)},
			}},
			4,
		},
		{
			"entradas ilegibles",
			amqp.Table{"x-death": []any{"roto", amqp.Table{"queue": colaDePrueba, "count": "tres"}}},
			0,
		},
		{
			"count int32",
			amqp.Table{"x-death": []any{amqp.Table{"queue": colaDePrueba, "count": int32(5)}}},
			5,
		},
	}

	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			if got := deathCount(c.headers, colaDePrueba); got != c.want {
				t.Errorf("deathCount = %d, se esperaba %d", got, c.want)
			}
		})
	}
}
