package consumer

import amqp "github.com/rabbitmq/amqp091-go"

// deathCount lee el header x-death que RabbitMQ agrega cada vez que un mensaje
// es rechazado o expira desde una cola, y devuelve cuántas veces ocurrió eso
// específicamente en la cola de trabajo queue. Solo cuenta esa cola: la entrada
// de la cola .retry (por vencimiento del TTL) describe el mismo reintento y
// sumarla lo contaría dos veces. Un mensaje que nunca fue rechazado no trae
// x-death y devuelve 0.
func deathCount(headers amqp.Table, queue string) int64 {
	deaths, ok := headers["x-death"].([]any)
	if !ok {
		return 0
	}

	var count int64
	for _, entry := range deaths {
		table, ok := entry.(amqp.Table)
		if !ok {
			continue
		}
		if entryQueue, _ := table["queue"].(string); entryQueue != queue {
			continue
		}
		if c := asInt64(table["count"]); c > count {
			count = c
		}
	}
	return count
}

func asInt64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int32:
		return int64(n)
	case int:
		return int64(n)
	default:
		return 0
	}
}
