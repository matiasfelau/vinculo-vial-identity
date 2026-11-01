package postgres

import "time"

// queryTimeout acota cuánto puede tardar una consulta, incluyendo el tiempo
// de espera por una conexión libre del pool. Es una defensa adicional al
// statement_timeout configurado del lado del servidor (ver pkg/config):
// statement_timeout protege contra una sentencia que ya empezó a ejecutar y
// se cuelga, pero no contra el tiempo de espera previo a que la sentencia
// arranque, por ejemplo con el pool de conexiones agotado.
//
// El valor coincide con pkg/config.defaultStatementTimeout y con
// RENAPER_TIMEOUT a propósito: son las dos dependencias síncronas que
// /auth/signup encadena en el peor caso, y 1500 ms × 2 más el margen de
// Argon2id y el resto de la CPU propia mantiene el request completo bajo los
// 5000 ms del contrato de resiliencia.
const queryTimeout = 1500 * time.Millisecond
