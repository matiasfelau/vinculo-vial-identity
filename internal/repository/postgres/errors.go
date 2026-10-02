package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

// classifyDBError traduce un error de la capa de persistencia al centinela de
// dominio que la capa HTTP necesita para mapear el código correcto, según la
// sección Postgres del contrato de resiliencia: deadline de contexto,
// SQLSTATE 08xxx (conexión), 53xxx (recursos agotados), 57014
// (statement_timeout) y 57P0x (apagado administrativo) se traducen a
// domain.ErrDatabaseUnavailable (503). Cualquier otro error se devuelve tal
// cual, para que el llamador lo trate como 500: 502 no aplica a la base.
func classifyDBError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && isUnavailableSQLState(pgErr.Code) {
		return fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
	}

	return err
}

func isUnavailableSQLState(code string) bool {
	switch {
	case strings.HasPrefix(code, "08"): // connection_exception
		return true
	case strings.HasPrefix(code, "53"): // insufficient_resources (pool/memoria/conexiones agotadas)
		return true
	case code == "57014": // query_canceled: lo dispara statement_timeout
		return true
	case strings.HasPrefix(code, "57P"): // operator_intervention (admin shutdown, crash shutdown)
		return true
	default:
		return false
	}
}
