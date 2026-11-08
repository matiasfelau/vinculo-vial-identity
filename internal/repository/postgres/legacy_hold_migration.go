package postgres

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

// Este archivo es el único que nombra el esquema legal_hold: el registro de
// retención de la baja de cuenta (US-11) que el Audit Service reemplazó. Existe
// solo para llevar una base que ya lo creó al esquema actual; una base nueva
// nunca lo ve.

// legacySchemaExists consulta el catálogo en lugar de intentar crear o borrar: no
// exige ningún permiso, así que con el esquema ya retirado el rol del servicio no
// necesita DDL sobre él.
const legacySchemaExists = `SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'legal_hold')`

const legacyHoldsTableExists = `SELECT to_regclass('legal_hold.user_holds') IS NOT NULL`

// copyLegacySanctions lleva a sanction_carryovers las sanciones vigentes que los
// holds guardaban para heredar: las filas con dni_hmac, que la baja solo escribía
// para una cuenta penalizada y el signup anulaba al heredarlas. El vencimiento es
// el destroy_at del hold, así que el plazo que ya corría no se extiende ni se
// acorta.
const copyLegacySanctions = `
INSERT INTO sanction_carryovers (dni_hmac, account_status, reputation_score, report_count, created_at, expires_at)
SELECT dni_hmac, account_status, reputation_score, report_count, deleted_at, destroy_at
FROM legal_hold.user_holds
WHERE dni_hmac IS NOT NULL
  AND account_status IS NOT NULL
  AND reputation_score IS NOT NULL
  AND report_count IS NOT NULL
  AND destroy_at > ?
ON CONFLICT (dni_hmac) DO NOTHING`

const dropLegacySchema = `DROP SCHEMA legal_hold CASCADE`

// dropLegacySchemaIfExists lo usa EPHEMERAL_DB: una base efímera arranca vacía, y
// un esquema anterior que sobreviviera al borrado de public se migraría y le haría
// heredar una sanción de una corrida anterior a un registro de la siguiente.
const dropLegacySchemaIfExists = `DROP SCHEMA IF EXISTS legal_hold CASCADE;`

// migrateLegacyHoldSchema copia las sanciones vigentes del esquema anterior y lo
// borra. Con el esquema ausente no hace nada, y por eso es idempotente: la
// segunda corrida (u otra réplica) no encuentra nada que migrar.
//
// Tiene que correr dentro de la transacción de ensureSanctionCarryovers: la copia
// y el DROP se confirman juntos, así que un fallo a mitad no pierde sanciones ni
// deja la base a medio migrar. Borrar el esquema exige ser su dueño; en un
// entorno donde pertenece a otro rol, el README documenta cómo lo aplica el DBA
// antes del despliegue, y entonces esta función ya no lo encuentra.
func migrateLegacyHoldSchema(tx *gorm.DB, now time.Time) error {
	var schemaExists bool
	if err := tx.Raw(legacySchemaExists).Scan(&schemaExists).Error; err != nil {
		return fmt.Errorf("no se pudo comprobar si existe el esquema anterior: %w", err)
	}
	if !schemaExists {
		return nil
	}

	var tableExists bool
	if err := tx.Raw(legacyHoldsTableExists).Scan(&tableExists).Error; err != nil {
		return fmt.Errorf("no se pudo comprobar si existe la tabla anterior: %w", err)
	}
	if tableExists {
		if err := tx.Exec(copyLegacySanctions, now.UTC()).Error; err != nil {
			return fmt.Errorf("no se pudieron copiar las sanciones del esquema anterior: %w", err)
		}
	}

	if err := tx.Exec(dropLegacySchema).Error; err != nil {
		return fmt.Errorf("no se pudo borrar el esquema anterior: %w", err)
	}
	return nil
}
