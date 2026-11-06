package domain

import "time"

// SanctionCarryover es la sanción de una cuenta penalizada que se dio de baja
// (US-11), guardada para que el mismo DNI no pueda borrarla dándose de baja y
// registrándose de nuevo. Es un dato operativo de Identity, no un registro de
// retención: vive hasta ExpiresAt (SANCTION_CARRYOVER_DAYS) o hasta que un
// nuevo registro con el mismo DNI la hereda, lo que ocurra primero.
//
// No lleva el user_id: la fila se vincula con el DNI y nada más. DNIHMAC es el
// mismo Blind Index que users.dni_hashed.
type SanctionCarryover struct {
	DNIHMAC         string
	AccountStatus   AccountStatus
	ReputationScore int
	ReportCount     int
	CreatedAt       time.Time
	ExpiresAt       time.Time
}
