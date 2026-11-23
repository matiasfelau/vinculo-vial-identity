// Package domain contiene el modelo de negocio del bounded context de identidad
// y los puertos (interfaces) que la capa de aplicación necesita para operar.
//
// Regla dura de la arquitectura: este paquete no importa gin, gorm, circl ni amqp.
// Solo la librería estándar y tipos de valor sin comportamiento de infraestructura.
package domain

import (
	"time"

	"github.com/google/uuid"
)

// AccountStatus representa el estado del ciclo de vida de una cuenta.
type AccountStatus string

const (
	// AccountStatusActive es el estado con el que nace toda cuenta en US-01.
	AccountStatusActive AccountStatus = "ACTIVE"
	// AccountStatusUnderReview es el estado de un emisor reportado por
	// REPORT_REVIEW_THRESHOLD destinatarios (US-08). Restringe solo la creación
	// de alertas, que decide Alert a partir de user.status.changed: no bloquea
	// el login, el refresh, el buzón ni la gestión de vehículos. Salir de este
	// estado es manual y fuera de alcance de US-08: hacerlo a mano en la base no
	// alcanza, también hay que emitir user.status.changed con ACTIVE.
	AccountStatusUnderReview AccountStatus = "UNDER_REVIEW"
)

// User es la entidad raíz del bounded context.
//
// Ningún campo guarda el DNI en claro: el número solo existe en memoria durante
// el registro y se persiste de dos formas complementarias:
//
//   - DNIHashed: Blind Index (HMAC-SHA256) determinístico, permite detectar
//     duplicados sin exponer el dato.
//   - DNIEncrypted: cifrado simétrico reversible (AES-256-GCM) con una clave
//     distinta a la de transporte, para respaldo y auditoría.
type User struct {
	ID            uuid.UUID
	Email         string
	PasswordHash  string
	DNIHashed     string
	DNIEncrypted  string
	AccountStatus AccountStatus
	// ReputationScore es la reputación del usuario. Identity es su única
	// fuente de verdad: nace en 0 y solo baja, por cada alerta rechazada por
	// fraude. Puede quedar negativa.
	ReputationScore int
	// ReportCount es la cantidad de reportes recibidos de los destinatarios de
	// sus alertas. Solo el conteo: no se guarda quién reportó.
	ReportCount int
	// EmailVerifiedAt es cuándo se verificó el email con un código (US-13). Nil en
	// las cuentas que nunca lo verificaron: solo una cuenta con este campo no
	// nulo puede recuperar su contraseña.
	EmailVerifiedAt *time.Time
	// TermsVersion y TermsAcceptedAt (US-19) son la versión de los Términos y
	// Condiciones que el usuario aceptó en el alta y cuándo: el consentimiento
	// registrado que exige el art. 5 de la Ley 25.326. Quedan vacíos (nil) en las
	// cuentas anteriores a US-19 y en las dadas de alta con SIGNUP_REQUIRE_TERMS=false
	// sin el campo; ahí no hay consentimiento registrado.
	TermsVersion    string
	TermsAcceptedAt *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// AcceptTerms registra que el usuario aceptó esa versión de los términos en ese
// instante.
func (u *User) AcceptTerms(version string, at time.Time) {
	accepted := at.UTC()
	u.TermsVersion = version
	u.TermsAcceptedAt = &accepted
}

// IsPenalized informa si la cuenta tiene alguna sanción (US-11): está en
// revisión, recibió reportes o tiene reputación negativa. Es lo que decide si
// la baja deja una SanctionCarryover con que reconocer al mismo DNI si se vuelve
// a registrar.
func (u *User) IsPenalized() bool {
	return u.AccountStatus == AccountStatusUnderReview || u.ReportCount > 0 || u.ReputationScore < 0
}

// InheritSanction hace que la cuenta nazca con la sanción que dejó una cuenta
// anterior del mismo DNI al darse de baja (US-11).
func (u *User) InheritSanction(s SanctionCarryover) {
	u.AccountStatus = s.AccountStatus
	u.ReputationScore = s.ReputationScore
	u.ReportCount = s.ReportCount
}

// NewUser construye un User válido con los invariantes del alta.
//
// Recibe los valores ya derivados criptográficamente: la entidad nunca ve un
// DNI ni una contraseña en claro. Si algún invariante no se cumple devuelve un
// error envuelto en ErrInvalidUser, lo que indica un bug de orquestación (no un
// dato inválido del cliente, que se rechaza antes en la capa de validación).
func NewUser(email, passwordHash, dniHashed, dniEncrypted string, now time.Time) (*User, error) {
	switch {
	case email == "":
		return nil, invalidUser("email vacío")
	case passwordHash == "":
		return nil, invalidUser("hash de password vacío")
	case dniHashed == "":
		return nil, invalidUser("blind index de DNI vacío")
	case dniEncrypted == "":
		return nil, invalidUser("DNI cifrado vacío")
	}

	return &User{
		ID:            uuid.New(),
		Email:         email,
		PasswordHash:  passwordHash,
		DNIHashed:     dniHashed,
		DNIEncrypted:  dniEncrypted,
		AccountStatus: AccountStatusActive,
		CreatedAt:     now.UTC(),
		UpdatedAt:     now.UTC(),
	}, nil
}
