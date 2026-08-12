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
	CreatedAt     time.Time
	UpdatedAt     time.Time
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

// UserRegistered es el evento de dominio que se emite tras persistir un alta.
//
// No transporta PII: ni email, ni DNI, ni derivados del DNI. Los consumidores
// que necesiten datos del usuario los piden a este servicio.
type UserRegistered struct {
	UserID        uuid.UUID
	AccountStatus AccountStatus
	OccurredAt    time.Time
}

// NewUserRegistered deriva el evento a partir del usuario recién persistido.
func NewUserRegistered(u *User) UserRegistered {
	return UserRegistered{
		UserID:        u.ID,
		AccountStatus: u.AccountStatus,
		OccurredAt:    u.CreatedAt,
	}
}
