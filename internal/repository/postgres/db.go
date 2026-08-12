package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// Config son los parámetros de conexión y del pool.
type Config struct {
	// DSN es la cadena de conexión de PostgreSQL.
	DSN string
	// MaxOpenConns acota las conexiones simultáneas contra la base.
	MaxOpenConns int
	// MaxIdleConns es el tamaño del pool ocioso.
	MaxIdleConns int
	// ConnMaxLifetime fuerza el reciclado periódico de conexiones, para que un
	// failover del lado del servidor no deje conexiones muertas en el pool.
	ConnMaxLifetime time.Duration
	// ConnMaxIdleTime cierra conexiones ociosas antes de que las corte un
	// intermediario de red.
	ConnMaxIdleTime time.Duration
	// LogSQL habilita el log de sentencias de GORM. Solo para depuración local:
	// las sentencias llevan los parámetros interpolados, incluidos el hash de
	// contraseña y el DNI cifrado, que no deben terminar en un agregador de logs.
	LogSQL bool
}

// Open abre la conexión, ajusta el pool y verifica que la base responda.
func Open(ctx context.Context, cfg Config) (*gorm.DB, error) {
	logLevel := gormlogger.Silent
	if cfg.LogSQL {
		logLevel = gormlogger.Info
	}

	db, err := gorm.Open(postgres.Open(cfg.DSN), &gorm.Config{
		// Traduce los errores del driver a los centinela de GORM, que es lo que
		// permite reconocer una violación de unicidad sin leer SQLSTATE.
		TranslateError: true,
		Logger:         gormlogger.Default.LogMode(logLevel),
		// El servicio genera los UUID y las marcas de tiempo en el dominio, así
		// que no hace falta que GORM las lea de vuelta tras cada INSERT.
		SkipDefaultTransaction: true,
	})
	if err != nil {
		// El DSN lleva la contraseña de la base: nunca se envuelve el error del
		// driver sin más, porque suele incluirlo.
		return nil, fmt.Errorf("postgres: no se pudo abrir la conexión: %w", sanitizeDSN(err, cfg.DSN))
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("postgres: no se pudo obtener el pool: %w", err)
	}

	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	sqlDB.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)

	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("postgres: la base no responde: %w", sanitizeDSN(err, cfg.DSN))
	}

	return db, nil
}

// Close libera el pool subyacente.
func Close(db *gorm.DB) error {
	if db == nil {
		return nil
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// sanitizeDSN reemplaza cualquier aparición literal del DSN en el error, para
// que la contraseña de la base no llegue al log de arranque.
func sanitizeDSN(err error, dsn string) error {
	if err == nil || dsn == "" {
		return err
	}

	msg := err.Error()
	if !strings.Contains(msg, dsn) {
		return err
	}
	return errors.New(strings.ReplaceAll(msg, dsn, "[dsn omitido]"))
}
