# vinculo-vial-identity

Microservicio de identidad de Vínculo Vial. Bounded context estricto: identidad
y seguridad. No conoce vehículos ni patentes.

Alcance actual: **US-01 / CU-01 — Registro de un vecino**.

## Cómo funciona un alta

La app envía email, contraseña y DNI dentro de un criptograma HPKE cifrado con
la clave pública de este servicio. Kong lo reenvía sin tocarlo: identity es el
único componente capaz de abrirlo.

```
POST /api/v1/auth/signup
      │
      ├─ 1. Descifrar el criptograma (HPKE, RFC 9180)
      ├─ 2. Normalizar email y DNI
      ├─ 3. Validar formato y fortaleza      → 400 si algo no pasa
      ├─ 4. Blind Index del DNI (HMAC-SHA256)
      ├─ 5. Cifrar el DNI at-rest (AES-256-GCM, clave distinta)
      ├─ 6. Derivar la contraseña (Argon2id)
      ├─ 7. Persistir                        → 409 si email o DNI ya existen
      └─ 8. Publicar user.registered         → no compromete el alta si falla
                                             → 201
```

El DNI en claro existe únicamente en memoria durante el paso 1 al 6, en buffers
que se limpian al salir, y nunca se loguea.

### Respuestas

| Código | Cuándo |
|---|---|
| `201` | Alta exitosa. Devuelve el id opaco del usuario, sin tokens: la sesión es US-02. |
| `400` | El cuerpo no es interpretable, o los datos descifrados no validan. Detalla los campos rechazados, nunca los valores. |
| `409` | El email o el DNI ya existen. Mensaje genérico deliberado: distinguirlos permitiría enumerar usuarios. |
| `500` | El criptograma no descifra, o un fallo interno. Sin detalle criptográfico en el cuerpo. |

## Los dos mecanismos criptográficos

No confundirlos: son independientes y usan claves distintas a propósito.

| | Transporte | At-rest |
|---|---|---|
| Qué protege | El payload entre el dispositivo y el servicio | El DNI dentro de la base |
| Algoritmo | HPKE — X25519_HKDF_SHA256 / HKDF_SHA256 / AES256GCM | AES-256-GCM |
| Clave | `HPKE_PRIVATE_KEY` | `AES_KEY` |

A eso se suman el Blind Index del DNI (HMAC-SHA256, `HMAC_SECRET`) que habilita
la detección de duplicados sin exponer el dato, y Argon2id para la contraseña.

Comprometer una clave no debe comprometer las otras, y cada una tiene su propio
ciclo de rotación. `go run ./cmd/genkeys` genera las tres.

## Puesta en marcha

```bash
cp .env.example .env
go run ./cmd/genkeys        # copiar las tres claves privadas al .env
docker compose up --build
```

`HPKE_PUBLIC_KEY`, que `genkeys` también imprime, es la única clave que sale de
acá: se embebe en la app Android para cifrar el payload del registro.

Para correr el servicio fuera del contenedor hace falta un Postgres accesible y
`POSTGRES_HOST` apuntando a él:

```bash
go run ./cmd/api
```

## Comandos

```bash
go run ./cmd/api                              # levantar el servicio
go run ./cmd/genkeys                          # generar el material criptográfico
go test ./...                                 # tests unitarios
go test -cover ./...                          # con cobertura
go vet ./...                                  # análisis estático
CGO_ENABLED=0 go build -o identity ./cmd/api  # binario estático
docker compose up --build                     # entorno local completo
```

Los tests son unitarios y no necesitan Postgres ni RabbitMQ: todo lo externo
está detrás de interfaces de `domain` y se ejercita con dobles.

## Arquitectura

Clean Architecture. Los puertos se declaran en `domain` y las implementaciones
viven en los anillos externos; `cmd/api/main.go` es el único lugar donde se
conocen todas las implementaciones concretas.

```
cmd/api/                    binario del servicio, resolución de dependencias
cmd/genkeys/                generación del material criptográfico
internal/domain/            entidad User, eventos, errores centinela, puertos
internal/service/signup/    orquestación del caso de uso
internal/repository/postgres/  persistencia GORM
internal/delivery/http/     handler Gin, DTOs, middlewares
internal/delivery/events/   publisher RabbitMQ (+ inerte)
internal/crypto/hpke/       descifrado del transporte
internal/crypto/symmetric/  cifrado at-rest
internal/crypto/blindindex/ Blind Index del DNI
internal/crypto/password/   Argon2id
internal/validation/        Never Trust the Client
pkg/config/                 carga y validación de variables de entorno
```

**Regla dura:** `domain` no importa `gin`, `gorm`, `circl` ni `amqp`. La capa de
servicio depende solo de interfaces de `domain`.

## Modelo de datos

Tabla `users`, creada con `AutoMigrate` en la inicialización del repositorio.

| campo | tipo | notas |
|---|---|---|
| `id` | uuid | PK, generada en el dominio |
| `email` | varchar(254) | UNIQUE, normalizado a minúscula |
| `password` | varchar(255) | hash Argon2id en formato PHC |
| `dni_hashed` | varchar(64) | UNIQUE — Blind Index HMAC-SHA256 |
| `dni_encrypted` | text | AES-256-GCM |
| `account_status` | varchar(32) | `ACTIVE` |
| `created_at` / `updated_at` | timestamptz | |

`AutoMigrate` es una decisión de MVP: solo agrega columnas e índices. Antes de
tener datos reales en producción hay que pasar a una herramienta con versionado.

## Evento publicado

`user.registered`, con el Event Envelope estándar de la plataforma. El payload
no lleva PII: quien necesite datos de la persona los pide a este servicio.

```json
{
  "eventId": "…",
  "eventType": "user.registered",
  "timestamp": "2026-08-12T15:30:01Z",
  "producer": "vinculo-vial-identity",
  "actor": "6f2a4c1e-9d3b-4f5a-8c7d-1e2f3a4b5c6d",
  "payload": {
    "userId": "6f2a4c1e-9d3b-4f5a-8c7d-1e2f3a4b5c6d",
    "accountStatus": "ACTIVE",
    "registeredAt": "2026-08-12T15:30:00Z"
  }
}
```

## Deuda técnica conocida

- **Outbox transaccional.** Hoy, si RabbitMQ está caído, el alta se completa y
  el evento se pierde con un registro de error. Es la decisión correcta para no
  romper el registro por un problema del broker, pero hay que resolverlo antes
  de que algún consumidor dependa del evento para algo crítico.
- **Migraciones versionadas**, en lugar de `AutoMigrate`.
- **Rate limiting** del endpoint de alta. Argon2id reserva 64 MiB por derivación
  concurrente, así que el tope de concurrencia es una decisión de capacidad que
  hoy queda del lado del gateway.
