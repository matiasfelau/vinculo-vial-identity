# vinculo-vial-identity

Microservicio de identidad de Vínculo Vial. Bounded context estricto: identidad
y seguridad. No conoce vehículos ni patentes.

Alcance actual: **US-01 / CU-01 — Registro de un vecino**.

## Cómo funciona un alta

La app envía email, contraseña, DNI, número de trámite, sexo registral y una
selfie dentro de un mensaje HPKE cifrado con la clave pública de este servicio.
Kong lo reenvía sin tocarlo: identity es el único componente capaz de abrirlo.

> **Cambio de contrato (agosto 2026):** el payload interno reemplazó
> `biometric_verified: true` (un booleano de atestación del dispositivo) por
> `tramite` + `sexo` + `selfie`, que habilitan una verificación de identidad real
> contra RENAPER en lugar de confiar en que el dispositivo dice la verdad. Hay
> que replicar este cambio en Frontend y Gateway antes de integrar.

El cuerpo lleva las dos piezas del mensaje HPKE, cada una en base64, que es el
encoding estándar de HPKE en modo BASE:

```json
{ "ephemeral_public_key": "…", "ciphertext": "…" }
```

```
POST /api/v1/auth/signup
      │
      ├─ 1. Descifrar el mensaje (HPKE, RFC 9180)
      ├─ 2. Normalizar email, DNI y sexo
      ├─ 3. Validar formato y fortaleza        → 400 si algo no pasa
      │      (incluye la selfie: base64 +
      │       magic bytes JPEG/PNG + tamaño)
      ├─ 4. Verificar identidad contra RENAPER → 400 si no se confirma
      │      (dni + tramite + sexo + selfie)      500 si RENAPER no responde
      ├─ 5. Blind Index del DNI (HMAC-SHA256)
      ├─ 6. Cifrar el DNI at-rest (AES-256-GCM, clave distinta)
      ├─ 7. Derivar la contraseña (Argon2id)
      ├─ 8. Persistir                          → 409 si email o DNI ya existen
      └─ 9. Publicar user.created              → no compromete el alta si falla
                                                → 201
```

El DNI, el trámite, el sexo, la selfie y la contraseña en claro existen
únicamente en memoria durante estos pasos, en buffers que se limpian al salir
—tanto si el alta falla como si termina en éxito— y nunca se loguean.

La verificación de identidad corre después de la validación local y antes de
Argon2id, a propósito: no tiene sentido pagar una consulta a una autoridad
externa por un payload que ya se iba a rechazar, ni derivar un hash costoso para
una identidad que no se confirmó.

### Respuestas

| Código | Cuándo |
|---|---|
| `201` | Alta exitosa. Devuelve el id opaco del usuario, sin tokens: la sesión es US-02. |
| `400` | El cuerpo no es interpretable, el mensaje cifrado no tiene forma de mensaje HPKE, los datos descifrados no validan, o RENAPER no pudo confirmar la identidad. Detalla los campos rechazados de la validación local, nunca los valores; el rechazo de RENAPER es siempre genérico. |
| `409` | El email o el DNI ya existen. Mensaje genérico deliberado: distinguirlos permitiría enumerar usuarios. |
| `500` | Un mensaje bien formado que no descifra, RENAPER no pudo consultarse (caído, timeout — no es un veredicto sobre la identidad), o un fallo interno. Sin detalle criptográfico en el cuerpo. |

La frontera entre `400` y `500` en el descifrado es deliberada. Que la clave
pública efímera no mida lo que el KEM define se verifica sin tocar la clave
privada del servicio: es un cliente mal implementado y se le dice con un `400`,
en vez de mandarlo a buscar una falla del servidor que no existe. Que un mensaje
bien formado no abra es indistinguible entre clave desincronizada y manipulación,
así que sale siempre igual y sin detalle. La misma lógica separa "RENAPER dijo
que no" (400, dato del cliente) de "no se pudo preguntarle a RENAPER" (500,
fallo de la dependencia).

Las dos piezas del mensaje HPKE se aceptan en cualquiera de las cuatro variantes
de base64 —alfabeto estándar o URL-safe, con relleno o sin él—, porque el
contrato dice "base64" sin precisar cuál y cada plataforma elige distinto.

El `403` que enumera el contrato compartido lo produce el gateway cuando la App
Attestation no convence; nunca lo emite este servicio.

## Verificación de identidad (RENAPER)

Antes de dar de alta la cuenta, el servicio confirma que `dni` + `tramite` +
`sexo` + `selfie` corresponden a una persona real, a través del puerto
`domain.RenaperService`:

```go
ValidateIdentity(ctx, dni, tramite, sexo, selfie []byte) (bool, error)
```

`(true, nil)` confirma la identidad; `(false, nil)` es un rechazo genuino de
RENAPER (→ `400`, sin decir si falló el trámite, el sexo o la selfie); un
`error` es un fallo de la consulta, no un veredicto (→ `500`).

**Hoy solo existe `internal/renaper.Mock`**: espera ~500 ms y siempre devuelve
`true`, sin contactar ningún servicio externo. No hay todavía credenciales ni
contrato acordado con la API real de RENAPER. `cmd/api/main.go` lo cablea sin
condicionarlo a ninguna variable de entorno y deja un `WARN` en cada arranque
—**no debe usarse en producción**: aprobaría cualquier identidad sin verificar
nada—. Cuando exista el cliente real, va a vivir en el mismo paquete, detrás del
mismo puerto, sin que el resto del servicio se entere del cambio.

## Los dos mecanismos criptográficos

No confundirlos: son independientes y usan claves distintas a propósito.

| | Transporte | At-rest |
|---|---|---|
| Qué protege | El payload entre el dispositivo y el servicio | El DNI dentro de la base |
| Algoritmo | HPKE — X25519_HKDF_SHA256 / HKDF_SHA256 / AES256GCM | AES-256-GCM |
| Clave | `IDENTITY_HPKE_PRIVATE_KEY` | `AES_KEY` |

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

`IDENTITY_HPKE_PUBLIC_KEY`, que `genkeys` también imprime, es la única clave que
sale de acá: se embebe en el frontend para cifrar el payload del registro. Los
dos valores tienen que salir de la misma corrida.

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
internal/renaper/           verificación de identidad (hoy solo Mock)
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

`tramite`, `sexo` y `selfie` **no** están en esta tabla ni lo van a estar: son
insumos de la verificación contra RENAPER, no datos que el dominio conserve. Se
usan una vez, en memoria, y se limpian con `defer` antes de que la función
vuelva, sea cual sea el resultado del alta.

## Evento publicado

`user.created`, con el Event Envelope estándar de la plataforma. El payload no
lleva PII: quien necesite datos de la persona los pide a este servicio.

`actor` va en `null` porque en el signup todavía no hay sesión ni usuario
autenticado actuando: el usuario se está creando en esa misma petición.

```json
{
  "eventId": "…",
  "eventType": "user.created",
  "timestamp": "2026-08-12T15:30:01Z",
  "producer": "vinculo-vial-identity",
  "actor": null,
  "payload": {
    "userId": "6f2a4c1e-9d3b-4f5a-8c7d-1e2f3a4b5c6d"
  }
}
```

## Deuda técnica conocida

- **Cliente real de RENAPER.** `internal/renaper.Mock` aprueba cualquier
  identidad sin verificar nada: es imprescindible para desarrollar y para tests,
  pero **no debe llegar a producción**. No hay todavía credenciales ni contrato
  acordado con la API real.
- **Contrato desincronizado con Frontend y Gateway.** El payload interno
  reemplazó `biometric_verified` por `tramite`/`sexo`/`selfie`; hasta que los
  otros dos repos repliquen el cambio, no son interoperables entre sí.
- **Outbox transaccional.** Hoy, si RabbitMQ está caído, el alta se completa y
  el evento se pierde con un registro de error. Es la decisión correcta para no
  romper el registro por un problema del broker, pero hay que resolverlo antes
  de que algún consumidor dependa del evento para algo crítico.
- **Migraciones versionadas**, en lugar de `AutoMigrate`.
- **Rate limiting** del endpoint de alta. Argon2id reserva 64 MiB por derivación
  concurrente y RENAPER agrega una llamada de red externa por alta, así que el
  tope de concurrencia es una decisión de capacidad que hoy queda del lado del
  gateway.
