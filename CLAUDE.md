# CLAUDE.md — vinculo-vial-identity (Go/Gin/GORM, US-01 Registro)

## Resumen del caso de uso (CU-01 / US-01)
Un vecino se registra: la app envía email, password y DNI dentro de un criptograma HPKE cifrado con la Public Key de este servicio. Identity es el único componente capaz de desencriptarlo. A partir del DNI en claro (solo en memoria, nunca logueado) calcula un Blind Index (HMAC-SHA256) para poder buscar/evitar duplicados sin exponer el DNI, cifra el DNI simétricamente para guardarlo como respaldo/auditoría, hashea el password con Argon2id, valida formatos estrictamente (Never Trust the Client) y persiste. Responde `201 Created` sin emitir tokens (login es US-02). Duplicado de DNI o email → `409 Conflict` genérico. Dato mal formado → `400 Bad Request`.

## Contexto
- Bounded Context estricto: identidad y seguridad. No conoce vehículos ni patentes.
- Entrada: HTTP/REST exclusivamente detrás de `vinculo-vial-gateway` (Kong ya valida App Attestation antes de que la petición llegue acá; este servicio no revalida atestación).
- El payload llega cifrado end-to-end desde el dispositivo (Kong no lo toca).
- Salida asíncrona: publisher hacia RabbitMQ (evento `user.registered`, Event Envelope estándar de la plataforma), broker externo/global — no se levanta en el `docker-compose.yml` local de este servicio.

## Criptografía — dos mecanismos distintos, no confundir
1. **Transporte (HPKE, RFC 9180)**: desencripta el payload que llega desde la app. Suite: KEM `X25519_HKDF_SHA256`, KDF `HKDF_SHA256`, AEAD `AES256GCM`. Librería: `github.com/cloudflare/circl/hpke`. Compatible con el criptograma que genera Tink del lado Android. Usa la Private Key HPKE del servicio (`HPKE_PRIVATE_KEY`).
2. **At-rest (independiente de HPKE)**: una vez el DNI está en claro en memoria, se cifra de nuevo con AES-256-GCM (`crypto/aes` + `crypto/cipher`, modo GCM) para persistirlo en `dni_encrypted`, usando una key distinta (`AES_KEY`) — no reutilizar la key/par de HPKE para esto.

Adicional: Blind Index del DNI vía HMAC-SHA256 (`crypto/hmac` + `crypto/sha256`, secret `HMAC_SECRET`) → `dni_hashed`. Password: Argon2id (`golang.org/x/crypto/argon2`) → `password`.

## Stack
- Go + Gin
- GORM + PostgreSQL
- `github.com/cloudflare/circl/hpke` (desencriptación del payload)
- `crypto/aes` + `crypto/cipher` (GCM) — cifrado at-rest del DNI
- `crypto/hmac` + `crypto/sha256` — Blind Index
- `golang.org/x/crypto/argon2` — hashing de password
- RabbitMQ (amqp091-go) — publisher del evento `user.registered`
- Clean Architecture: `domain` / `service` / `repository` / `delivery`

## Arquitectura del componente
```
/cmd/api/main.go
/internal/domain/              # entidad User, interfaces Repository/EventPublisher/HPKEDecryptor
/internal/service/signup/      # SignUpService: orquesta desencriptar -> validar -> cifrar -> persistir -> publicar
/internal/repository/postgres/ # GORM: modelo User, AutoMigrate, mapeo de unique constraint -> error de dominio
/internal/delivery/http/       # handler Gin POST /api/v1/auth/signup, DTOs de entrada/salida
/internal/delivery/events/     # publisher RabbitMQ (Event Envelope)
/internal/crypto/hpke/         # wrapper sobre circl/hpke
/internal/crypto/symmetric/    # AES-256-GCM at-rest
/internal/crypto/blindindex/   # HMAC-SHA256
/internal/crypto/password/     # Argon2id
/internal/validation/          # regex email, DNI argentino, fortaleza de password
/pkg/config/                   # carga de env vars
```

Regla dura: `domain` no importa `gin`, `gorm`, `circl` ni `amqp`. `service` depende de interfaces de `domain`.

## Modelo de datos (tabla `users`, GORM)
| campo | tipo | constraint |
|---|---|---|
| id | UUID | PK |
| dni_encrypted | text | AES-256-GCM |
| dni_hashed | varchar | UNIQUE, indexed (Blind Index) |
| password | varchar | Argon2id |
| email | varchar | UNIQUE |
| account_status | varchar | default `ACTIVE` |
| created_at / updated_at | timestamptz | |

`AutoMigrate` de GORM en la inicialización del repositorio (MVP, sin herramienta de migración externa). `role`, `reputation_score`, `failed_login_attempts`, `lock_until` quedan fuera del alcance estricto de US-01 (se agregan cuando se aborde US-02/Login), pero el struct puede reservarlos como columnas nullable si simplifica el modelo único de `users` a futuro — decisión a confirmar en `feature/user-domain-model`.

## Endpoint
`POST /api/v1/auth/signup`
- Body: criptograma HPKE (bytes/base64).
- `201 Created`: alta exitosa, sin body de sesión.
- `400 Bad Request`: email/DNI/password no pasan validación tras desencriptar.
- `409 Conflict`: `dni_hashed` o `email` ya existen (mensaje genérico, anti-enumeración).
- `500`: fallo de desencriptación HPKE o error interno no esperado (no debe filtrar detalle criptográfico en el body).

## Never Trust the Client — validaciones antes de tocar la BD
- Email: regex estándar de formato.
- DNI: numérico, longitud válida de DNI argentino (7-8 dígitos).
- Password: reglas de fortaleza mínimas (longitud, combinación de caracteres) — definir umbral exacto en `feature/validation`.

## Evento publicado
- `user.registered` — Event Envelope estándar (`eventId, eventType, timestamp, producer, actor, payload`). `actor` = `user_hash` (no el `dni_hashed`, definir mapeo exacto en `feature/rabbitmq-publisher` según si ya existe un `X-User-Hash` en este punto o se genera acá).

## Flujo Git (iterativo por feature)
- Rama base: `dev`. Una rama por feature, `feature/<slug>`, PR + squash merge a `dev` al cerrar checklist, sin tests rotos.

### Plan de branches (orden sugerido)

1. `feature/user-domain-model` — entidad `User` en `domain`, interfaces `UserRepository`, `EventPublisher`, `HPKEDecryptor`.
2. `feature/hpke-decryption` — wrapper `circl/hpke` (KEM X25519/HKDF-SHA256, AEAD AES256GCM), carga de Private Key desde env, tests con vector conocido/criptograma de prueba.
3. `feature/blind-index-hmac` — función HMAC-SHA256 para `dni_hashed`, tests deterministas.
4. `feature/aes-gcm-at-rest` — cifrado/descifrado AES-256-GCM para `dni_encrypted`, tests round-trip.
5. `feature/argon2id-password` — hash y verificación de password, tests.
6. `feature/validation` — regex email, formato DNI argentino, reglas de fortaleza de password, tests con casos válidos/inválidos.
7. `feature/user-repository-gorm` — modelo GORM, `AutoMigrate`, `CreateUser` mapeando violación de unique constraint a error de dominio (`ErrDuplicateUser`).
8. `feature/signup-usecase` — `SignUpService` orquestando: desencriptar → validar → blind index → cifrar DNI → hash password → persistir. Tests con mocks de todas las interfaces.
9. `feature/signup-endpoint` — handler Gin `POST /api/v1/auth/signup`, mapeo de errores de dominio a 400/409/500.
10. `feature/rabbitmq-publisher` — publisher del evento `user.registered` (Event Envelope), invocado tras persistencia exitosa.

Cada branch se abre desde `dev` actualizado y se rebasea antes del PR.

## Testing
- `service` y todos los paquetes de `crypto`/`validation`: tests unitarios con `testing` (+ testify opcional).
- Mocks de `UserRepository` y `EventPublisher` (interfaces en `domain`). Sin conexión real a Postgres ni RabbitMQ en tests unitarios.

## Docker
- `Dockerfile`: multi-stage. Etapa `builder` (`golang:1.22-alpine`), `CGO_ENABLED=0 go build`; etapa final `scratch` con únicamente el binario.
- `docker-compose.yml` local: este microservicio + PostgreSQL únicamente. RabbitMQ no se incluye (broker externo/global).

## Configuración
`.env.example` con: conexión a Postgres, `HPKE_PRIVATE_KEY`, `AES_KEY`, `HMAC_SECRET`, puerto del servicio, config de conexión a RabbitMQ (para cuando se integre el publisher, aunque no corra localmente en este compose).

## Comandos
```
go run ./cmd/api
go test ./...
CGO_ENABLED=0 go build -o identity ./cmd/api
docker compose up --build
```