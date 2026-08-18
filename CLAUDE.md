# CLAUDE.md — vinculo-vial-identity (Go/Gin/GORM, US-01 Registro)

## Resumen del caso de uso
Identity recibe el payload cifrado (HPKE) del signup, es el único componente capaz de desencriptarlo con su Private Key X25519. Valida formatos estrictamente (Never Trust the Client), incluida la selfie. Con el payload ya válido localmente, verifica la identidad contra RENAPER (dni + trámite + sexo + selfie) antes de dar de alta la cuenta — hoy vía un Mock, sin integración real. Del DNI en claro (solo en memoria, nunca logueado) calcula un Blind Index (HMAC-SHA256) para detectar duplicados sin exponerlo, lo cifra de nuevo (AES-256-GCM) para guardarlo como respaldo, hashea el password con Argon2id y persiste. Responde `201 Created` sin tokens de sesión (login es US-02). Duplicado → `409 Conflict` genérico. Dato mal formado o identidad no verificada → `400 Bad Request`.

## Fuera de alcance
- Emisión de tokens de sesión (JWT) — corresponde a US-02.
- Verificación de email.

## Contrato compartido entre componentes (US-01 — fuente única de verdad, idéntico en los 3 repos)

- **Endpoint**: `POST /api/v1/auth/signup` (síncrono).
- **Payload externo (lo que viaja por HTTP, cifrado)**:
  ```json
  { "ephemeral_public_key": "<base64>", "ciphertext": "<base64>" }
  ```
  Encoding estándar de un mensaje HPKE modo BASE (KEM X25519/HKDF-SHA256, AEAD AES-256-GCM).
- **Payload interno (una vez desencriptado en Identity)**:
  ```json
  { "dni": "12345678", "tramite": "12345678901", "sexo": "F", "selfie": "<base64 JPEG/PNG>", "email": "usuario@ejemplo.com", "password": "Password123!" }
  ```
  ⚠️ Cambio de contrato (agosto 2026): reemplaza a la versión anterior, que llevaba `biometric_verified: true` en lugar de `tramite`/`sexo`/`selfie`. `email` y `password` no cambiaron — siguen siendo las credenciales de la cuenta. **Este cambio hay que replicarlo en Frontend y Gateway** antes de integrar; hasta entonces, Identity y los otros dos repos hablan contratos distintos.
  - `tramite`: número de trámite de la cédula, 11 dígitos.
  - `sexo`: sexo registral, `M`/`F`/`X`.
  - `selfie`: foto para contraste biométrico, JPEG o PNG en base64 (hasta 4 MiB decodificada).
  - Ninguno de los tres tiene columna en `users`: son condiciones para verificar la identidad contra RENAPER, no datos de la persona, y no se persisten — ni siquiera cifrados. Se usan una vez y se limpian de memoria (`defer` + zeroing), tanto si el alta falla como si termina en éxito.
- **Respuestas**: `201 Created` / `400 Bad Request` / `403 Forbidden` / `409 Conflict`.
- **Header `X-App-Attestation`**: JWT de vida corta, firmado HMAC-SHA256 con `APP_ATTESTATION_PSK`, simulando el veredicto de Play Integrity (claims incluyen algo equivalente a `PLAY_RECOGNIZED`, `MEETS_DEVICE_INTEGRITY`). Lo genera la app, lo valida el Gateway. Identity nunca lo revisa.
- **Evento RabbitMQ publicado**: `user.created`, producido por `vinculo-vial-identity`.
  ```json
  { "eventId": "<uuid>", "eventType": "user.created", "timestamp": "<iso8601>", "producer": "vinculo-vial-identity", "actor": null, "payload": { "userId": "<uuid>" } }
  ```
  `actor: null` porque en signup todavía no hay sesión/usuario autenticado actuando.
- **Variables de entorno compartidas conceptualmente** (mismo secreto/par de claves en dos repos, nombre puede variar levemente por convención de cada lenguaje pero el valor debe coincidir):
  - `APP_ATTESTATION_PSK` — compartida entre Frontend (firma el mock JWT) y Gateway (lo valida).
  - `IDENTITY_HPKE_PUBLIC_KEY` (Frontend) ↔ `IDENTITY_HPKE_PRIVATE_KEY` (Identity) — mismo par de claves X25519.
- **Red Docker compartida**: el Gateway alcanza a Identity en `http://vinculo-vial-identity:8080`, sobre la red externa `vinculo-vial` (la crea el compose del Gateway). El nombre no es el del servicio (`identity`) ni el del contenedor (`vinculo-vial-identity-identity-1`) — es un alias explícito que el `docker-compose.yml` de Identity declara al unirse a esa red. Se eligió un alias explícito y no `identity` a secas porque en una red con varios componentes ese nombre es demasiado genérico y colisiona fácil; cada componente se anuncia con su nombre completo. `postgres` no se une a `vinculo-vial`: esa red es para tráfico entre componentes de la plataforma, no para la base de datos de nadie. Esta omisión —el contrato especificaba la URL pero no que Identity debía unirse a la red y anunciar el alias— causó un 503 por DNS en la primera prueba end-to-end (agosto 2026); ver `docker-compose.yml` para el detalle de la configuración.

## Contexto
- Bounded Context estricto: identidad y seguridad. No conoce vehículos ni patentes.
- Entrada: HTTP/REST detrás de `vinculo-vial-gateway` (Kong ya validó App Attestation; Identity no la revalida).
- El payload llega en formato `{ephemeral_public_key, ciphertext}` (HPKE modo BASE); Kong no lo toca.
- Salida asíncrona: publisher hacia RabbitMQ (evento `user.created`, broker externo/global, no se levanta en el `docker-compose.yml` local de este servicio).
- Salida síncrona adicional: consulta a RENAPER para verificar identidad. Sigue dentro del bounded context (identidad y seguridad) — no es un servicio de terceros ajeno al dominio, es la autoridad de la que depende la garantía central de US-01. Hoy no hay integración real, solo un Mock que siempre aprueba (`internal/renaper.Mock`); ver `## Verificación de identidad (RENAPER)`.

## Criptografía — dos mecanismos distintos, no confundir
1. **Transporte (HPKE, RFC 9180)**: desencripta `{ephemeral_public_key, ciphertext}`. Suite: KEM `X25519_HKDF_SHA256`, KDF `HKDF_SHA256`, AEAD `AES256GCM`, modo BASE. Librería: `github.com/cloudflare/circl/hpke`. Usa `IDENTITY_HPKE_PRIVATE_KEY` (mismo par que `IDENTITY_HPKE_PUBLIC_KEY` del lado app).
2. **At-rest (independiente de HPKE)**: el DNI en claro se cifra de nuevo con AES-256-GCM (`crypto/aes`+`crypto/cipher`) para `dni_encrypted`, usando `AES_KEY` — key distinta, no reutilizar el par HPKE.

Adicional: Blind Index vía HMAC-SHA256 (`crypto/hmac`+`crypto/sha256`, secret `HMAC_SECRET`) → `dni_hashed`. Password: Argon2id (`golang.org/x/crypto/argon2`) → `password`.

## Stack
- Go + Gin
- GORM + PostgreSQL
- `github.com/cloudflare/circl/hpke`
- `crypto/aes` + `crypto/cipher` (GCM) — at-rest
- `crypto/hmac` + `crypto/sha256` — Blind Index
- `golang.org/x/crypto/argon2` — password
- RabbitMQ (`amqp091-go`) — publisher `user.created`
- RENAPER — verificación de identidad; hoy solo `internal/renaper.Mock`, sin cliente HTTP real
- Clean Architecture: `domain` / `service` / `repository` / `delivery`

## Estructura del componente
```
/cmd/api/main.go
/internal/domain/              # entidad User, interfaces Repository/EventPublisher/HPKEDecryptor/RenaperService
/internal/service/signup/      # SignUpService: desencriptar -> validar -> RENAPER -> cifrar -> persistir -> publicar
/internal/repository/postgres/ # GORM: modelo User, AutoMigrate, unique constraint -> error de dominio
/internal/delivery/http/       # handler Gin POST /api/v1/auth/signup, DTOs
/internal/delivery/events/     # publisher RabbitMQ (Event Envelope)
/internal/crypto/hpke/         # wrapper sobre circl/hpke
/internal/crypto/symmetric/    # AES-256-GCM at-rest
/internal/crypto/blindindex/   # HMAC-SHA256
/internal/crypto/password/     # Argon2id
/internal/renaper/             # domain.RenaperService: hoy solo el Mock, sin cliente real
/internal/validation/          # regex email, DNI argentino, trámite, sexo, selfie, fortaleza de password
/pkg/config/                   # carga de env vars
```
Regla dura: `domain` no importa `gin`, `gorm`, `circl` ni `amqp`.

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

`AutoMigrate` de GORM en la inicialización del repositorio (MVP). `role`, `reputation_score`, `failed_login_attempts`, `lock_until` quedan fuera del alcance estricto de US-01 (se agregan en US-02/Login) — confirmar en `feature/user-domain-model` si se reservan como columnas nullable ahora o se agregan después vía migración incremental. `tramite`, `sexo` y `selfie` **no** son parte de este modelo ni lo van a ser: no existe (ni se planea) un `tramite_encrypted` o similar — son insumos de la verificación de identidad, no datos que el dominio conserve.

## Endpoint
`POST /api/v1/auth/signup`
- `201 Created`: alta exitosa, sin body de sesión.
- `400 Bad Request`: email/DNI/tramite/sexo/selfie/password no pasan validación tras desencriptar, el mensaje HPKE está mal formado (la clave pública efímera no mide lo que define el KEM, falta una de las dos piezas), o RENAPER no pudo confirmar la identidad. Todos verificables sin filtrar el motivo exacto → mensaje genérico, salvo el detalle por campo de la validación local.
- `409 Conflict`: `dni_hashed` o `email` ya existen (mensaje genérico, anti-enumeración).
- `500`: mensaje bien formado que no desencripta (clave desincronizada o manipulación), RENAPER no pudo consultarse (caído, timeout — no es un veredicto), o error interno inesperado. Nunca filtra detalle criptográfico.

Las dos piezas del mensaje HPKE se aceptan en las cuatro variantes de base64 (estándar/URL-safe, con relleno o sin él): el contrato no precisa cuál y cada plataforma elige distinto.

## Never Trust the Client
- Email: regex de formato estándar.
- DNI: numérico, 7-8 dígitos (DNI argentino).
- Trámite: numérico, exactamente 11 dígitos.
- Sexo: `M`, `F` o `X` (case-insensitive, se normaliza a mayúscula).
- Selfie: base64 bien formado, magic bytes de JPEG o PNG, hasta 4 MiB decodificada (`validation.MaxSelfieBytes`).
- Password: 8-128 caracteres, las cuatro clases (minúscula, mayúscula, dígito, símbolo), sin similitud con el DNI ni el usuario del email. El piso bajó de 12 a 8 en agosto 2026 para alinearse con el mínimo del Frontend — relajación deliberada, no neutra: el registro sigue sin exigir segundo factor (US-02 sigue fuera de alcance), que es la misma condición que en su momento justificó el piso más alto. Revisar si el mínimo del Frontend cambia o si US-02 introduce MFA.

Todo se acumula en un solo `Errors`: un payload con varios campos inválidos a la vez devuelve todos los rechazos juntos, no corta en el primero.

## Verificación de identidad (RENAPER)
Puerto `domain.RenaperService.ValidateIdentity(ctx, dni, tramite, sexo, selfie) (bool, error)`. Corre **después** de la validación local de formato y **antes** de Argon2id: no tiene sentido gastar una consulta a una autoridad externa (potencialmente facturada por llamada) en un payload que ya se iba a rechazar, ni derivar un hash costoso para una identidad que no se confirmó.

- `(true, nil)`: identidad confirmada, el alta continúa.
- `(false, nil)`: RENAPER respondió pero no pudo confirmar — `domain.ErrIdentityNotVerified` → `400`, mensaje genérico (no distingue si falló el trámite, el sexo o la selfie: distinguirlo facilitaría tantear los datos de otra persona).
- `(_, error)`: RENAPER no pudo consultarse — `500`, no implica nada sobre la identidad.

**Hoy solo existe `internal/renaper.Mock`**: simula 500 ms de latencia (`DefaultMockLatency`) y siempre devuelve `true`, sin contactar ningún servicio real. No hay todavía credenciales ni contrato acordado con la API de RENAPER. `cmd/api/main.go` lo cablea incondicionalmente y deja un `WARN` en cada arranque — **no debe llegar a producción así**: aprobaría cualquier identidad sin verificar nada. Cuando exista el cliente real, va a vivir en el mismo paquete `internal/renaper`, detrás del mismo puerto.

## Evento publicado
`user.created` (Event Envelope estándar), `actor: null`, `payload: {"userId": "<uuid>"}`, emitido tras persistencia exitosa.

## Flujo Git (iterativo por feature)
Rama base `dev`. Una rama por feature, `feature/<slug>`, PR + squash merge a `dev` con tests en verde.

### Plan de branches
1. `feature/user-domain-model` — entidad `User`, interfaces `UserRepository`, `EventPublisher`, `HPKEDecryptor`.
2. `feature/hpke-decryption` — wrapper `circl/hpke` (modo BASE, X25519/HKDF-SHA256/AES256GCM), carga de `IDENTITY_HPKE_PRIVATE_KEY`, tests con criptograma de prueba.
3. `feature/blind-index-hmac` — HMAC-SHA256 para `dni_hashed`, tests deterministas.
4. `feature/aes-gcm-at-rest` — cifrado/descifrado AES-256-GCM para `dni_encrypted`, tests round-trip.
5. `feature/argon2id-password` — hash y verificación de password, tests.
6. `feature/validation` — regex email, formato DNI, fortaleza de password, tests con casos válidos/inválidos.
7. `feature/user-repository-gorm` — modelo GORM, `AutoMigrate`, `CreateUser` mapeando unique constraint a `ErrDuplicateUser`.
8. `feature/signup-usecase` — `SignUpService` orquestando el flujo completo, tests con mocks de todas las interfaces.
9. `feature/signup-endpoint` — handler Gin, mapeo de errores de dominio a 400/409/500.
10. `feature/rabbitmq-publisher` — publisher del evento `user.created`, invocado tras persistencia exitosa.
11. `feature/renaper-identity-verification` — puerto `RenaperService` + Mock, payload extendido con `tramite`/`sexo`/`selfie` en reemplazo de `biometric_verified`, `ErrIdentityNotVerified` → 400, `HTTP_MAX_BODY_BYTES` subido para la selfie. Pendiente: replicar el contrato en Frontend y Gateway; integrar el cliente real de RENAPER antes de producción.

## Testing
`service` y paquetes de `crypto`/`validation`: tests unitarios (`testing` + testify opcional). Mocks de `UserRepository` y `EventPublisher`. Sin conexión real a Postgres ni RabbitMQ.

## Docker
- `Dockerfile`: multi-stage. `builder` (`golang:1.22-alpine`), `CGO_ENABLED=0 go build`; etapa final `scratch` con únicamente el binario.
- `docker-compose.yml` local: este servicio + PostgreSQL únicamente. RabbitMQ no se incluye (broker externo/global).
- Redes: `identity` se une a su red por defecto (donde vive `postgres`) **y** a `vinculo-vial`, la red externa compartida de la plataforma, anunciándose ahí con el alias `vinculo-vial-identity` (ver el detalle en `## Contrato compartido entre componentes`). La red externa la crea el compose del Gateway — si Identity se levanta primero, hay que crearla a mano: `docker network create vinculo-vial`. `postgres` no se une a `vinculo-vial`.

## Configuración
`.env.example`: conexión a Postgres, `IDENTITY_HPKE_PRIVATE_KEY`, `AES_KEY`, `HMAC_SECRET`, puerto del servicio, conexión a RabbitMQ (para cuando se integre el publisher). `HTTP_MAX_BODY_BYTES` sube a 10 MiB por defecto desde que el payload incluye una selfie — ver el comentario en `router.DefaultMaxBodyBytes` para el cálculo. RENAPER no tiene variables propias todavía: no hay cliente real que configurar, solo el Mock.

## Comandos
```
go run ./cmd/api
go test ./...
CGO_ENABLED=0 go build -o identity ./cmd/api
docker compose up --build
```