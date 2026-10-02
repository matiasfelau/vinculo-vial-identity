# vinculo-vial-identity

Microservicio de identidad de Vínculo Vial. Bounded context estricto: identidad
y seguridad. No conoce vehículos ni patentes.

Alcance actual: **US-01 / CU-01 — Registro de un vecino** y **US-02 / CU-02 —
Inicio de sesión**.

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
      └─ 8. Persistir                          → 409 si email o DNI ya existen
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
`error` es un fallo de la consulta, no un veredicto, y se clasifica según el
contrato de resiliencia de la plataforma: `domain.ErrUpstreamUnavailable` si
RENAPER no respondió —timeout, conexión rechazada— (→ `503`), o
`domain.ErrUpstreamInvalidResponse` si respondió con un error de su lado o un
cuerpo fuera de contrato (→ `502`).

`RENAPER_TIMEOUT` (1500 ms por defecto) acota esa consulta de punta a punta,
aplicado por `renaper.WithTimeout` alrededor de la implementación activa — no
depende únicamente del contexto de la petición HTTP entrante.

Por fuera de `WithTimeout`, `renaper.WithCircuitBreaker` abre el circuito tras
`RENAPER_BREAKER_FAILURE_THRESHOLD` fallas (`ErrUpstreamUnavailable` o
`ErrUpstreamInvalidResponse`) dentro de `RENAPER_BREAKER_WINDOW` —defaults: 5
fallas en 1 minuto—, y lo mantiene abierto `RENAPER_BREAKER_OPEN_DURATION`
(30 s) antes de admitir una única llamada de prueba. Con el circuito abierto,
`ValidateIdentity` devuelve `ErrUpstreamUnavailable` de inmediato, sin tocar la
red. Un rechazo legítimo —`(false, nil)`— nunca cuenta como falla: es un
resultado válido de la dependencia, no una caída suya.

**Hoy solo existe `internal/renaper.Mock`**: espera ~500 ms y siempre devuelve
`true`, sin contactar ningún servicio externo. No hay todavía credenciales ni
contrato acordado con la API real de RENAPER. `cmd/api/main.go` lo cablea sin
condicionarlo a ninguna variable de entorno y deja un `WARN` en cada arranque
—**no debe usarse en producción**: aprobaría cualquier identidad sin verificar
nada—. Cuando exista el cliente real, va a vivir en el mismo paquete, detrás del
mismo puerto, envuelto por el mismo `WithTimeout` y `WithCircuitBreaker`, sin
que el resto del servicio se entere del cambio.

## Cómo funciona un login

La app envía DNI y contraseña dentro del mismo tipo de mensaje HPKE que el
registro: la contraseña es una credencial reutilizable, y merece la misma
protección de transporte que el DNI del alta —a diferencia del Refresh Token
de un solo uso que rota US-03, que sí viaja en texto plano—.

```
POST /api/v1/auth/signin
      │
      ├─ 1. Descifrar el mensaje (HPKE, RFC 9180)
      ├─ 2. Normalizar el DNI
      ├─ 3. Validar formato (DNI, contraseña       → 400 si algo no pasa
      │      no vacía)
      ├─ 4. Blind Index del DNI (HMAC-SHA256)      → 401 genérico si no
      │      y búsqueda                                hay usuario
      ├─ 5. Verificar la contraseña                → 401 genérico si no
      │      (argon2.Verify)                            coincide
      ├─ 6. Emitir Access Token (JWT RS256, 15m)
      ├─ 7. Emitir Refresh Token (opaco, 30d)
      └─ 8. Persistir la sesión (solo el           → 200
             SHA-256 del refresh token)
```

### Respuestas

| Código | Cuándo |
|---|---|
| `200` | Login exitoso. Devuelve `access_token` (JWT) y `refresh_token` (opaco). |
| `400` | El cuerpo no es interpretable, o los datos descifrados no validan (DNI mal formado, contraseña vacía). |
| `401` | El DNI no corresponde a ningún usuario, o la contraseña no verifica. Respuesta idéntica en los dos casos. |
| `500` | Un mensaje bien formado que no descifra, o falla algo interno. |

El `403` que enumera el contrato compartido lo produce el gateway cuando la App
Attestation no convence; nunca lo emite este servicio.

### El 401 unificado

Un DNI inexistente y una contraseña incorrecta producen la misma respuesta
—mismo status, mismo código, mismo cuerpo— y también el mismo costo en tiempo:
cuando el DNI no corresponde a ningún usuario, el servicio igual ejecuta
`argon2.Verify` contra un hash dummy derivado una única vez al arrancar, para
que la ausencia de una comparación real no se note por el reloj. Distinguir
los dos casos —en la respuesta o en la latencia— convertiría el endpoint en un
oráculo para averiguar qué DNIs están registrados.

El motivo real del rechazo sí queda en el log del servidor, identificado por
`dni_hashed` y nunca por el DNI en claro: es diagnóstico interno, no algo que
el cliente pueda usar para enumerar.

### Tokens de sesión

Mismo esquema en `/signin` que en la rotación de US-03: Access Token JWT
**RS256** (Identity firma, Gateway verifica con la Public Key correspondiente),
TTL 15 minutos, claim `sub` = UUID interno del usuario y ningún otro
dato —ni DNI, ni email, ni el Blind Index—. Refresh Token opaco
(`crypto/rand`), TTL 30 días, persistido en `sessions` solo como su SHA-256.

**Fuera de alcance de este CU**: bloqueo de cuenta por intentos fallidos
(`failed_login_attempts` / `lock_until` no existen; la defensa contra fuerza
bruta masiva es del gateway), recuperación de contraseña, y la rotación del
Refresh Token (`/refresh`, `/logout`), que es US-03.

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
ciclo de rotación. `go run ./cmd/genkeys` genera las cuatro.

## Firma de sesión (JWT)

Un tercer mecanismo, independiente de los dos anteriores: **RS256** sobre un
par RSA de al menos 2048 bits. Identity es el único custodio de la Private Key
(`JWT_PRIVATE_KEY`) y el único componente que firma; el Gateway y el resto de
la plataforma reciben solo la Public Key (`JWT_PUBLIC_KEY`) para verificar. Se
eligió una firma asimétrica en lugar de un secreto compartido (HS256) a
propósito: HS256 obligaría a distribuir el material de firma a cada
verificador, y cualquiera de ellos podría entonces emitir tokens válidos.

El JWT se compone a mano sobre la librería estándar (`internal/token`), sin
sumar una dependencia de terceros: son tres segmentos en base64url y una firma
RSASSA-PKCS1-v1_5 sobre SHA-256, algo que la librería estándar cubre por
completo y que este servicio nunca necesita volver a interpretar —firma, pero
no verifica los tokens que él mismo emite—.

## Router interno (US-04)

Además del router público (`HTTP_PORT`, default `8080`), el servicio levanta
un segundo `*http.Server` en `HTTP_INTERNAL_PORT` (default **`8081`**) con las
rutas `/internal/*` que otros componentes de la plataforma consumen directo
por red interna. Kong nunca enruta hacia acá.

Desde otro contenedor de la red `vinculo-vial`, la llamada completa es:

```bash
curl -X POST http://vinculo-vial-identity:8081/internal/verify-ownership \
  -H "X-Internal-Service-Token: $INTERNAL_SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"owner_id":"<UUID>","dni_enc":"<base64 de enc||ciphertext>"}'
```

Hoy expone una sola ruta: `POST /internal/verify-ownership`, que usa
`vinculo-vial-vehicle` para confirmar si un DNI corresponde al usuario dueño
de `owner_id`. Identity lo descifra, calcula su Blind Index y compara contra
`users`, sin persistir ni loguear nunca el DNI en claro.

`owner_id` viaja en el **body**, no en un header: es el mismo UUID que Kong
le inyectó a Vehicle como `X-User-Id`, reenviado como campo del JSON.

`dni_enc` es un **único blob** `enc || ciphertext` en base64 —los primeros 32
bytes son la clave pública efímera del KEM (X25519), el resto el ciphertext
del AEAD—, **no las dos piezas separadas** que usan `/signup` y `/signin` en
sus campos `ephemeral_public_key` y `ciphertext`. Se aceptan las cuatro
variantes de base64. Desde el ajuste de arquitectura de agosto 2026 lo cifra
Vehicle contra `IDENTITY_HPKE_PUBLIC_KEY`, con el DNI que obtiene de su
integración con la DNRPA; antes reenviaba sin abrir uno producido por la app.

| Código | Cuándo |
|---|---|
| `200` | `{"match": true}` o `{"match": false}`, y nada más. Que el `owner_id` no exista y que el DNI no le corresponda son **indistinguibles**: ambos son `false`, para no convertir el endpoint en un oráculo de verificación de DNI. |
| `400` | Cuerpo no interpretable, `owner_id` que no es UUID, `dni_enc` que no es base64, o criptograma sin forma de mensaje HPKE. |
| `401` | Falta `X-Internal-Service-Token` o es incorrecto. |
| `500` | El criptograma no descifra (clave desincronizada o manipulación), o falla algo interno. |

Que el puerto no esté publicado (ni en Kong ni en el `docker-compose` de este
servicio) es una condición necesaria pero no suficiente: dentro de una red
Docker compartida, cualquier contenedor puede alcanzar igual cualquier
puerto de otro. Por eso toda petición a `/internal/*`, sin excepción, exige
además el secreto `INTERNAL_SERVICE_TOKEN` en la cabecera
`X-Internal-Service-Token`, comparado a tiempo constante. Sin ese secreto (o
con uno incorrecto), el servidor responde `401` — incluso para una ruta que
no existe, para no delatar por el status qué rutas expone.

## Puesta en marcha

```bash
cp .env.example .env
go run ./cmd/genkeys        # copiar las cuatro claves privadas al .env
docker compose up --build
```

`IDENTITY_HPKE_PUBLIC_KEY` y `JWT_PUBLIC_KEY`, que `genkeys` también imprime,
son las dos claves que salen de acá: la primera se embebe en el frontend para
cifrar el payload del registro, la segunda va al Gateway para verificar los
Access Token. Cada par (privada + pública) tiene que salir de la misma
corrida.

Para correr el servicio fuera del contenedor hace falta un Postgres accesible y
`POSTGRES_HOST` apuntando a él:

```bash
go run ./cmd/api
```

## Nomenclatura de infraestructura

Los recursos de Docker siguen la convención de nomenclatura de la plataforma,
que fija nombres deterministas para que la resolución DNS entre microservicios
no dependa del entorno de cada quien. Por defecto Compose deriva el nombre del
proyecto del directorio contenedor y lo antepone a cada recurso, con lo que un
mismo componente cambia de nombre según la máquina donde se haya clonado el
repositorio. Para evitarlo, el proyecto se nombra de forma explícita y cada
recurso fija su `name`.

| Recurso | Nombre | Rol |
|---|---|---|
| Contenedor principal | `vinculo-vial-identity` | Nombre canónico del componente en toda la plataforma. Es el que resuelve por DNS desde el Gateway y desde el resto de los microservicios. |
| Contenedor de la base | `vinculo-vial-identity-db` | Postgres exclusivo de este componente. Se nombra por el servicio que sirve, no por la tecnología. |
| Red compartida | `vinculo-vial` (`external: true`) | Red puente general de la plataforma. La crea el compose del Gateway, así que hay que levantarlo primero (o crearla a mano con `docker network create vinculo-vial`). |
| Red interna | `identity-internal` | Aísla el tráfico contra la base, que no atraviesa la red compartida. |
| Volumen | `vinculo-vial-identity-data` | Datos persistentes de Postgres. |

La base vive únicamente en `identity-internal`: no se asoma a la red compartida,
porque ningún componente ajeno tiene por qué alcanzarla. El microservicio es el
único que pertenece a las dos redes, y en la compartida se anuncia con su nombre
completo y no con `identity` a secas, que en una red con varios componentes es
demasiado genérico y colisiona fácil.

Fijar `container_name` vuelve el nombre único en todo el daemon, no solo dentro
del proyecto: dos instancias simultáneas de este compose colisionan, y `docker
compose up --scale` deja de ser posible. Es el precio deliberado de tener un
nombre DNS estable, y no representa una limitación real para un componente que
se despliega como instancia única por entorno.

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
internal/domain/            entidades User y Session, eventos, errores centinela, puertos
internal/service/signup/    orquestación del alta (US-01)
internal/service/signin/    orquestación del login (US-02)
internal/service/outbox/    worker en background del patrón Transactional Outbox (US-06)
internal/repository/postgres/  persistencia GORM (users, sessions, outbox_events)
internal/delivery/http/     handlers Gin, DTOs, middlewares
internal/delivery/events/   publisher RabbitMQ (+ inerte)
internal/crypto/hpke/       descifrado del transporte
internal/crypto/symmetric/  cifrado at-rest
internal/crypto/blindindex/ Blind Index del DNI
internal/crypto/password/   Argon2id
internal/token/             emisión de Access Token (JWT RS256) y Refresh Token opaco
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

Tabla `sessions`, creada con `AutoMigrate` en la inicialización del
repositorio de sesiones. Requiere que `users` ya exista: declara una clave
foránea hacia ella.

| campo | tipo | notas |
|---|---|---|
| `id` | uuid | PK, generada en el dominio |
| `user_id` | uuid | FK → `users.id`, `ON DELETE CASCADE` |
| `refresh_token_hash` | varchar(64) | UNIQUE — SHA-256 del Refresh Token opaco |
| `is_revoked` | boolean | `false` al crearse; US-03 la revoca |
| `expires_at` | timestamptz | +30 días desde la emisión |
| `created_at` | timestamptz | |

El Refresh Token en claro nunca se persiste: solo existe en la respuesta HTTP
que recibe el cliente. La clave foránea con `ON DELETE CASCADE` se agrega con
SQL crudo después de `AutoMigrate`, de forma idempotente: GORM solo la genera
sola a partir de una asociación Go, y no hace falta cargar esa relación
completa solo para declararla.

Tabla `outbox_events`, creada con `AutoMigrate` en la inicialización de
`OutboxRepository`. No depende de `users` ni de `sessions`: es infraestructura
interna del patrón Transactional Outbox (US-06), no un dato de negocio.

| campo | tipo | notas |
|---|---|---|
| `id` | uuid | PK; mismo valor que `eventId` al publicarse |
| `user_id` | uuid | usuario cuyas sesiones se revocaron |
| `reason` | varchar(64) | `REUSE_DETECTED` |
| `status` | varchar(16) | `pending` / `sent`, indexada junto a `created_at` |
| `attempts` | int | incrementado en cada intento fallido |
| `last_error` | text | nullable; diagnóstico del último fallo |
| `created_at` | timestamptz | usada para ordenar `FetchPending` |
| `sent_at` | timestamptz | nullable; se fija al marcar `sent` |

### Clasificación de errores de la base

`internal/repository/postgres.classifyDBError` traduce cualquier error de
persistencia a `domain.ErrDatabaseUnavailable` cuando es indisponibilidad —no
cuando es un error de la aplicación—, según la sección Postgres del contrato
de resiliencia: deadline de contexto vencido, SQLSTATE `08xxx` (conexión),
`53xxx` (recursos agotados), `57014` (`statement_timeout`) o `57P0x` (apagado
administrativo). Cualquier otro error de la base —una violación de constraint,
ya colapsada en `ErrDuplicateUser`— se propaga sin clasificar. Todos los
repositorios lo aplican, y todos los handlers HTTP lo mapean a `503` antes de
caer en el `500` genérico: `502` no aplica a la base, porque Postgres no tiene
un equivalente al "5xx del upstream" de una dependencia HTTP.

## Eventos publicados

El servicio publica un único evento, `user.sessions.revoked`, con el Event
Envelope estándar de la plataforma. El payload no lleva PII: quien necesite
datos de la persona los pide a este servicio. El alta no publica nada: Core
confirmó que `user.created` no tiene consumidor.

Se publican sobre `vvi.topic.exchange`. Este servicio nunca declara esa
topología: la responsabilidad es de `vinculo-vial-core`, y `NewPublisher`
verifica que el exchange exista con una declaración pasiva, fallando el
arranque si no la encuentra en vez de crearla por su cuenta. Cada publicación
va además con `mandatory=true`, sin excepciones (así lo fija el contrato): si
ningún binding la enruta a una cola, el broker la devuelve y `Publisher` lo
deja en WARN, en lugar de perderse en silencio.

`RABBITMQ_PUBLISH_TIMEOUT` (1500 ms por defecto) acota el intento completo —el
primer publish, la reconexión si hace falta y el reintento— con un único
deadline: el dial de la reconexión usa lo que le quede a ese mismo contexto en
vez de abrir su propia ventana de `RABBITMQ_DIAL_TIMEOUT`, así que un broker
caído no puede multiplicar la latencia del publish más allá del presupuesto
configurado. Lo consume el worker del outbox, fuera del camino de cualquier
request, así que no suma a la latencia de ningún endpoint.

### Presupuesto de latencia de `/auth/signup`

Es el endpoint que más dependencias síncronas encadena: RENAPER y la escritura
en base. El contrato de resiliencia fija el techo del request completo en
5000 ms; `RENAPER_TIMEOUT` y `POSTGRES_STATEMENT_TIMEOUT` valen 1500 ms cada
uno, y queda margen para Argon2id y el resto de la CPU propia (HPKE, Blind
Index, cifrado AES, framework):

```
RENAPER (1500 ms) + escritura en base (1500 ms) + margen (~500 ms) ≈ 3500 ms ≤ 5000 ms
```

El alta no publica ningún evento, así que `RABBITMQ_PUBLISH_TIMEOUT` no entra en
este presupuesto. Los demás endpoints tocan como máximo dos consultas en serie
(`/refresh` normal: `FindByHash` + `RotateSession`) o una sola dependencia
(`/logout`, `/signin`), y quedan cómodos bajo el mismo techo.

### `user.sessions.revoked`

Se publica exclusivamente desde la Defensa Activa de `/refresh` (US-03), al
detectar el reúso de un Refresh Token ya rotado y revocar toda la familia de
sesiones del usuario. Un logout normal de un solo dispositivo no lo publica:
`vinculo-vial-notification` lo consume para dar de baja todos los tokens FCM
del usuario, y hacerlo en cada logout apagaría las notificaciones de sus
demás dispositivos. Acá `actor` sí lleva el UUID del usuario afectado, y
`reason` es un enum acotado pensado para auditoría.

**Patrón Transactional Outbox.** `RefreshService` no publica nada de forma síncrona: `SessionRepository.
RevokeAllByUserID` persiste la revocación y una fila en `outbox_events` en la
misma transacción, y `internal/service/outbox.Worker` la retira y publica en
background (`OUTBOX_WORKER_INTERVAL`, por defecto cada 2 s). Un evento se
marca enviado solo después de que el broker lo confirme; si el publish falla,
o se confirma pero no se puede marcar, queda pendiente para el próximo ciclo,
reutilizando el mismo `eventId` para que un consumidor que deduplique por él
no cuente dos veces un reintento. Resuelve la doble escritura no atómica que
antes existía entre la revocación y el publish: la respuesta de `/refresh` ya
no depende en absoluto de la disponibilidad de RabbitMQ.

```json
{
  "eventId": "…",
  "eventType": "user.sessions.revoked",
  "timestamp": "2026-08-12T15:30:01Z",
  "producer": "vinculo-vial-identity",
  "actor": "6f2a4c1e-9d3b-4f5a-8c7d-1e2f3a4b5c6d",
  "payload": {
    "reason": "REUSE_DETECTED"
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
- **Migraciones versionadas**, en lugar de `AutoMigrate`.
- **Rate limiting** de los endpoints de alta y login. Argon2id reserva 64 MiB
  por derivación concurrente (el login también deriva uno, vía `Verify`, en
  cada intento) y RENAPER agrega una llamada de red externa por alta, así que
  el tope de concurrencia es una decisión de capacidad que hoy queda del lado
  del gateway.
- **Bloqueo de cuenta por intentos fallidos.** El login no lleva
  `failed_login_attempts` ni `lock_until`: un DNI puede probarse contra
  contraseñas indefinidamente sin que la cuenta se bloquee. La defensa contra
  fuerza bruta masiva es hoy responsabilidad exclusiva del rate limiting del
  gateway.
- **Recuperación de contraseña.** No existe ningún flujo para que un vecino
  recupere el acceso si la olvida.
- **Revocación inmediata de Access Tokens.** Son JWT stateless: siguen siendo
  válidos hasta su `exp` (máx. 15 minutos) aunque la sesión se revoque en
  US-03. Requeriría una denylist consultada por el gateway — fuera de alcance
  del MVP.
