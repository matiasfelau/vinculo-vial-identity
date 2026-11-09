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

Hoy expone dos rutas. La primera, `POST /internal/verify-ownership`, la usa
`vinculo-vial-vehicle` para confirmar si un DNI corresponde al usuario dueño
de `owner_id`. Identity lo descifra, calcula su Blind Index y compara contra
`users`, sin persistir ni loguear nunca el DNI en claro. La segunda,
`POST /internal/audit/dni`, la usa `vinculo-vial-alert` para obtener el DNI del
emisor sellado hacia el Audit Service: ver
[Sellado del DNI para Audit](#sellado-del-dni-para-audit-us-11).

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

## Baja de cuenta (US-11)

El usuario puede eliminar su cuenta desde la app, confirmándola con su
contraseña. La baja borra todo lo operativo y **Identity no conserva ningún
registro de retención**: el de las alertas que llegaron a un destinatario lo
lleva el Audit Service. Lo único que sobrevive en Identity es la sanción de una
cuenta penalizada, en una tabla operativa (`sanction_carryovers`), para que el
mismo DNI no pueda borrarla dándose de baja y registrándose de nuevo.

```
App       Configuración → Eliminar cuenta → pantalla informativa → contraseña
          DELETE /api/v1/users/me { "password": "…" }
Kong      jwt → token-offloading (X-User-Id) → rate-limiting (3/min, 10/h)
Identity  verifica la contraseña (Argon2) → 401 INVALID_PASSWORD si no coincide
          TX:
            sanction_carryovers ← dni_hmac, account_status, reputation_score,
                                  report_count, created_at, expires_at
                                  (solo si estaba penalizada)
            borra las sesiones · borra la fila de users
            outbox ← user.sessions.revoked + user.deleted   (actor = user_id)
          → 204
```

### Endpoint

`DELETE /api/v1/users/me`, detrás de Kong con `jwt` y `token-offloading`. Kong
inyecta `X-User-Id`, que este servicio toma como el usuario autenticado: la baja
actúa siempre sobre ese usuario, sin ningún identificador en la ruta ni en el
body, así que no hay forma de pedir la baja de otra cuenta. Como pasa con el
resto de las rutas públicas, el servicio confía en que solo Kong lo alcanza
(puerto sin publicar fuera de la red de la plataforma); una petición sin un
`X-User-Id` válido se rechaza.

Body: `{ "password": "<string>" }`, JSON plano (la reautenticación sobre una
sesión ya validada no lleva el wrapper HPKE; la confidencialidad la aporta
HTTPS). Máximo 4 KiB y, como en el alta, hasta 128 caracteres.

| Status | `code` | Caso | Emite |
|---|---|---|---|
| 204 | — | Baja realizada. También si el usuario ya no existe: es idempotente y no revela nada | Identity |
| 400 | `INVALID_BODY` | Body ausente, ilegible o sin `password` | Identity |
| 401 | — | JWT ausente o inválido | Kong |
| 401 | `INVALID_PASSWORD` | La contraseña no coincide | Identity |
| 401 | `UNAUTHORIZED` | Falta `X-User-Id` o no es un UUID: la petición no pasó por Kong | Identity |
| 429 | — | Rate limit | Kong |
| 503 | `DEPENDENCY_UNAVAILABLE` | Base caída o en timeout; header `Retry-After` | Identity |

Los errores usan el formato vigente (`{ "error": "…", "code": "…" }`). Un fallo
inesperado es un `500` genérico: el detalle queda en el log, nunca en la
respuesta. La baja no hace ninguna llamada síncrona saliente: lo único externo
es la base, acotada por `POSTGRES_STATEMENT_TIMEOUT`.

`UNAUTHORIZED` no está en la tabla del contrato de US-11: es el caso de una
petición que se saltó el gateway, que el contrato asigna a Kong. Se agrega para
que el servicio falle cerrado en vez de actuar sobre un usuario sin autenticar.

### Qué se borra y qué se conserva

| Se borra | Se conserva |
|---|---|
| La fila de `users` (email, contraseña, `dni_hashed`, `dni_encrypted`, estado y reputación) | Solo si la cuenta estaba penalizada: su sanción en `sanction_carryovers`, hasta `SANCTION_CARRYOVER_DAYS` |
| Las `sessions` del usuario | |

Todo el resto lo borran los demás servicios al consumir `user.sessions.revoked`
(Notification: device tokens) y `user.deleted` (Alert y Vehicle). La baja es una
única transacción: la sanción, el borrado de sesiones y de usuario, y los dos
eventos del outbox se confirman juntos o no se confirma ninguno. La fila del
usuario se lee con `SELECT … FOR UPDATE` dentro de esa transacción, así que un
reporte o una penalización que llega a la vez espera, y la sanción que se deja
nunca es más vieja que la fila que se borra.

### Eventos

`user.sessions.revoked` (con `reason: ACCOUNT_DELETED`) y `user.deleted` salen
por el outbox con el usuario como `actor`. Ver [Eventos publicados](#eventos-publicados).

### `sanction_carryovers`

Tabla operativa de Identity, en el esquema por defecto, creada con `AutoMigrate`
como el resto. A diferencia del registro de retención que reemplazó, no es un
dato aislado ni cifrado: no lleva el DNI ni el `user_id`, solo el Blind Index con
que se reconoce al mismo DNI.

| Columna | Tipo | Nota |
|---|---|---|
| `dni_hmac` | varchar(64) PK | El mismo Blind Index que `users.dni_hashed` |
| `account_status`, `reputation_score`, `report_count` | iguales que en `users` | La sanción que se hereda |
| `created_at` | timestamptz not null | La fecha de la baja |
| `expires_at` | timestamptz not null, indexada | `deleted_at + SANCTION_CARRYOVER_DAYS` |

"Penalizada" es `account_status = UNDER_REVIEW`, `report_count > 0` o
`reputation_score < 0`. La baja de una cuenta penalizada hace un `upsert` por
`dni_hmac` (una fila vencida que el barrido todavía no borró, de una cuenta
anterior con el mismo DNI, se pisa); la de una cuenta sin penalizaciones no
escribe nada.

Reglas:

- **Ningún endpoint lee la tabla.** Solo la tocan la baja, el signup y el sweeper.
- **Nunca se loguean** el DNI, la contraseña ni `dni_hmac`.

DDL equivalente a lo que crea `AutoMigrate`, para un entorno donde el rol de la
aplicación no tiene permisos de DDL y el DBA crea la tabla con su propio rol:

```sql
CREATE TABLE sanction_carryovers (
    dni_hmac         varchar(64) PRIMARY KEY,
    account_status   varchar(32) NOT NULL,
    reputation_score integer     NOT NULL,
    report_count     integer     NOT NULL,
    created_at       timestamptz NOT NULL,
    expires_at       timestamptz NOT NULL
);
CREATE INDEX idx_sanction_carryovers_expires_at ON sanction_carryovers (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON sanction_carryovers TO identity_app;  -- rol de conexión del servicio
```

Con la tabla ya creada, el arranque no ejecuta DDL y alcanza con esos permisos
(lo comprueba una prueba de integración con un rol sin `CREATE`). El rol del
servicio usa una única conexión: la baja escribe esta tabla y borra `users` en la
misma transacción.

### Herencia de la sanción al registrarse otra vez

Si el mismo DNI se vuelve a registrar y hay una fila vigente (`expires_at > now`)
con su `dni_hmac`, la cuenta nueva **hereda** `account_status`,
`reputation_score` y `report_count`, y la fila se borra. Todo ocurre en la misma
transacción que el `INSERT` del usuario (`UserRepository.Create`), con un único
`DELETE … RETURNING`:

- Un alta que falla (email repetido, base caída, outbox caído) no consume la
  sanción: el reclamo se deshace con el resto.
- La sanción no se hereda dos veces: tras el primer alta la fila ya no existe.
  Dos altas simultáneas con el mismo DNI se serializan en el bloqueo de la fila
  y en el índice único de `users.dni_hashed`.
- Si la cuenta queda `UNDER_REVIEW`, se encola `user.status.changed` con
  `reason: INHERITED_ON_SIGNUP` en la misma transacción. Con una sanción que no
  llega a revisión (solo reputación o reportes) se hereda sin publicar nada.
- Una fila vencida pero todavía no barrida no se hereda.

### Sweeper

`internal/service/sanction` borra las filas con `expires_at <= now`: una vez al
arrancar y después cada `SANCTION_CARRYOVER_SWEEP_INTERVAL`, de a lotes de
`SANCTION_CARRYOVER_SWEEP_BATCH_SIZE`. Es el primer proceso periódico propio del
servicio. Es seguro con varias réplicas (`FOR UPDATE SKIP LOCKED` sobre un CTE
materializado: se reparten el trabajo y nunca borran más que el lote) y se
apaga ordenadamente: al recibir `SIGTERM` el barrido en curso se corta y el
proceso espera a que termine antes de cerrar la base. Un fallo se loguea en
ERROR y el próximo ciclo reintenta. Solo loguea cuántas filas borró.

### Migración desde el registro de retención anterior

Antes del Audit Service, la baja guardaba un registro de retención en un esquema
aparte (`legal_hold`, tabla `user_holds`), con el DNI sellado hacia el
responsable legal. Ese registro ya no existe: su función la cumple Audit, y la
sanción pasó a `sanction_carryovers`. El código y las CLI (`legalhold-keygen`,
`legalhold-open`) se retiraron.

En el arranque, `ensureSanctionCarryovers` migra una base que todavía tenga ese
esquema, en una sola transacción bajo un advisory lock (varias réplicas pueden
arrancar a la vez):

1. Copia a `sanction_carryovers` las filas de `user_holds` con `dni_hmac` no nulo
   y `destroy_at > now`, con `expires_at = destroy_at` (el plazo que ya corría no
   cambia) y `created_at = deleted_at`. Si ya hay una fila para ese DNI, no la
   pisa.
2. Borra el esquema con `DROP SCHEMA legal_hold CASCADE`.

Si el esquema no existe no hace nada. Si la copia falla, el esquema queda intacto
y el siguiente arranque reintenta.

`DROP SCHEMA` exige ser el dueño del esquema. Si en el entorno pertenece a otro
rol (lo que recomendaba la versión anterior), el DBA aplica la migración antes de
desplegar, con ese rol, y entonces el servicio ya no encuentra el esquema:

```sql
BEGIN;
INSERT INTO sanction_carryovers (dni_hmac, account_status, reputation_score, report_count, created_at, expires_at)
SELECT dni_hmac, account_status, reputation_score, report_count, deleted_at, destroy_at
FROM legal_hold.user_holds
WHERE dni_hmac IS NOT NULL AND account_status IS NOT NULL
  AND reputation_score IS NOT NULL AND report_count IS NOT NULL
  AND destroy_at > now()
ON CONFLICT (dni_hmac) DO NOTHING;
DROP SCHEMA legal_hold CASCADE;
COMMIT;
```

Los `dni_sealed` del esquema anterior se pierden con el `DROP`, y es lo previsto:
el registro de lo que se envió desde ahora lo lleva Audit, que no depende de la
baja. El rol `legal_hold_owner` y sus `GRANT`, si se crearon, se retiran con
`DROP ROLE`.

### Variables

| Variable | Valor | Nota |
|---|---|---|
| `SANCTION_CARRYOVER_DAYS` | `1095` | 3 años (art. 2561 del CCyC y art. 62 del CP) |
| `SANCTION_CARRYOVER_SWEEP_INTERVAL` | `1h` | Cada cuánto corre el sweeper |
| `SANCTION_CARRYOVER_SWEEP_BATCH_SIZE` | `500` | Filas por sentencia de borrado |

Para ver el barrido funcionando en local, bajar `SANCTION_CARRYOVER_SWEEP_INTERVAL`
y mover `expires_at` al pasado de una fila de prueba.

### Residual aceptado

Un Access Token emitido antes de la baja sigue siendo válido hasta su `exp`
(`ACCESS_TOKEN_TTL_MINUTES`, 15 minutos): son JWT stateless. Alert lo cubre con
la restricción `DELETED` (`403 ACCOUNT_DELETED`) durante ese plazo; Identity no
puede revocarlos.

## Sellado del DNI para Audit (US-11)

Cada alerta que llega a un destinatario queda registrada en el Audit Service
durante `AUDIT_RETENTION_DAYS`, aislada, inmutable y legible solo ante un
requerimiento judicial. Identity participa con una sola cosa: cuando Alert va a
crear una alerta, le entrega el DNI de su emisor **sellado** hacia la clave
pública de Audit. Alert lo guarda únicamente en su outbox, hasta publicarlo en
`audit.alert.recorded`; este servicio no guarda ni loguea el criptograma.

```
Alert     POST /alerts → en paralelo y antes del 202:
            Identity  POST /internal/audit/dni { user_id, alert_id }
Identity  abre users.dni_encrypted con AES_KEY (en memoria)
          → lo sella con HPKE hacia AUDIT_PUBLIC_KEY
          → borra el DNI en claro
          → { dni_enc_audit, audit_key_id }
```

### `POST /internal/audit/dni`

Va en el puerto interno (`HTTP_INTERNAL_PORT`), con `X-Internal-Service-Token`
como el resto de `/internal/*`, y nunca en Kong.

```bash
curl -X POST http://vinculo-vial-identity:8081/internal/audit/dni \
  -H "X-Internal-Service-Token: $INTERNAL_SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"<UUID>","alert_id":"<UUID>"}'
```

| Status | `code` | Caso |
|---|---|---|
| 200 | — | `{ "dni_enc_audit": "<base64 de enc‖ct>", "audit_key_id": "<string>" }`, y nada más |
| 400 | `INVALID_BODY` | Cuerpo no interpretable, o `user_id` o `alert_id` ausentes, nulos o que no son UUID |
| 401 | `servicio_no_autorizado` | Falta `X-Internal-Service-Token` o es incorrecto (igual que `verify-ownership`) |
| 404 | `USER_NOT_FOUND` | El usuario no existe. Alert lo traduce en `403 ACCOUNT_DELETED` |
| 500 | `error_interno` | Falla algo interno, por ejemplo un `dni_encrypted` que no abre; sin detalle |
| 503 | `DEPENDENCY_UNAVAILABLE` | Base caída o en timeout; header `Retry-After` |

Alert es fail-closed: sin esta respuesta no se crea la alerta. La respuesta lleva
`Cache-Control: no-store`.

### Criptografía

| | |
|---|---|
| Suite | HPKE RFC 9180, modo base: DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM, la misma del resto del servicio |
| Clave pública | `AUDIT_PUBLIC_KEY`, en el entorno del servicio. Con ella solo se puede sellar |
| Clave privada | La genera `audit-keygen` (repo del Audit Service), fuera de línea y fuera de cualquier repo. No la carga ningún servicio, ni siquiera Audit; la custodia el responsable legal |
| `info` HPKE | UTF-8 de `"vv-audit:dni:" + alert_id`: un criptograma movido al registro de otra alerta, o hecho pasar por la patente (`vv-audit:pat:`), no abre |
| Texto plano | El DNI canónico (solo dígitos), tal como se guardó en el alta |
| `dni_enc_audit` | base64 estándar de `enc‖ct`, el mismo formato que `pat_enc_ia` |
| `audit_key_id` | Id corto de la clave (`AUDIT_KEY_ID`, por ejemplo `2026-11`), para rotarla |

Cada sellado usa una clave efímera nueva, así que dos alertas del mismo emisor
dan criptogramas distintos: el registro no permite saber que son del mismo
emisor sin abrirlos.

La apertura (`auditctl export` y `audit-open`) y la custodia de la privada son
del repo de Audit; Identity no participa y no tiene cómo reabrir lo que sella.

### Variables

| Variable | Valor | Nota |
|---|---|---|
| `AUDIT_PUBLIC_KEY` | Pública X25519 en base64 | **Obligatoria.** Se valida al arrancar sellando un valor de prueba: una clave que no sirve hace fallar el arranque. Tiene que ser igual a la de Vehicle |
| `AUDIT_KEY_ID` | Id corto, `[A-Za-z0-9._-]`, hasta 32 caracteres | **Obligatorio**, igual al de Vehicle. Cabe en `audit_key_id` de Audit (`varchar(32)`) y en la línea `audit_key_id=base64` que lee `audit-open`, por eso no admite `=` ni espacios |

El servicio no arranca sin ellas, ni compose.

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

`AUDIT_PUBLIC_KEY` y `AUDIT_KEY_ID` son obligatorias (el servicio no arranca sin
ellas, ni compose) y **no** salen de `genkeys`: el par de Audit lo genera
`audit-keygen`, en el repo del Audit Service, fuera de línea y con la privada
fuera de cualquier repo. Ver
[Sellado del DNI para Audit](#sellado-del-dni-para-audit-us-11). Para desarrollo
local alcanza con un par de prueba, que se genera con `audit-keygen` o con
cualquier par X25519 en base64, y un id como `dev`.

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
está detrás de interfaces de `domain` y se ejercita con dobles. Las pruebas de
integración del repositorio (`-tags=integration`) sí necesitan Postgres; ver
la sección CI.

## CI

`.github/workflows/ci.yml` corre en todo pull request hacia `dev` o `main` y
tiene dos jobs. Para la regla de protección de `dev` hay que exigir los dos
checks: `build-and-test` y `security`.

**`build-and-test`**: compila, `go vet -tags=integration`, pruebas unitarias,
pruebas de integración contra Postgres (se exige que corran todas las
`TestIntegracion*`) y cobertura.

- **Un solo reporte.** Las unitarias y las de integración se miden con
  `-covermode=atomic -coverpkg=./...`, se unen con `gocovmerge` y se convierten
  a Cobertura XML con `gocover-cobertura`.
- **Gate sobre el código nuevo.** `diff-cover` exige 85 % de cobertura sobre
  las líneas que el PR agrega o cambia respecto de su rama base. Si el PR no
  toca código medible, pasa.
- **Cobertura total.** Se publica en el resumen del job (`$GITHUB_STEP_SUMMARY`)
  y en el artefacto `cobertura`, sin cortar el job. En v0.14, cuando todos los
  repos estén en 85 % o más, el gate pasa a ser sobre el total.
- **Exclusiones.** Ninguna: hoy no hay código generado en el repo, y no se
  excluye código escrito a mano para subir el número. Si aparece código
  generado, se lista acá con su motivo.

**`security`**:

- **Trivy** (`fs`, `vuln,secret,misconfig`, `HIGH,CRITICAL`, `--ignore-unfixed`):
  falla ante hallazgos con corrección disponible. Las excepciones van solo en
  `.trivyignore`, cada una con un comentario con el motivo y hasta cuándo.
- **govulncheck** (`./...`): falla ante vulnerabilidades alcanzables desde el
  código.
- **Semgrep** (`p/default`): solo informativo. Los hallazgos salen en el
  resumen del job y no cortan nada; pasa a gate en v0.14.

Las acciones de terceros están fijadas por SHA de commit (la versión va en un
comentario) y el workflow tiene `permissions: contents: read`. Dependabot
propone semanalmente actualizaciones de `gomod`, `github-actions` y `docker`
contra `dev`.

### Correrlo en local

Con Go y Python instalados (las versiones de las herramientas están en el
bloque `env` de `ci.yml`):

```bash
go install github.com/wadey/gocovmerge@b5bfa59ec0adc420475f97f89b58045c721d761c
go install github.com/boumenot/gocover-cobertura@v1.5.0
go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
python -m pip install diff-cover==11.0.1

# Cobertura: unitarias + integración (Postgres en 127.0.0.1:55432)
mkdir -p coverage
go test -count=1 -covermode=atomic -coverpkg=./... -coverprofile=coverage/unit.out ./...
docker run -d --name vv-identity-it -e POSTGRES_USER=identity \
  -e POSTGRES_PASSWORD=identity -e POSTGRES_DB=identity \
  -p 127.0.0.1:55432:5432 postgres:17-alpine
TEST_DATABASE_URL='postgres://identity:identity@127.0.0.1:55432/identity?sslmode=disable' \
  go test -tags=integration -count=1 -run Integracion -covermode=atomic \
  -coverpkg=./... -coverprofile=coverage/integration.out ./internal/repository/postgres/
gocovmerge coverage/unit.out coverage/integration.out > coverage/total.out
gocover-cobertura < coverage/total.out > coverage/cobertura.xml
go tool cover -func=coverage/total.out | tail -1          # cobertura total

# Gate sobre el código nuevo (contra la rama base; hace falta `git fetch origin`)
diff-cover coverage/cobertura.xml --compare-branch=origin/dev --fail-under=85

# Escaneos
govulncheck ./...
docker run --rm -v "$PWD:/src:ro" aquasec/trivy:latest fs \
  --scanners vuln,secret,misconfig --severity HIGH,CRITICAL --ignore-unfixed \
  --exit-code 1 --skip-files /src/.env /src
docker run --rm -v "$PWD:/src" -w /src semgrep/semgrep:1.184.0 \
  semgrep scan --config p/default --metrics=off .
```

`diff-cover` compara contra el árbol de trabajo, así que los archivos nuevos
tienen que estar al menos con `git add -N` para que cuenten.

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
internal/service/account/   baja de cuenta (US-11)
internal/service/audit/     sellado del DNI del emisor hacia Audit (US-11)
internal/service/sanction/  barrido de las sanciones heredables vencidas (US-11)
internal/repository/postgres/  persistencia GORM (users, sessions, outbox_events, sanction_carryovers)
internal/delivery/http/     handlers Gin, DTOs, middlewares
internal/delivery/events/   publisher RabbitMQ (+ inerte)
internal/delivery/consumer/ infraestructura de consumo RabbitMQ: ack manual, reintentos, DLQ (US-08)
internal/crypto/hpke/       descifrado del transporte
internal/crypto/auditseal/  sellado HPKE del DNI hacia la clave pública de Audit (US-11)
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
| `account_status` | varchar(32) | `ACTIVE` o `UNDER_REVIEW` (US-08) |
| `reputation_score` | integer | NOT NULL, default 0 (US-08); baja `FRAUD_PENALTY` por cada alerta rechazada por fraude y puede quedar negativa |
| `report_count` | integer | NOT NULL, default 0 (US-08); solo el conteo, nunca quién reportó |
| `created_at` / `updated_at` | timestamptz | |

`AutoMigrate` es una decisión de MVP: solo agrega columnas e índices. Va contra
la regla de migraciones versionadas de la plataforma (`.clauderules`, 14.5); la
excepción está aceptada y es deuda técnica de todo el proyecto (ver abajo).

Las columnas de US-08 se agregaron a una tabla con usuarios. Llevan default
explícito, que es lo que deja declararlas `NOT NULL` y hace que cada usuario
existente quede en 0 al migrar, sin backfill. Una prueba de integración migra
una tabla `users` con filas y verifica los valores, el `NOT NULL` y el default.

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
| `type` | varchar(64) | tipo de evento: `user.sessions.revoked`, `user.status.changed` (US-08) o `user.deleted` (US-11) |
| `payload` | jsonb | por tipo; p. ej. `{"user_id": "…", "reason": "REUSE_DETECTED"}` |
| `status` | varchar(16) | `pending` / `sent`, indexada junto a `created_at` |
| `attempts` | int | incrementado en cada intento fallido |
| `last_error` | text | nullable; diagnóstico del último fallo |
| `created_at` | timestamptz | usada para ordenar `FetchPending` |
| `sent_at` | timestamptz | nullable; se fija al marcar `sent` |

Una base que haya corrido el esquema anterior de #41 (columnas `user_id` y
`reason`, ambas NOT NULL) se migra sola al arrancar: `NewOutboxRepository`
convierte cada fila existente al formato `type` + `payload` y recién después
borra las dos columnas viejas, para no dejar sin contenido a los eventos
pendientes. Es idempotente y no toca la tabla si ya está migrada. Se cubre con
pruebas de integración contra Postgres real, bajo el build tag `integration`:
`TEST_DATABASE_URL=… go test -tags=integration -run Integracion ./internal/repository/postgres/`.
Fallan —no se omiten— si falta la variable, y el CI las corre en un paso aparte.

Tabla `processed_events` (US-08), creada con `AutoMigrate` en
`ReputationRepository`. Es la marca de deduplicación de los consumidores, que
son at-least-once: se inserta en la misma transacción que el efecto del evento.

| campo | tipo | notas |
|---|---|---|
| `event_id` | uuid | PK compuesta: `eventId` del sobre |
| `consumer` | varchar(128) | PK compuesta: cola de trabajo que lo procesó |
| `event_type` | varchar(64) | |
| `processed_at` | timestamptz | |

La clave única `(event_id, consumer)` es lo que hace idempotente al consumidor:
`INSERT … ON CONFLICT DO NOTHING` sin filas afectadas significa que el evento ya
se procesó. El mismo evento visto por otra cola no es un duplicado.

Tabla `sanction_carryovers` (US-11), creada con `AutoMigrate` en
`ensureSanctionCarryovers`, que además migra el registro de retención anterior si
la base lo tiene. Es la sanción de una cuenta penalizada que se dio de baja, para
heredarla si el mismo DNI se vuelve a registrar; su estructura, sus reglas y el
barrido están en [Baja de cuenta](#baja-de-cuenta-us-11). `EPHEMERAL_DB` también
borra el esquema de retención anterior, si existe: sobrevivir al borrado de
`public` lo haría migrar, y heredar una sanción de una corrida anterior.

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

El servicio publica tres eventos, `user.sessions.revoked`,
`user.status.changed` (US-08) y `user.deleted` (US-11), con el Event Envelope
estándar de la plataforma. Los tres salen por el outbox. El payload no lleva PII: quien necesite datos de
la persona los pide a este servicio. El alta no publica nada: Core confirmó que
`user.created` no tiene consumidor.

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

### `user.status.changed`

Anuncia un cambio de `account_status` (US-08). Hoy solo lo emite el consumo de
`alert.reported`, cuando un emisor ACTIVE llega a `REPORT_REVIEW_THRESHOLD`
reportes y pasa a `UNDER_REVIEW`. Alert lo consume para bloquear nuevas alertas
de ese emisor. `actor` es `null`: es un hecho del sistema, y el usuario va en el
payload.

Se escribe en `outbox_events` en la misma transacción que el cambio de estado
(nunca con un publish suelto tras el commit), y el worker del outbox lo
publica con el mismo `eventId` entre reintentos.

```json
{
  "eventId": "…",
  "eventType": "user.status.changed",
  "timestamp": "2026-10-09T12:00:00Z",
  "producer": "vinculo-vial-identity",
  "actor": null,
  "payload": {
    "user_id": "6f2a4c1e-9d3b-4f5a-8c7d-1e2f3a4b5c6d",
    "account_status": "UNDER_REVIEW",
    "reason": "REPORTS_THRESHOLD"
  }
}
```

`reason` puede ser `REPORTS_THRESHOLD` (el emisor llegó al umbral de reportes) o,
desde US-11, `INHERITED_ON_SIGNUP`: la cuenta nació en revisión porque el mismo
DNI había sido dado de baja con una sanción vigente. Alert ignora el `reason`.

**Levantar la revisión** queda fuera de alcance de US-08 (es manual, para un
caso de uso futuro de administración). Hacerlo a mano en la base **no alcanza**:
Alert mantiene una proyección alimentada por este evento, así que además de
poner `account_status = 'ACTIVE'` hay que emitir `user.status.changed` con
`ACTIVE`. Sin ese evento, Alert sigue bloqueando al emisor.

### `user.deleted`

Anuncia la baja de una cuenta (US-11). Alert lo consume para desvincular al
usuario de las alertas que emitió y recibió, y Vehicle para borrar sus
vehículos. `actor` es el usuario dado de baja; el payload solo lleva cuándo, sin
ningún dato personal.

Se escribe en `outbox_events` en la misma transacción que el borrado, junto con
`user.sessions.revoked` (con `reason: ACCOUNT_DELETED`, que Notification usa
para borrar los device tokens), y el worker lo publica con el mismo `eventId`
entre reintentos. `deleted_at` es el de la baja, no el del intento de
publicación.

```json
{
  "eventId": "…",
  "eventType": "user.deleted",
  "timestamp": "2026-11-02T15:04:06Z",
  "producer": "vinculo-vial-identity",
  "actor": "6f2a4c1e-9d3b-4f5a-8c7d-1e2f3a4b5c6d",
  "payload": {
    "deleted_at": "2026-11-02T15:04:05.123456789Z"
  }
}
```

## Consumo de eventos (US-08)

`internal/delivery/consumer` es la infraestructura común de los consumidores de
este servicio. Cada handler implementa `consumer.Handler` y se corre con
`consumer.Run`, con una conexión AMQP dedicada que se reabre con backoff
exponencial si el broker cae. Como el publisher, nunca declara topología: la
cola de trabajo `W`, `W.retry` y `W.dlq` las declara `vinculo-vial-core`.

- **Ack manual** después de procesar con éxito, nunca `auto-ack`, y `prefetch`
  explícito (`RABBITMQ_PREFETCH`).
- **Fallo transitorio** (cualquier error que el handler devuelva, por ejemplo la
  base caída): `nack` sin requeue. `W` hace dead-letter a `vvi.retry.exchange`
  con routing key `W`; `W.retry` espera su TTL y devuelve el mensaje solo a `W`.
  Los reintentos se cuentan con `x-death`, mirando únicamente la cola `W`.
  Agotados `MAX_RETRIES`, el mensaje se publica en `vvi.dlq.exchange` y recién
  después se hace ack.
- **Fallo permanente** (sobre ilegible, sin `eventId` ni `eventType`, `eventType`
  ajeno a la cola, `errors.Is(err, consumer.ErrPermanent)` o un panic del
  handler): directo a la DLQ, sin reintento.
- **La DLQ se rutea por el nombre de la cola de trabajo**, no por la routing key
  del evento, con mensaje persistente, `mandatory=true` y publisher confirm
  bajo un timeout (`RABBITMQ_PUBLISH_TIMEOUT`). Si la DLQ no confirma, el
  original no se confirma: vuelve por la cola de reintento.
- La entrega es at-least-once: cada handler tiene que ser idempotente.

### `alert.rejected` → reputación

Consume `identity.alert-rejected.q` (`ALERT_REJECTED_QUEUE`). El `actor` del
sobre es el emisor de la alerta rechazada. En una única transacción se registra
el evento en `processed_events` y, si algún código de `reason_codes` es de
fraude (`NO_VEHICLE`, `BURST_MISMATCH`, `PLATE_MISMATCH`), se resta
`FRAUD_PENALTY` a `users.reputation_score`. `EVIDENCE_UNREADABLE` solo no
penaliza. Un `actor` que no es un UUID, o un payload sin `alert_id` válido ni
`reason_codes`, va directo a la DLQ; un error de base reintenta.

Un evento sin `actor` (`null` o ausente) es el de una alerta cuyo emisor fue
dado de baja (`issuer_id = NULL`, US-11): no hay a quién penalizar, así que se
confirma sin efecto, con un log INFO y sin pasar por la DLQ ni por el reintento.
Lo mismo si el usuario ya no existe: se loguea y se confirma. El payload se
valida antes de mirar el actor, así que un payload inválido va a la DLQ aunque
el actor falte.

### `alert.reported` → revisión

Consume `identity.alert-reported.q` (`ALERT_REPORTED_QUEUE`). El `actor` del
sobre es el emisor reportado. En una única transacción se registra el evento en
`processed_events`, se suma uno a `users.report_count` (`UPDATE … RETURNING`) y,
si el conteo llega a `REPORT_REVIEW_THRESHOLD` y el usuario estaba `ACTIVE`, se
lo pasa a `UNDER_REVIEW` y se escribe `user.status.changed` en el outbox. Un
usuario que ya está en revisión sigue contando pero no vuelve a publicar, y un
duplicado no incrementa.

Igual que con `alert.rejected`, un evento sin `actor` (alerta de un emisor dado
de baja, US-11) o cuyo usuario ya no existe se confirma sin efecto: nadie queda
en revisión, no se encola `user.status.changed` y el mensaje no va a la DLQ. Un
`actor` que no es un UUID o un payload inválido sí va a la DLQ.

`UNDER_REVIEW` restringe solo la creación de alertas, y esa restricción la
aplica Alert: en Identity no bloquea el login, el refresh ni nada más (ningún
flujo consulta `account_status`). Identity no guarda quién reportó ni qué
alerta fue: `alert.reported` no trae al denunciante, y el payload solo se
valida (`alert_id` UUID, `reason` ∈ `FALSE_ALERT` | `SPAM`). Riesgo aceptado por
el contrato: con umbral 1, cualquier destinatario puede poner en revisión al
emisor que lo alertó.

## Health

Tres rutas en el puerto público, con roles distintos:

| ruta | qué chequea | responde |
|---|---|---|
| `/healthz` | nada: el proceso está vivo | `200` |
| `/ready` (alias `/readyz`) | **solo la base propia** | `200` / `503` |
| `/health/deps` | broker, worker del outbox y breaker hacia RENAPER | `200` / `503` |

`/ready` es el path del healthcheck activo de Kong, por eso no mira nada más
que la base: sacar a Identity del balanceo porque el broker o RENAPER fallan
dejaría sin servicio a endpoints que no los usan. `/health/deps` es para
diagnóstico y monitoreo, y su `503` **no** afecta al balanceo ni a `/ready`.

```json
{"status": "ok", "checks": {"broker": "up", "outbox_worker": "up", "renaper_breaker": "closed"}}
```

Si alguna dependencia no está sana responde `503` con `"status": "degraded"` y
el estado de las tres (nunca corta en la primera que falla):

| check | sano | degradado |
|---|---|---|
| `broker` | `up`; `disabled` con `RABBITMQ_ENABLED=false` (solo desarrollo) | `down`: sin conexión o canal vivo |
| `outbox_worker` | `up` | `down`: el último ciclo no pudo leer el outbox (la base falla); `stalled`: sin iniciar un ciclo hace más de `max(5 × intervalo, 1 min)`; `stopped` |
| `renaper_breaker` | `closed` | `open`; `half_open` (venció `RENAPER_BREAKER_OPEN_DURATION`, la próxima llamada decide) |

Un broker caído **no** degrada al worker: un publish fallido deja el evento
pendiente y el worker sigue sano reintentando. Y como la reconexión del
publisher es perezosa, el worker la restablece solo en los ciclos sin eventos
pendientes: sin eso, `broker` seguiría en `down` tras una caída hasta el
próximo evento, aunque el broker ya estuviera sano. El cuerpo solo lleva el
nombre del estado, nunca el detalle de un error.

## Deuda técnica conocida

- **Cliente real de RENAPER.** `internal/renaper.Mock` aprueba cualquier
  identidad sin verificar nada: es imprescindible para desarrollar y para tests,
  pero **no debe llegar a producción**. No hay todavía credenciales ni contrato
  acordado con la API real.
- **Contrato desincronizado con Frontend y Gateway.** El payload interno
  reemplazó `biometric_verified` por `tramite`/`sexo`/`selfie`; hasta que los
  otros dos repos repliquen el cambio, no son interoperables entre sí.
- **Migraciones versionadas**, en lugar de `AutoMigrate`. La migración del
  registro de retención anterior (US-11) usa SQL explícito e idempotente, pero
  tampoco está versionada.
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
