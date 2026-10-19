# Auditoría de seguridad y mejoras — Canary Token Generator

Alcance: todo el código propio (backend Go, frontend React, Docker/nginx/CI, documentación). Se excluyó `node_modules`.
Método: lectura completa del código, **reproducción de los fallos con código ejecutable** sobre la versión original y
tests de regresión para cada corrección. Un fallo que no pude reproducir se marca como *por análisis*.

> **Resumen.** El diseño general es sólido (capas claras, interfaces, sin SQL concatenado, React sin `dangerouslySetInnerHTML`).
> Pero una herramienta de *detección* tiene un requisito especial: **no puede perder ni falsear alertas**. Había fallos que
> permitían tomar el control de todos los tokens, atacar la red interna del servidor, falsificar la IP del intruso,
> **evadir las alertas** y atribuir detecciones al usuario equivocado.

## 1. Hallazgos y correcciones

Severidad: **C** crítica · **A** alta · **M** media · **B** baja. *Evidencia*: ✅ reproducido en el original · 🔎 por análisis de código.

### Críticos

| # | Hallazgo | Evidencia | Corrección |
|---|---|---|---|
| C1 | **Credenciales de administración por defecto** (`canary-super-secret-admin-token` en Go y otro valor por defecto en `compose.yml`). `GET /admin/tokens` devolvía las `manage_key` de **todos** los tokens ⇒ control total. `/admin` estaba además expuesto por nginx. | 🔎 | Sin valor por defecto: en producción se exige `ADMIN_TOKEN` ≥ 24 caracteres y se rechazan los valores conocidos (el proceso no arranca); en desarrollo se genera uno aleatorio. Comparación en tiempo constante sobre SHA-256, 401 uniforme, rate limit, `/admin` restringido en nginx y bloqueado en el túnel. |
| C2 | **SSRF por `webhook_url`**: cualquier usuario anónimo podía hacer que el servidor enviase POST a `127.0.0.1`, `169.254.169.254` (metadatos cloud) o servicios internos, siguiendo redirecciones. | 🔎 | Paquete `netguard`: solo `https`, validación **al conectar** sobre la IP ya resuelta (neutraliza DNS rebinding y respuestas mixtas), sin redirecciones, sin proxies de entorno. |
| C3 | **XSS / redirección abierta a `javascript:`** en el *slow redirect*: `target_url` no se validaba y se insertaba con `html.EscapeString` dentro de un literal JavaScript (contexto de escape equivocado). Un enlace del propio dominio ejecutaba JS en el origen de la app. Una `\` final rompía además el script. | ✅ | `target_url` solo `http(s)` sin credenciales (al crear **y** al renderizar, por si hay filas antiguas); plantilla `html/template` con escape contextual; CSP con *nonce* por respuesta. |
| C4 | **Honeypot MySQL**: (a) el usuario generado llevaba solo 12 de los 25 caracteres del ID, **nunca coincidía**, y el *fallback* atribuía la conexión al primer token MySQL reciente **de cualquier usuario**; (b) cualquier bot que probase `root` generaba una alerta falsa a un tercero; (c) cada conexión sin autenticar podía forzar una reserva de 16 MiB, sin límite de conexiones ⇒ DoS de todo el proceso. | ✅ (a, b) · 🔎 (c) | Atribución solo por coincidencia **exacta** del ID completo; el ruido de fondo se cuenta en métricas pero no alerta; paquete máx. 64 KiB antes de reservar memoria; límites total/por IP; *deadline* de 15 s; `recover` por conexión. |
| C5 | **IP de origen falsificable**: se creía ciegamente `CF-Connecting-IP`, `X-Forwarded-For` (primer valor) y `X-Real-IP`; nginx además *anexaba* a lo que enviase el cliente. El atacante podía falsear su IP, **esquivar el rate limit y el deduplicado** rotando la cabecera y, en Postgres (`source_ip VARCHAR(64)`), enviar una cabecera larga para que el `INSERT` fallase y **el evento se perdiese**. | ✅ | Paquete `clientip`: las cabeceras solo se aceptan si el peer TCP es un proxy de confianza (`TRUSTED_PROXIES`), se recorre `X-Forwarded-For` de derecha a izquierda, la IP siempre se valida/normaliza. nginx **sobrescribe** `X-Forwarded-For` y elimina `CF-Connecting-IP`. |

### Altos

| # | Hallazgo | Evidencia | Corrección |
|---|---|---|---|
| A1 | **Evasión de alertas en Telegram**: Markdown con valores sin escapar; un `` ` `` en el *User-Agent* hacía que la API devolviese 400 y la alerta se perdía. Además el **token del bot se filtraba a los logs** (`*url.Error` incluye la URL). | 🔎 | Modo HTML con escape y truncado de todos los campos; errores sin URL. |
| A2 | **Rate limit inoperante en modo standalone**: `MemoryCache.Incr` tenía el cuerpo vacío y siempre devolvía 1. En Redis, incremento y TTL eran dos pasos (carrera). No se aplicaba a `/api/manage`, `/admin` ni a los sensores. | ✅ | `IncrWithTTL` atómico (Lua en Redis), caché acotada, límites por ruta y por IP real. |
| A3 | **El aviso con la huella del navegador se silenciaba**: el deduplicado por (token, IP) hacía que la alerta inicial suprimiese la del *fingerprint*, que es la que desenmascara al visitante. `Exists`+`Set` no era atómico. | 🔎 | `SetNX` atómico por token+IP+**clase** (`hit`/`fp`). |
| A4 | **Secretos de gestión expuestos**: `manage_key` en texto plano en BD, en la **ruta de la URL** (registrada por el logger de la app y por nginx, historial, `Referer`), devuelta por la API de admin; el secreto HMAC del webhook se devolvía en cada `GET`. | 🔎 | Solo se guarda su SHA-256 (migración automática de claves antiguas), viaja en `X-Manage-Key`, los enlaces usan el fragmento `/#/manage/…`, y `Token` serializa con lista blanca (sin `manage_key`, `notify_config` ni semilla). |
| A5 | **Eventos perdidos**: el registro usaba el contexto de la petición (si el cliente cerraba, se cancelaba el `INSERT`), y los errores se descartaban (`_, _ =`). | 🔎 | Contexto desacoplado con *timeout*, errores registrados. |
| A6 | **SQLite sin `foreign_keys`, `busy_timeout` ni WAL**: el `ON DELETE CASCADE` no se aplicaba (eventos huérfanos) y las escrituras concurrentes fallaban con *database is locked* (eventos perdidos). | 🔎 | Pragmas en el DSN, una única conexión de escritura, índice compuesto. |
| A7 | **Cola de alertas**: el apagado cancelaba el contexto y **descartaba las alertas pendientes**; `Enqueue` tras el cierre provocaba *panic* (`send on closed channel`); un webhook lento (*tarpit*) controlado por un atacante acaparaba los 4 workers y dejaba sin alertas a los demás. | 🔎 | Drenado ordenado, `Enqueue` seguro, tope de 2 concurrentes por host, reintentos solo en 5xx/429, URLs de webhook no se registran completas. |
| A8 | **Cobertura de detección**: `HEAD` y otros métodos daban 405 (previsualizadores y escáneres de correo no se detectaban); `/k/…` respondía distinto para tokens válidos e inválidos (**oráculo** para enumerar señuelos). | 🔎 | Los sensores aceptan cualquier método; respuesta idéntica exista o no el token. |

### Medios

| # | Hallazgo | Corrección |
|---|---|---|
| M1 | **Turnstile nunca se cargaba en el frontend**: activar `TURNSTILE_SECRET_KEY` hacía fallar **todas** las creaciones con 403 (✅). | Endpoint `/api/config` + widget real. |
| M2 | Los validadores (`IsValidURL`…) eran **código muerto**; sin límite de tamaño de body; los 500 devolvían `err.Error()` (SQL, rutas). | Validación completa de etiqueta/URL/canal/chat/opciones, `MaxBytesReader`, errores genéricos al cliente. |
| M3 | El token se guardaba **antes** de generar el artefacto: si fallaba quedaba un token activo huérfano. PDF con `/Length 120` frente a 151 bytes reales (✅ `qpdf` lo reparaba) y fallo con `BASE_URL` > 48 caracteres. | Validar → generar → persistir. PDF construido con xref y `/Length` calculados (`qpdf --check` sin avisos). |
| M4 | La **descarga ignoraba la receta elegida** (siempre AWS) y regeneraba credenciales distintas cada vez; el `.docx` tenía orden de ZIP aleatorio; el «JPEG» del webbug **no podía disparar nada** (falsa sensación de protección). Descarga pública identificada solo por el ID del token. | Semilla por token (HMAC-SHA256) y opciones persistidas ⇒ artefactos deterministas; webbug entrega HTML; descarga exige `X-Manage-Key`. |
| M5 | **Fidelidad de los señuelos**: claves AWS en hex minúsculo (los escáneres tipo trufflehog las ignoran), `svc_canary_worker`, banner `8.0.35-canary-audit`, `CanaryPixel`, `CanaryFP` (delatan el engaño), `whsec_` derivado de la clave principal, JWT falso con firma literal, `shuffle` que mezclaba comentarios, variable `AWS_STS_REGIONAL_ENDPOINTS=<url>` sin sentido. | Formatos reales (AKIA+base32, ghp_ con CRC32 válido…), sin marcas, secretos independientes, `AWS_ENDPOINT_URL`/`GITHUB_API_URL`/`STRIPE_API_BASE` (variables que las herramientas sí respetan), JWT con claims reales, y el `.env` apunta al honeypot MySQL de la propia instancia. |
| M6 | **Infraestructura**: CORS `*`; `X-XSS-Protection: 1; mode=block`; sin CSP; regex de nginx sin anclar (`/robots.txt`, `/favicon.ico`… iban al backend ✅); puerto 443 publicado sin TLS; DSN de Postgres con contraseña fija (ignoraba `POSTGRES_PASSWORD`); Redis sin contraseña; contenedor como root, `amd64` fijo, Go 1.24 frente a `go 1.26.0` (las imágenes oficiales de Go fijan `GOTOOLCHAIN=local`, por lo que el build debería fallar; no pude construir imágenes para confirmarlo), `pnpm@latest`, Node 20 y Alpine 3.20 (fin de vida); puertos de dev expuestos a toda la red; sin `.gitignore`/`.dockerignore`. | Reescritos (ver §3). |
| M7 | El generador MySQL ignoraba `MYSQL_PORT`; el compose nunca montaba la base GeoIP (el enriquecimiento nunca funcionaba). | `PUBLIC_MYSQL_HOST/PORT`; volumen `data/geoip`. |
| M8 | Métricas serializadas con *data race*; `rows.Err()` sin comprobar; retención en hora local; sin primera limpieza al arrancar; `Sleep` ciego en el apagado; `Daemon Online` fijo en la UI. | Corregidos. |

### Bajos / mejoras
Cabeceras de petición acotadas y con credenciales **redactadas** (`Authorization`, `Cookie`…); *beacon* absoluto y con `keepalive` (el HTML descargado y alojado fuera nunca reportaba); hash SHA-256 en lugar de 32 bits para el canvas; etiquetado `link-preview-or-scanner` / `prefetch` (principal fuente de falsos positivos); `aws_access_key_id` extraído de peticiones SigV4; borrado de token y eventos por su propietario; consultas SQL escritas una sola vez (`Rebind`); CI con `govulncheck`, `pnpm audit`, `gitleaks` y build de imágenes.

## 2. Verificación

| Comprobación | Resultado |
|---|---|
| `go build`, `go vet`, `gofmt` | limpios |
| `go test -race -count=3` | **84 tests** (original: 7), 2.267 líneas de test (original: 226), estables en 3 ejecuciones |
| Cliente MySQL **real** (PyMySQL) contra el honeypot | handshake OK, error 1045 con formato exacto; credencial plantada ⇒ `password_match:"yes"` y atributos `pymysql 1.2.3`; otro token ⇒ 0 eventos; `root`/`admin` ⇒ sin evento |
| `qpdf --check` sobre el PDF generado | sin avisos (original: «expected endstream») |
| nginx 1.24 real delante de un backend de eco | `X-Forwarded-For` sobrescrito, rutas ancladas, `/admin` 403 desde IP no permitida, 100 KB ⇒ 413, 108 de 300 ráfagas ⇒ 429 |
| Frontend `tsc --noEmit` y `vite build` | sin errores; sin scripts inline (compatible con la CSP) |

Los tests incluyen una regresión por hallazgo (p. ej. `TestAttributionIsExactAndNeverFallsBackToAnotherToken`,
`TestMemoryCacheIncrActuallyCounts`, `TestFingerprintAlertNotSuppressedByInitialHit`, `TestSlowRedirectNeutralisesDangerousTargets`).
Durante el trabajo aparecieron y se corrigieron además tres fallos en mi propio código (bucle infinito en `accept` por comparar
`err == net.ErrClosed`, *race* en `SetLimits`, y un test intermitente por truncar cabeceras en orden de `map`).

## 3. Cambios incompatibles (migración)

- **API**: la clave de gestión ya no va en la URL. `GET /api/manage/{key}` → `GET /api/manage` con cabecera `X-Manage-Key`; `POST /api/manage/toggle`; `DELETE /api/manage` (nuevo); `GET /api/manage/download` sustituye a `GET /api/tokens/{id}/download` (que era público). `manage_key` y `notify_config` ya no se serializan; `CreateTokenResponse` incluye `manage_key` **una sola vez**.
- **Enlaces antiguos** `/manage/<key>` siguen funcionando (se trasladan al fragmento). Las claves en claro existentes se **hashean automáticamente** en el primer arranque.
- **Configuración**: `ADMIN_TOKEN` obligatorio en producción; el compose exige `BASE_URL`, `ADMIN_TOKEN`, `POSTGRES_PASSWORD`, `REDIS_PASSWORD` (ver `.env.example`). Nuevas variables: `TRUSTED_PROXIES`, `CLIENT_IP_HEADER`, `CORS_ALLOWED_ORIGINS`, `ALLOW_PRIVATE_WEBHOOKS`, `PUBLIC_MYSQL_HOST/PORT`, `MYSQL_MAX_CONNS[_PER_IP]`, `TURNSTILE_SITE_KEY`.
- **Tokens MySQL ya emitidos**: sus usuarios `canary_<12>` nunca funcionaron; hay que regenerarlos.
- **Webhooks**: ahora `https` y destinos públicos. Para uno interno de confianza, `ALLOW_PRIVATE_WEBHOOKS=true` (rechazado en producción pública).
- **Tunnel**: requiere Docker Compose ≥ 2.24.4 (`!reset`).

## 4. Limitaciones de esta revisión (léelas)

1. **No pude compilar contra las dependencias reales** (la red del sandbox lo impide). Verifiqué con *stubs* de `chi`, `cors`, `uuid`, `go-redis`, `geoip2` y `pgx`, que cubren solo el subconjunto de API usado, y con SQLite real (`mattn/go-sqlite3`) en lugar de `modernc.org/sqlite`. Ejecuta `just backend-test` en tu entorno; los puntos de mayor riesgo son: el DSN `?_pragma=…` de modernc (sintaxis documentada, no ejecutada), `redis.NewScript(...).Run` y el comportamiento de `chi.Route/With`.
2. **Postgres y Redis reales no se ejecutaron**; el SQL es portable (`$n`) y los índices/`DROP INDEX IF EXISTS` son estándar.
3. **Docker no estaba disponible**: los Dockerfiles y el compose no se construyeron aquí (nginx sí se probó con el binario real, versión 1.24; producción usa 1.28). Verifica que existan las etiquetas `golang:1.26-alpine`, `alpine:3.22` y `nginx:1.28-alpine`, y fija `cloudflared` por versión/digest.
4. Riesgos que **siguen existiendo** por diseño: la paginación es `LIMIT/OFFSET` (inestable con eventos nuevos); las huellas del navegador las aporta el cliente y son falsificables; el bot de Telegram es compartido y no se verifica que el `chat_id` pertenezca al usuario; un único token de operador estático (sin cuentas ni auditoría completa); el stack no termina TLS; el PDF y el `.docx` tienen fiabilidad limitada (Acrobat suele pedir confirmación, *Protected View* bloquea contenido remoto); las credenciales de AWS/GitHub/Stripe del `.env` no son reales, por lo que usarlas contra esos servicios **no** te alerta (para eso, canaries nativos del proveedor).
5. Uso responsable: el slow redirect y el web bug recogen IP y huella de terceros; documenta la finalidad y la retención (`RETENTION_DAYS`) conforme a tu normativa de privacidad.
