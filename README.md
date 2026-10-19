# Canary Token Generator

> Sistema de **engaño defensivo** (*cyber deception*): crea señuelos —un PDF, un `.env`, un `kubeconfig`, una base de datos
> falsa…— que no tienen ningún uso legítimo. Si alguien los toca, **sabes que hay un intruso** y obtienes su IP, ubicación
> y huella, con una alerta en tiempo real por webhook o Telegram.

*[Read in English](README.en.md)* · [Informe de seguridad (`AUDIT.md`)](AUDIT.md) · [Guías técnicas (`learn/`)](learn/00_architecture_overview.md)

---

## Índice

1. [¿Qué es y para qué sirve?](#qué-es-y-para-qué-sirve)
2. [Cómo funciona](#cómo-funciona)
3. [Tipos de token y fiabilidad](#tipos-de-token-y-fiabilidad)
4. [Inicio rápido](#inicio-rápido)
5. [Uso](#uso)
6. [Configuración](#configuración)
7. [API](#api)
8. [Arquitectura y estructura del repositorio](#arquitectura-y-estructura-del-repositorio)
9. [Modelo de seguridad](#modelo-de-seguridad)
10. [Pruebas y calidad](#pruebas-y-calidad)
11. [Limitaciones y uso responsable](#limitaciones-y-uso-responsable)
12. [Licencia](#licencia)

---

## ¿Qué es y para qué sirve?

Un **canary token** (o *honeytoken*) es un señuelo que ningún usuario legítimo tocaría jamás. Cuando alguien lo abre o lo usa,
salta una alarma. Es una de las formas más baratas de detectar:

- un atacante que ya está **dentro** de tu red y rebusca en carpetas, repositorios o servidores;
- la **fuga** de un documento, una copia de seguridad o un repositorio privado;
- un **phishing** dirigido (el enlace trampa revela el navegador y la IP reales de quien lo abre).

Este proyecto es una implementación autoalojable: tú controlas el servidor, los datos y las alertas.

**Qué recibes cuando salta un señuelo:** IP de origen · país y ciudad (GeoIP, opcional) · User-Agent y cabeceras (con las
credenciales redactadas) · protocolo y tipo de señuelo · huella del navegador (en el *slow redirect*) · programa cliente y si usó
**exactamente la contraseña plantada** (en el honeypot MySQL) · etiquetas como `link-preview-or-scanner` para distinguir
a un escáner de enlaces de una persona.

## Cómo funciona

```
                     1. creas un token                      2. colocas el señuelo
   Tú ─────────────► [ Interfaz web / API ] ───────────────► PDF · .env · kubeconfig · enlace · my.cnf
                                │                                        │
                                │                       3. un intruso lo abre / lo usa
                                ▼                                        ▼
                     ┌─────────────────────┐    HTTP  /t /r /f /k   ┌──────────────┐
                     │  Backend Go (canary)│◄───────────────────────│  Intruso     │
                     │   · sensores HTTP   │    TCP 3306 (MySQL)    │              │
                     │   · honeypot MySQL  │◄───────────────────────└──────────────┘
                     └──────────┬──────────┘
        4. registra el evento   │   5. alerta (con deduplicado y sin perder eventos)
        (SQLite / PostgreSQL)   ▼
                     ┌─────────────────────┐        ┌─────────────────────────────┐
                     │ Eventos + GeoIP     │───────►│ Webhook firmado (HMAC) /    │
                     └─────────────────────┘        │ Telegram                    │
                                                    └─────────────────────────────┘
```

1. Creas un token desde la web (o la API): eliges el tipo y dónde quieres la alerta.
2. El sistema genera el **artefacto** (un PDF, un `.env`…) que contiene la URL de un sensor propio, y te da una **clave de gestión** privada.
3. Si alguien toca el señuelo, la petición llega a un sensor del backend (HTTP o el servidor MySQL falso).
4. Se guarda el evento y se enriquece (GeoIP).
5. Se envía la alerta. Un deduplicado atómico evita inundarte, y la cola de notificaciones se vacía ordenadamente al apagar.

## Tipos de token y fiabilidad

Un canary detecta **contacto**, no intención, y cada tipo tiene su propio alcance. Esta tabla es deliberadamente honesta:

| Tipo | Qué es | Cuándo salta | Fiabilidad |
|---|---|---|---|
| `webbug` | Píxel invisible 1×1 (HTML, Markdown o página `.html`) | Un cliente renderiza el contenido **y** carga imágenes remotas | Media: muchos clientes de correo bloquean imágenes y los proxies (p. ej. Gmail) ocultan la IP real |
| `pdf` | PDF con una acción `/OpenAction` a tu URL | Acrobat lo abre y sigue la acción | **Baja**: Acrobat suele pedir confirmación y los visores de navegador la ignoran. Pruébalo con tus lectores |
| `docx` | Word con una imagen externa en el pie de página | Word carga la imagen al abrir | Media: la *Vista protegida* la bloquea hasta «Habilitar edición» |
| `envfile` | `.env` señuelo (recetas AWS, BD, GitHub, Stripe) | Una herramienta sigue `AWS_ENDPOINT_URL`, `GITHUB_API_URL` o `STRIPE_API_BASE`, o alguien conecta al host de BD (honeypot MySQL) | Media/Baja: **las claves no son reales**; probarlas contra AWS/GitHub/Stripe no llega a tu servidor |
| `kubeconfig` | `~/.kube/config` con un JWT de *service account* realista | Alguien ejecuta `kubectl` con él | Alta para quien lo use |
| `mysql` | Servidor MySQL falso en el puerto 3306 + `my.cnf` | Alguien intenta autenticarse con el usuario plantado | Alta **si el puerto es alcanzable por el atacante** |
| `slowredirect` | Enlace con página intermedia que recoge la huella del navegador y redirige | Alguien abre el enlace | Alta para personas; los escáneres de enlaces también lo abren (se etiquetan). La huella la aporta el cliente: es un indicio, no una prueba |

> Para detectar el uso real de **credenciales cloud** usa canaries nativos del proveedor (p. ej. un usuario IAM sin permisos
> más alertas de CloudTrail). Los de este proyecto cubren el contacto con tu infraestructura.

## Inicio rápido

### Requisitos
Go 1.26+ y Node 22+ con [pnpm](https://pnpm.io) para desarrollo local; Docker con Compose ≥ 2.24 para producción.

### Opción 1 — Local (sin servicios externos)
Usa SQLite y una caché en memoria. En desarrollo el backend **genera un token de administrador aleatorio** y lo muestra en el log.

```bash
# Terminal 1 — backend (BASE_URL apunta al puerto de Vite para que los enlaces generados funcionen)
cd backend
BASE_URL=http://localhost:3000 go run ./cmd/canary

# Terminal 2 — frontend (proxy hacia el backend en :8080)
cd frontend
pnpm install
pnpm dev
```
Abre <http://localhost:3000>. Si el puerto 3306 está ocupado: `MYSQL_PORT=13306 PUBLIC_MYSQL_PORT=13306`.

### Opción 2 — Producción con Docker Compose
```bash
cp .env.example .env     # rellena BASE_URL, ADMIN_TOKEN, POSTGRES_PASSWORD y REDIS_PASSWORD
                         #   (genera cada secreto con:  openssl rand -hex 32)
mkdir -p data/geoip      # opcional: coloca aquí GeoLite2-City.mmdb para activar el GeoIP
docker compose up -d --build
docker compose logs -f
```
- **No hay credenciales por defecto**: el stack se niega a arrancar si faltan los secretos.
- Sirve **solo HTTP**: ponlo detrás de un balanceador con HTTPS o usa el túnel de Cloudflare (opción 3).
- El honeypot MySQL escucha en `3306` y debe ser alcanzable por el atacante.
- `/admin` solo responde desde el propio host Docker (edita `infra/nginx/prod.nginx` para añadir tu red de gestión).

### Opción 3 — Cloudflare Tunnel (el origen no queda expuesto)
```bash
# en .env: CLOUDFLARE_TUNNEL_TOKEN=...
docker compose -f compose.yml -f cloudflared.compose.yml up -d
```
El túnel solo reenvía HTTP(S): el puerto 3306 **no** pasa por él; publícalo en una IP pública y fija `PUBLIC_MYSQL_HOST`.
`/admin` queda bloqueado en esta variante.

### Opción 4 — Con `just`
```bash
just backend-test      # tests Go con detector de condiciones de carrera
just lint              # go vet + tsc
just audit             # govulncheck + pnpm audit
just dev               # stack de desarrollo con recarga en caliente (Air + Vite)
just --list            # todo lo demás
```

## Uso

1. **Crea un token** en la web: elige el tipo, una etiqueta y el canal de alerta (webhook o Telegram).
2. **Guarda la clave de gestión** que se muestra una sola vez (el servidor solo conserva su hash) y **descarga el artefacto**.
3. **Coloca el señuelo** donde no tenga uso legítimo (carpetas de backups, repositorios, servidores, un correo trampa…).
4. Consulta el **panel de gestión** (`/#/manage/<clave>`): eventos, detalle forense, armar/silenciar el sensor o borrar el token con todos sus eventos.

### Alerta por webhook
El servidor hace un `POST` JSON a tu URL (solo `https` y destinos públicos). Si configuraste un secreto, la petición va firmada:

```
X-Canary-Timestamp: 1760000000
X-Canary-Signature: sha256=<HMAC-SHA256 de  "<timestamp>.<cuerpo>"  con tu secreto>
X-Canary-Event-Id:  <uuid>
```
```python
import hmac, hashlib
def valido(secreto: str, timestamp: str, cuerpo: bytes, cabecera: str) -> bool:
    esperado = "sha256=" + hmac.new(secreto.encode(), timestamp.encode() + b"." + cuerpo, hashlib.sha256).hexdigest()
    return hmac.compare_digest(esperado, cabecera)   # y rechaza timestamps antiguos para evitar repeticiones
```

## Configuración

Todo se configura por variables de entorno (plantilla en [`.env.example`](.env.example)).

| Variable | Defecto | Descripción |
|---|---|---|
| `APP_ENV` | `development` | `production` activa las validaciones estrictas y el log JSON |
| `BASE_URL` | `http://localhost:8080` | URL pública; se incrusta en los señuelos y los enlaces de gestión |
| `ADMIN_TOKEN` | *(sin defecto)* | **Obligatorio en producción**, ≥ 24 caracteres. En desarrollo se genera uno aleatorio |
| `HTTP_PORT` / `MYSQL_PORT` | `8080` / `3306` | Puertos de escucha |
| `DB_DRIVER` / `DB_DSN` | `sqlite` / `canary.db` | `sqlite` o `postgres` |
| `REDIS_ADDR` / `REDIS_PASSWORD` | vacío | Sin Redis se usa caché en memoria (una sola instancia) |
| `RETENTION_DAYS` | `90` | Días que se conservan los eventos |
| `GEOIP_PATH` | `GeoLite2-City.mmdb` | Base MaxMind opcional |
| `TURNSTILE_SECRET_KEY` / `TURNSTILE_SITE_KEY` | vacío | Anti-abuso en la creación de tokens (se necesitan ambas) |
| `TELEGRAM_BOT_TOKEN` | vacío | Bot compartido para alertas por Telegram |
| `TRUSTED_PROXIES` | redes privadas | IP/CIDR de proxies cuyas cabeceras de reenvío se aceptan |
| `CLIENT_IP_HEADER` | `x-forwarded-for` | `x-forwarded-for`, `x-real-ip` o `cf-connecting-ip` |
| `CORS_ALLOWED_ORIGINS` | `BASE_URL` | Orígenes CORS permitidos |
| `ALLOW_PRIVATE_WEBHOOKS` | `false` | Permite webhooks a redes internas y `http://`. **Prohibido en producción pública** (SSRF) |
| `PUBLIC_MYSQL_HOST` / `PUBLIC_MYSQL_PORT` | host de `BASE_URL` / `MYSQL_PORT` | Dirección con la que el atacante alcanzará el honeypot |
| `MYSQL_MAX_CONNS` / `MYSQL_MAX_CONNS_PER_IP` | `256` / `8` | Límites de conexiones del honeypot |

## API

Las respuestas son `{"success": true, "data": …}` o `{"success": false, "error": "…"}`.

| Método y ruta | Auth | Descripción |
|---|---|---|
| `POST /api/tokens` | — (rate limit) | Crea un token. Devuelve `manage_key` **una sola vez**, la URL del sensor y el artefacto |
| `GET /api/config` | — | Configuración pública (clave de sitio de Turnstile) |
| `GET /api/manage?limit=&offset=` | `X-Manage-Key` | Token y eventos paginados |
| `POST /api/manage/toggle` | `X-Manage-Key` | `{"is_active": true\|false}` arma o silencia el sensor |
| `GET /api/manage/download` | `X-Manage-Key` | Descarga el artefacto (siempre idéntico) |
| `DELETE /api/manage` | `X-Manage-Key` | Borra el token y todos sus eventos |
| `GET /admin/stats` · `/admin/tokens` · `/admin/events/recent` | `Authorization: Bearer <ADMIN_TOKEN>` | Operación |
| `POST /admin/tokens/{id}/disable` | Bearer | Desactiva un token |
| `GET /healthz` | — | Estado (BD) |
| `ANY /t/{id}` · `GET /r/{id}` · `POST /f/{id}` · `ANY /k/{id}/*` | — | **Sensores públicos**: responden igual exista o no el token |

```bash
# Crear un token y leer sus eventos
curl -s -X POST localhost:8080/api/tokens -H 'Content-Type: application/json' \
  -d '{"type":"webbug","label":"Carpeta RRHH","notify_channel":"none"}'
curl -s localhost:8080/api/manage -H "X-Manage-Key: k0123…"
```

## Arquitectura y estructura del repositorio

```
.
├── backend/                         Go: API, sensores, honeypot MySQL, notificaciones
│   ├── cmd/canary/                  Arranque, configuración, apagado ordenado
│   └── internal/
│       ├── core/                    Config, BD (SQLite/Postgres), caché (Redis/memoria), validación, métricas
│       ├── clientip/                IP real del cliente resistente a falsificación
│       ├── netguard/                Cliente HTTP anti-SSRF
│       ├── middleware/              Request-ID, IP real, rate limit, cabeceras de seguridad, logging, auth de operador
│       ├── server/                  Router y rutas
│       ├── token/                   Entidad, servicio, repositorio y handlers HTTP de los tokens
│       │   └── generators/          pdf · docx · envfile · kubeconfig · mysql · slowredirect · webbug · pixel · seed
│       ├── event/                   Registro de eventos, deduplicado atómico, retención
│       ├── notify/                  Cola de alertas: webhook firmado y Telegram
│       ├── geoip/ · turnstile/ · health/ · admin/
├── frontend/                        React + TypeScript + Vite + Tailwind (creación de tokens y panel de gestión)
├── infra/                           Dockerfiles y configuración de nginx (producción, túnel y desarrollo)
├── learn/                           Guías técnicas de cada mecanismo
├── compose.yml · cloudflared.compose.yml · dev.compose.yml
├── .env.example · justfile · .github/workflows/ci.yml
└── AUDIT.md                         Informe de seguridad y de mejoras
```

Decisiones de diseño que conviene conocer:
- **Artefactos deterministas**: cada token guarda una semilla aleatoria; el mismo token produce siempre los mismos bytes.
- **No se pierde una detección**: el evento se guarda aunque el cliente cierre la conexión, y el apagado vacía la cola de alertas.
- **Deduplicado atómico** por token + IP + clase (`hit` / huella), en ventana fija de 5 minutos.
- **El honeypot MySQL no adivina**: solo atribuye una conexión si el usuario codifica el ID completo de un token.

## Modelo de seguridad

El detalle completo (hallazgos, evidencias y correcciones) está en [`AUDIT.md`](AUDIT.md). En resumen:

- La IP del cliente **nunca** se toma de una cabecera salvo que la conexión venga de un proxy de confianza.
- La clave de gestión viaja en una cabecera (no en la URL), los enlaces usan el fragmento `/#/manage/…` y solo se guarda su **SHA-256**.
- Los webhooks son **SSRF-safe**: solo `https`, destinos internos y de metadatos rechazados al conectar, sin redirecciones.
- Entradas validadas y acotadas; los errores internos no se devuelven al cliente.
- Cabeceras sensibles (`Authorization`, `Cookie`…) **redactadas** antes de guardarse.
- Contenedores sin root, sistema de ficheros de solo lectura, sin capacidades, Redis con contraseña, sin secretos por defecto.

## Pruebas y calidad

```bash
cd backend && go test -race ./...     # 84 tests: unitarios, integración HTTP y honeypot MySQL sobre TCP
cd frontend && pnpm exec tsc --noEmit && pnpm build
```
La CI (`.github/workflows/ci.yml`) ejecuta `gofmt`, `go vet`, los tests con `-race`, `govulncheck`, `pnpm audit`, `gitleaks` y la
construcción de las imágenes Docker.

## Limitaciones y uso responsable

- Los canaries detectan *contacto*; los escáneres de enlaces y los previsualizadores también pueden dispararlos (se etiquetan).
- Las huellas del navegador las aporta el cliente y son falsificables.
- El stack no termina TLS; usa un balanceador o el túnel.
- El bot de Telegram es compartido y no se verifica que el `chat_id` pertenezca a quien lo introduce.
- Hay un único token de operador estático (sin cuentas de usuario).
- **Privacidad**: el *slow redirect* y el *web bug* recogen la IP y la huella de terceros. Úsalos solo con una finalidad legítima de
  defensa, documenta la retención (`RETENTION_DAYS`) y cumple la normativa de privacidad aplicable (p. ej. RGPD).

## Licencia

[MIT](LICENSE).
