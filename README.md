# Zimlabs Server

API del CRM (Node + Express + SQLite). La web vive en otro repositorio y llama a esta API.

## Desarrollo local

```bash
npm install
cp .env.example .env     # ajusta WEB_ORIGIN si hace falta
npm run dev              # http://localhost:3000
```

## Crear la primera cuenta

No hay registro publico: las cuentas se crean con acceso al servidor.

```bash
npm run user -- create tu@correo.com --admin   # pide la contrasena (minimo 12 caracteres)
npm run user -- super tu@correo.com            # la define como unico super admin
npm run user -- list
```

## Hostinger (Node.js Web App)

| Campo | Valor |
| --- | --- |
| Node.js | 22 |
| Build command | `npm run build` |
| Entry file | `server.js` (ya existe en la raiz y arranca `dist/index.js`) |

Variables de entorno:

| Variable | Valor |
| --- | --- |
| `NODE_ENV` | `production` |
| `WEB_ORIGIN` | Direccion exacta de la web, sin barra final (por ejemplo `https://zimerman-web.vercel.app`) |
| `TRUST_PROXY` | `2` si la web reenvia `/api` hacia este servidor (Vercel + hosting) |
| `DB_PATH` | **Ruta absoluta FUERA de la carpeta de la app**, por ejemplo `/home/USUARIO/zimerman-data/app.db`, asi un nuevo deploy no borra la base |
| `BOOTSTRAP_SUPER_EMAIL` / `BOOTSTRAP_SUPER_PASSWORD` | Crean el super admin en el primer arranque; borra la contrasena despues |

El disco de Hostinger es persistente: no hace falta Litestream ni `LITESTREAM_*`.

## Render gratis (sin disco de pago)

El plan gratis de Render borra el disco en cada reinicio, y la base es un archivo SQLite. **Litestream** lo resuelve:
copia la base en vivo (cada segundo) a un almacenamiento gratuito y la restaura sola cuando el servicio arranca.

| Campo | Valor |
| --- | --- |
| Tipo / plan | Web Service (Node), **Free** |
| Build Command | `npm install --include=dev && npm run build && sh scripts/get-litestream.sh` |
| Start Command | `sh start.sh` |
| Health Check Path | `/api/health` |
| Disco | ninguno (no se necesita) |

Variables de entorno:

| Variable | Valor |
| --- | --- |
| `NODE_VERSION` | `22` |
| `NODE_ENV` | `production` |
| `TRUST_PROXY` | `2` si la web reenvia `/api` hacia Render (Vercel + Render); `1` si la web llama directo a Render |
| `WEB_ORIGIN` | La direccion exacta de la web, sin barra final (por ejemplo `https://tu-sitio.vercel.app`) |
| `LITESTREAM_BUCKET` | Nombre del bucket (Backblaze B2) |
| `LITESTREAM_ENDPOINT` | Endpoint S3 del bucket, por ejemplo `https://s3.us-west-004.backblazeb2.com` |
| `LITESTREAM_REGION` | La region del endpoint, por ejemplo `us-west-004` |
| `LITESTREAM_ACCESS_KEY_ID` | keyID de la Application Key |
| `LITESTREAM_SECRET_ACCESS_KEY` | applicationKey (se muestra una sola vez) |

`render.yaml` deja todo esto como plantilla (Blueprint). No definas `DB_PATH`: por defecto usa `./data/app.db`.

### Respaldo gratis en Backblaze B2 (10 GB, sin tarjeta)

1. Crea una cuenta en backblaze.com y entra a **B2 Cloud Storage**.
2. **Buckets > Create a Bucket**: nombre unico (por ejemplo `zimerman-db-tunombre`), **Private**.
3. **Application Keys > Add a New Application Key**: limitala a ese bucket, permiso Read and Write. Copia el **keyID** y la **applicationKey**.
4. El **endpoint** aparece en los datos del bucket (`s3.<region>.backblazeb2.com`); la region es la parte `<region>`.

### Primera cuenta (el plan gratis no tiene Shell)

En el primer arranque, con la base vacia, el servidor crea el super admin si estan definidas estas dos variables:

| Variable | Valor |
| --- | --- |
| `BOOTSTRAP_SUPER_EMAIL` | tu correo |
| `BOOTSTRAP_SUPER_PASSWORD` | una contrasena de 12 caracteres o mas |

Despues de entrar por primera vez, **borra `BOOTSTRAP_SUPER_PASSWORD` del panel de Render** (si la base ya tiene
cuentas, esas variables no hacen nada, pero la contrasena no deberia quedar guardada ahi).

### Cosas a saber del plan gratis

- El servicio **se duerme tras 15 minutos sin visitas** y la primera visita tarda cerca de un minuto en despertarlo.
  Un monitor gratuito (por ejemplo UptimeRobot) que visite `/api/health` cada 5 minutos lo mantiene despierto.
- Al dormirse se corta la conexion en vivo; el navegador reconecta solo y la pantalla se pone al dia.
- La base se restaura sola al despertar. Lo unico que se podria perder es lo escrito en el ultimo segundo antes de un
  corte brusco (Litestream copia cada segundo y hace una ultima copia al apagarse con normalidad).
- Sin las variables `LITESTREAM_*` el servidor igual arranca, pero **sin respaldo**: la base se pierde al reiniciar.
  El log lo avisa.

## Como se conecta la web

El navegador debe hablar con la API **desde el mismo dominio que la web**: la cookie de sesion es `SameSite=Lax` y
`HttpOnly`, y un dominio distinto la bloquearia. En Vercel se logra reenviando `/api` a Render con un rewrite en
`vercel.json`:

```json
{ "rewrites": [{ "source": "/api/:path*", "destination": "https://TU-SERVICIO.onrender.com/api/:path*" }] }
```

El tiempo real usa Server-Sent Events (`GET /api/events`); si el proxy corta la conexion, el navegador reconecta solo y
la pantalla se pone al dia.
