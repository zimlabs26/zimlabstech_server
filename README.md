# Zimlabs Server

API del CRM (Node + Express + SQLite). La web vive en otro repositorio (`zimlabstech_page`) y llama a esta API.

La base de datos usa el SQLite incluido en Node (`node:sqlite`), sin modulos nativos. Requiere Node 22.13 o mas.

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

En un hosting sin consola se puede usar `BOOTSTRAP_SUPER_EMAIL` y `BOOTSTRAP_SUPER_PASSWORD` (ver abajo).

## Hostinger (Node.js Web App)

| Campo | Valor |
| --- | --- |
| Node.js | 22.x |
| Build command | `npm run build` |
| Entry file | `server.js` (ya existe en la raiz y arranca `dist/index.js`) |

Variables de entorno:

| Variable | Valor |
| --- | --- |
| `NODE_ENV` | `production` (activa las cookies solo HTTPS) |
| `WEB_ORIGIN` | Direccion exacta de la web, sin barra final (por ejemplo `https://zimlabstech.com`) |
| `PUBLIC_URL` | Direccion publica de la web (adonde vuelve el cliente despues de activar el debito) |
| `DB_PATH` | **Ruta absoluta FUERA de la carpeta de la app**, por ejemplo `/home/USUARIO/domains/server.zimlabstech.com/data/app.db`. Hostinger crea una carpeta nueva en cada deploy: si la base queda dentro, se pierde |
| `TRUST_PROXY` | Cuantos proxies hay delante del servidor (por defecto 1 en produccion) |
| `BOOTSTRAP_SUPER_EMAIL` / `BOOTSTRAP_SUPER_PASSWORD` | Crean el super admin solo si la base esta vacia; borra la contrasena despues del primer ingreso |
| `MP_ACCESS_TOKEN` / `MP_WEBHOOK_SECRET` | Mercado Pago (debito automatico). Nunca los subas al repositorio |
| `MAIL_USER` / `MAIL_PASS` / `MAIL_FROM_NAME` | Correo saliente (Gmail con contrasena de aplicacion). Opcional |

La carpeta `data/` de `DB_PATH` queda fuera de `public_html`, asi que la base no se sirve por web.

### Respaldo de la base

La base es un archivo SQLite en modo WAL. Para copiarla en caliente hay que llevar `app.db`, `app.db-wal` y
`app.db-shm` juntos, o abrir la copia con SQLite y ejecutar `PRAGMA wal_checkpoint(TRUNCATE)` para dejar todo en `app.db`.

## Como se conecta la web

La web (`https://zimlabstech.com`) y el servidor (`https://server.zimlabstech.com`) son sitios distintos pero del
mismo dominio, asi que la cookie de sesion (`HttpOnly`, `SameSite=Lax`) viaja entre ellos. La web llama al servidor
directo (`VITE_API_URL` al compilar) y el servidor acepta ese origen por CORS (`WEB_ORIGIN`).

Las passkeys quedan ligadas al dominio de la web que las registra.

El tiempo real usa Server-Sent Events (`GET /api/events`); si el proxy corta la conexion, el navegador reconecta solo y
la pantalla se pone al dia.
