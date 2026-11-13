import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import express, { type Express } from 'express'
import { config } from './config.js'

/**
 * Entrega la web (la carpeta compilada de /web) desde este mismo servidor. Asi la web y la API comparten origen:
 * no hace falta un proxy en medio (el de Vercel tropezaba con el limite de Hostinger), ni CORS, y la cookie de sesion
 * viaja igual que siempre. Si la carpeta no existe (desarrollo: la web corre en Vite) no se monta nada.
 */

const hasSite = fs.existsSync(path.join(config.staticDir, 'index.html'))

/** Hashes CSP de los scripts en linea de las paginas (por ejemplo el que fija el tema antes del primer dibujo). */
export function inlineScriptHashes(): string[] {
  if (!hasSite) return []
  const hashes = new Set<string>()
  for (const file of fs.readdirSync(config.staticDir).filter((f) => f.endsWith('.html'))) {
    const html = fs.readFileSync(path.join(config.staticDir, file), 'utf8')
    for (const match of html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)) {
      hashes.add(`'sha256-${crypto.createHash('sha256').update(match[1]).digest('base64')}'`)
    }
  }
  return [...hashes]
}

/** Va despues de las rutas /api: lo que no sea API se busca en la carpeta de la web. */
export function mountSite(app: Express): void {
  if (!hasSite) return

  app.use(
    express.static(config.staticDir, {
      // /login -> login.html, /crm -> crm.html, /world -> world.html (las mismas URLs limpias que daba Vercel).
      extensions: ['html'],
      index: 'index.html',
      setHeaders(res, file) {
        // Los archivos de /assets llevan el hash en el nombre: nunca cambian. Las paginas se revalidan siempre.
        res.setHeader(
          'Cache-Control',
          file.includes(`${path.sep}assets${path.sep}`) ? 'public, max-age=31536000, immutable' : 'no-cache',
        )
      },
    }),
  )

  app.use((_req, res) => {
    res.status(404).type('text/plain').send('No encontrado')
  })
}
