/**
 * ZIP minimo (sin compresion): alcanza para juntar varios CSV en una sola descarga, sin sumar dependencias.
 * Los nombres van en UTF-8 y se abre con cualquier programa (Windows, macOS, Linux).
 */

const table = (() => {
  const out = new Uint32Array(256)
  for (let n = 0; n < 256; n++) {
    let c = n
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    out[n] = c >>> 0
  }
  return out
})()

export function crc32(buf: Buffer): number {
  let c = 0xffffffff
  for (const byte of buf) c = table[(c ^ byte) & 0xff] ^ (c >>> 8)
  return (c ^ 0xffffffff) >>> 0
}

function dosDateTime(d: Date): { time: number; date: number } {
  return {
    time: (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1),
    date: ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate(),
  }
}

export function createZip(files: { name: string; data: Buffer }[], when = new Date()): Buffer {
  const parts: Buffer[] = []
  const central: Buffer[] = []
  const { time, date } = dosDateTime(when)
  let offset = 0

  for (const file of files) {
    const name = Buffer.from(file.name, 'utf8')
    const crc = crc32(file.data)
    const size = file.data.length

    const local = Buffer.alloc(30)
    local.writeUInt32LE(0x04034b50, 0) // firma del encabezado local
    local.writeUInt16LE(20, 4) // version necesaria
    local.writeUInt16LE(0x0800, 6) // nombres en UTF-8
    local.writeUInt16LE(0, 8) // sin compresion
    local.writeUInt16LE(time, 10)
    local.writeUInt16LE(date, 12)
    local.writeUInt32LE(crc, 14)
    local.writeUInt32LE(size, 18)
    local.writeUInt32LE(size, 22)
    local.writeUInt16LE(name.length, 26)
    local.writeUInt16LE(0, 28)
    parts.push(local, name, file.data)

    const entry = Buffer.alloc(46)
    entry.writeUInt32LE(0x02014b50, 0) // firma del directorio central
    entry.writeUInt16LE(20, 4)
    entry.writeUInt16LE(20, 6)
    entry.writeUInt16LE(0x0800, 8)
    entry.writeUInt16LE(0, 10)
    entry.writeUInt16LE(time, 12)
    entry.writeUInt16LE(date, 14)
    entry.writeUInt32LE(crc, 16)
    entry.writeUInt32LE(size, 20)
    entry.writeUInt32LE(size, 24)
    entry.writeUInt16LE(name.length, 28)
    entry.writeUInt32LE(offset, 42)
    central.push(entry, name)

    offset += 30 + name.length + size
  }

  const directory = Buffer.concat(central)
  const end = Buffer.alloc(22)
  end.writeUInt32LE(0x06054b50, 0) // fin del directorio central
  end.writeUInt16LE(files.length, 8)
  end.writeUInt16LE(files.length, 10)
  end.writeUInt32LE(directory.length, 12)
  end.writeUInt32LE(offset, 16)
  return Buffer.concat([...parts, directory, end])
}
