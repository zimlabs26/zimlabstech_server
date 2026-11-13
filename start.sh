#!/bin/sh
# Arranque para Render GRATIS (sin disco persistente).
#
# El disco del plan gratis se borra en cada reinicio, y la base es un archivo SQLite. Litestream lo resuelve:
#   1. al arrancar, RESTAURA la base desde un almacenamiento gratuito (si ya hay una copia);
#   2. mientras el servidor corre, COPIA los cambios a ese almacenamiento cada segundo.
# Asi las cuentas y los datos sobreviven a reinicios, a dormirse por inactividad y a los deploys.
set -e

export DB_PATH="${DB_PATH:-$(pwd)/data/app.db}"
export LITESTREAM_REGION="${LITESTREAM_REGION:-us-east-1}"
mkdir -p "$(dirname "$DB_PATH")"

if [ -z "$LITESTREAM_BUCKET" ] || [ ! -x ./bin/litestream ]; then
  echo "AVISO: sin respaldo (falta LITESTREAM_BUCKET o el binario de Litestream)."
  echo "AVISO: la base se PIERDE cada vez que Render reinicia el servicio."
  exec node dist/index.js
fi

# Primera vez: no hay copia todavia y se empieza con una base nueva. Despues: se recupera la ultima copia.
./bin/litestream restore -config litestream.yml -if-db-not-exists -if-replica-exists "$DB_PATH"

# Litestream arranca el servidor como proceso hijo, sigue copiando y, al apagarse Render, hace una ultima copia.
exec ./bin/litestream replicate -config litestream.yml -exec "node dist/index.js"
