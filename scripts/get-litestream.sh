#!/bin/sh
# Descarga el binario de Litestream (Linux) durante el build de Render. Version fija para que el build sea repetible.
set -e
VERSION="0.3.13"
mkdir -p bin
curl -fsSL "https://github.com/benbjohnson/litestream/releases/download/v${VERSION}/litestream-v${VERSION}-linux-amd64.tar.gz" \
  | tar -xz -C bin litestream
chmod +x bin/litestream
./bin/litestream version
