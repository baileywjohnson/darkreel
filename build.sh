#!/bin/bash
set -e

cd "$(dirname "$0")"

# Generate SRI hashes for web assets
CSS_HASH="sha384-$(openssl dgst -sha384 -binary web/css/app.css | openssl base64 -A)"
CRYPTO_HASH="sha384-$(openssl dgst -sha384 -binary web/js/crypto.js | openssl base64 -A)"
MP4BOX_HASH="sha384-$(openssl dgst -sha384 -binary web/js/vendor/mp4box.min.js | openssl base64 -A)"

# Inject mp4box.js SRI hash into app.js BEFORE computing app.js hash,
# so the hash in index.html matches the final embedded file content.
perl -i -pe "s|MP4BOX_SRI = '[^']*'|MP4BOX_SRI = '${MP4BOX_HASH}'|" web/js/app.js

APP_HASH="sha384-$(openssl dgst -sha384 -binary web/js/app.js | openssl base64 -A)"

# Generate short content hashes for cache-busting query parameters.
# When file content changes, the ?v= param changes, busting browser caches.
CSS_VER=$(openssl dgst -sha256 -binary web/css/app.css | xxd -p -l 8)
CRYPTO_VER=$(openssl dgst -sha256 -binary web/js/crypto.js | xxd -p -l 8)
APP_VER=$(openssl dgst -sha256 -binary web/js/app.js | xxd -p -l 8)

# Update integrity attributes and cache-busting version params in index.html.
# Match lines by their src/href filename, replace integrity and add/update ?v= param.
perl -i -pe "s|href=\"/css/app\.css(\?v=[a-f0-9]+)?\"(.*?)integrity=\"sha384-[A-Za-z0-9+/=]+\"|href=\"/css/app.css?v=${CSS_VER}\"\2integrity=\"${CSS_HASH}\"|" web/index.html
perl -i -pe "s|src=\"/js/crypto\.js(\?v=[a-f0-9]+)?\"(.*?)integrity=\"sha384-[A-Za-z0-9+/=]+\"|src=\"/js/crypto.js?v=${CRYPTO_VER}\"\2integrity=\"${CRYPTO_HASH}\"|" web/index.html
perl -i -pe "s|src=\"/js/app\.js(\?v=[a-f0-9]+)?\"(.*?)integrity=\"sha384-[A-Za-z0-9+/=]+\"|src=\"/js/app.js?v=${APP_VER}\"\2integrity=\"${APP_HASH}\"|" web/index.html

echo "SRI hashes updated:"
echo "  app.css:    ${CSS_HASH}"
echo "  crypto.js:  ${CRYPTO_HASH}"
echo "  mp4box.js:  ${MP4BOX_HASH}"
echo "  app.js:     ${APP_HASH}"
echo "Cache-bust versions:"
echo "  app.css:    ${CSS_VER}"
echo "  crypto.js:  ${CRYPTO_VER}"
echo "  app.js:     ${APP_VER}"

# Verify module checksums against go.sum before building
go mod verify

# Build Go binary
go build -o darkreel .
echo "Build complete: ./darkreel"
