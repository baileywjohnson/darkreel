#!/bin/bash
set -e

cd "$(dirname "$0")"

# Generate SRI hashes for web assets
CSS_HASH="sha384-$(openssl dgst -sha384 -binary web/css/app.css | openssl base64 -A)"
CRYPTO_HASH="sha384-$(openssl dgst -sha384 -binary web/js/crypto.js | openssl base64 -A)"
MP4BOX_HASH="sha384-$(openssl dgst -sha384 -binary web/js/vendor/mp4box.min.js | openssl base64 -A)"
APP_HASH="sha384-$(openssl dgst -sha384 -binary web/js/app.js | openssl base64 -A)"

# Update integrity attributes in index.html
# Match lines by their src/href filename, replace the integrity value
perl -i -pe "s|(href=\"/css/app\.css\".*?integrity=\")sha384-[A-Za-z0-9+/=]+|\1${CSS_HASH}|" web/index.html
perl -i -pe "s|(src=\"/js/crypto\.js\".*?integrity=\")sha384-[A-Za-z0-9+/=]+|\1${CRYPTO_HASH}|" web/index.html
perl -i -pe "s|(src=\"/js/app\.js\".*?integrity=\")sha384-[A-Za-z0-9+/=]+|\1${APP_HASH}|" web/index.html

# Inject mp4box.js SRI hash into app.js for dynamic loading
perl -i -pe "s|MP4BOX_SRI = '[^']*'|MP4BOX_SRI = '${MP4BOX_HASH}'|" web/js/app.js

echo "SRI hashes updated:"
echo "  app.css:    ${CSS_HASH}"
echo "  crypto.js:  ${CRYPTO_HASH}"
echo "  mp4box.js:  ${MP4BOX_HASH}"
echo "  app.js:     ${APP_HASH}"

# Build Go binary
go build -o darkreel .
echo "Build complete: ./darkreel"
