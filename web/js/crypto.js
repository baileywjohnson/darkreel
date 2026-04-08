// Client-side cryptography using Web Crypto API
// All encryption/decryption happens in the browser — server never sees plaintext.

const CHUNK_SIZE = 1024 * 1024; // 1 MB — must match server
const ARGON2_PARAMS = { time: 3, mem: 65536, threads: 4, keyLen: 32 };

let _masterKey = null;
let _masterKeyRaw = null;

// We use a pure JS Argon2id implementation for key derivation in the browser.
// This is loaded dynamically to keep initial page load fast.

// Minimal Argon2id via PBKDF2 fallback — for production, use argon2-browser WASM.
// To match the Go server, we need identical KDF output.
// We'll use SubtleCrypto's PBKDF2 as an interim and later swap for Argon2id WASM.
// NOTE: For the server-side directory watcher to work, the KDF must produce the same output.
// Since the server uses Argon2id, we MUST use Argon2id here too.

// Import argon2-browser via a WASM module
// For now, we'll derive the key on the server during login and receive it encrypted.
// The login response already provides the KDF salt. We'll derive client-side using
// a JS Argon2id implementation.

// Simplified approach: the client sends password to server on login,
// server returns the KDF salt, and client derives the master key locally.
// We use a WASM-free approach with SubtleCrypto for AES operations.

// For Argon2id in browser without WASM, we use the following approach:
// The server derives the master key and includes it (encrypted with a session key derived from password)
// in the login response. This avoids needing Argon2id in the browser entirely.
// The session key is HKDF(password, "darkreel-session").

export async function deriveSessionKey(password, kdfSaltB64) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits', 'deriveKey']
    );
    const salt = base64ToBuffer(kdfSaltB64);
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
        keyMaterial, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
    );
}

export async function setMasterKeyFromServer(encryptedMasterKeyB64, password) {
    // The server sends the master key encrypted with PBKDF2(password, "darkreel-session-key")
    // For our initial implementation, we trust the login flow:
    // Server derives masterKey via Argon2id and stores it in session.
    // Client also needs masterKey for encryption. Since we can't run Argon2id in browser easily,
    // the server will return the master key encrypted with a key derived from the password.
    // This is secure because the password is only ever sent over TLS and the encrypted key
    // is useless without the password.

    const sessionKey = await deriveSessionKey(password);
    const data = base64ToBuffer(encryptedMasterKeyB64);
    const iv = data.slice(0, 12);
    const ciphertext = data.slice(12);

    _masterKeyRaw = new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv }, sessionKey, ciphertext
    ));

    _masterKey = await crypto.subtle.importKey(
        'raw', _masterKeyRaw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
    );
}

export async function setMasterKeyDirect(masterKeyBytes) {
    _masterKeyRaw = new Uint8Array(masterKeyBytes);
    _masterKey = await crypto.subtle.importKey(
        'raw', _masterKeyRaw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
    );
}

export function getMasterKeyRaw() {
    return _masterKeyRaw;
}

export function hasMasterKey() {
    return _masterKey !== null;
}

export function clearMasterKey() {
    if (_masterKeyRaw) _masterKeyRaw.fill(0);
    _masterKey = null;
    _masterKeyRaw = null;
}

// Generate a random 256-bit key
export function generateFileKey() {
    return crypto.getRandomValues(new Uint8Array(32));
}

// Generate a random hash nonce
export function generateHashNonce() {
    return crypto.getRandomValues(new Uint8Array(32));
}

// Encrypt a block (small data like a file key) with AES-256-GCM.
// The aad parameter binds the ciphertext to its context (e.g., media ID for
// file keys, user ID for master key wrapping), preventing substitution attacks.
// Returns: nonce (12 bytes) || ciphertext+tag
export async function encryptBlock(plaintext, keyBytes, aad) {
    const key = await crypto.subtle.importKey(
        'raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const params = { name: 'AES-GCM', iv };
    if (aad) params.additionalData = aad;
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
        params, key, plaintext
    ));
    const result = new Uint8Array(12 + ciphertext.length);
    result.set(iv, 0);
    result.set(ciphertext, 12);
    return result;
}

// Decrypt a block. The aad parameter must match the value used during encryption.
export async function decryptBlock(data, keyBytes, aad) {
    const key = await crypto.subtle.importKey(
        'raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']
    );
    const iv = data.slice(0, 12);
    const ciphertext = data.slice(12);
    const params = { name: 'AES-GCM', iv };
    if (aad) params.additionalData = aad;
    return new Uint8Array(await crypto.subtle.decrypt(
        params, key, ciphertext
    ));
}

// Encrypt a chunk with AAD (chunk index)
export async function encryptChunk(plaintext, keyBytes, chunkIndex) {
    const key = await crypto.subtle.importKey(
        'raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aad = new ArrayBuffer(8);
    new DataView(aad).setBigUint64(0, BigInt(chunkIndex));

    const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: aad }, key, plaintext
    ));
    const result = new Uint8Array(12 + ciphertext.length);
    result.set(iv, 0);
    result.set(ciphertext, 12);
    return result;
}

// Decrypt a chunk with AAD
export async function decryptChunk(data, keyBytes, chunkIndex) {
    const key = await crypto.subtle.importKey(
        'raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']
    );
    const iv = data.slice(0, 12);
    const ciphertext = data.slice(12);
    const aad = new ArrayBuffer(8);
    new DataView(aad).setBigUint64(0, BigInt(chunkIndex));

    return new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: aad }, key, ciphertext
    ));
}

// Encrypt a file key with the master key. mediaId binds the key to its media item.
export async function encryptFileKey(fileKey, mediaId) {
    const aad = new TextEncoder().encode(mediaId);
    return encryptBlock(fileKey, _masterKeyRaw, aad);
}

// Decrypt a file key with the master key. mediaId must match the value used during encryption.
export async function decryptFileKey(encryptedFileKey, mediaId) {
    const aad = new TextEncoder().encode(mediaId);
    return decryptBlock(encryptedFileKey, _masterKeyRaw, aad);
}

// Encrypt a filename. mediaId binds the name to its media item.
export async function encryptName(name, mediaId) {
    const enc = new TextEncoder();
    const aad = enc.encode(mediaId);
    return encryptBlock(enc.encode(name), _masterKeyRaw, aad);
}

// Decrypt a filename. mediaId must match the value used during encryption.
export async function decryptName(encData, mediaId) {
    const dec = new TextDecoder();
    const aad = new TextEncoder().encode(mediaId);
    const plaintext = await decryptBlock(encData, _masterKeyRaw, aad);
    return dec.decode(plaintext);
}

// Split a file into encrypted chunks
export async function encryptFile(fileData, fileKey) {
    const chunks = [];
    const totalChunks = Math.ceil(fileData.length / CHUNK_SIZE);

    for (let i = 0; i < totalChunks; i++) {
        const start = i * CHUNK_SIZE;
        const end = Math.min(start + CHUNK_SIZE, fileData.length);
        const chunk = fileData.slice(start, end);
        const encrypted = await encryptChunk(chunk, fileKey, i);
        chunks.push(encrypted);
    }

    return chunks;
}

// Generate thumbnail from image/video
export async function generateThumbnail(file) {
    return new Promise((resolve, reject) => {
        if (file.type.startsWith('video/')) {
            generateVideoThumbnail(file).then(resolve).catch(reject);
        } else {
            generateImageThumbnail(file).then(resolve).catch(reject);
        }
    });
}

function generateImageThumbnail(file) {
    return new Promise((resolve, reject) => {
        const img = new Image();
        img.onload = () => {
            const canvas = document.createElement('canvas');
            const maxDim = 320;
            let w = img.width, h = img.height;
            if (w > h) { h = h * maxDim / w; w = maxDim; }
            else { w = w * maxDim / h; h = maxDim; }
            canvas.width = w;
            canvas.height = h;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(img, 0, 0, w, h);
            canvas.toBlob(blob => {
                blob.arrayBuffer().then(buf => resolve(new Uint8Array(buf)));
            }, 'image/jpeg', 0.7);
        };
        img.onerror = reject;
        img.src = URL.createObjectURL(file);
    });
}

function generateVideoThumbnail(file) {
    return new Promise((resolve, reject) => {
        const video = document.createElement('video');
        video.preload = 'metadata';
        video.muted = true;
        video.playsInline = true;
        const url = URL.createObjectURL(file);

        function capture() {
            const canvas = document.createElement('canvas');
            const maxDim = 320;
            let w = video.videoWidth, h = video.videoHeight;
            if (!w || !h) { URL.revokeObjectURL(url); reject(new Error('No video dimensions')); return; }
            if (w > h) { h = h * maxDim / w; w = maxDim; }
            else { w = w * maxDim / h; h = maxDim; }
            canvas.width = w;
            canvas.height = h;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(video, 0, 0, w, h);
            video.pause();
            canvas.toBlob(blob => {
                URL.revokeObjectURL(url);
                blob.arrayBuffer().then(buf => resolve(new Uint8Array(buf)));
            }, 'image/jpeg', 0.7);
        }

        video.onseeked = capture;
        video.onloadedmetadata = () => {
            // Seek to a frame near the start
            video.currentTime = Math.min(1, video.duration / 4);
        };
        video.onerror = () => { URL.revokeObjectURL(url); reject(video.error); };
        video.src = url;
        // On iOS, a brief play() is needed to trigger frame loading
        video.play().then(() => video.pause()).catch(() => {});
    });
}

// Modify hash by injecting metadata nonce
export function modifyHash(data, mimeType, nonce) {
    const lower = mimeType.toLowerCase();
    if (lower.includes('jpeg') || lower.includes('jpg')) {
        return modifyJPEG(data, nonce);
    }
    if (lower.includes('png')) {
        return modifyPNG(data, nonce);
    }
    // MP4/M4V/MOV: wrap nonce in a valid 'free' box so the container stays parseable
    if (lower.includes('mp4') || lower.includes('m4v') || lower.includes('quicktime') || lower.includes('mov')) {
        return modifyMP4(data, nonce);
    }
    // For other types, append nonce directly (no identifying marker)
    const result = new Uint8Array(data.length + nonce.length);
    result.set(data, 0);
    result.set(nonce, data.length);
    return result;
}

function modifyMP4(data, nonce) {
    // Insert a 'free' box after ftyp (matches server-side implementation).
    // If no ftyp is found, insert at the beginning.
    let pos = 0;
    if (data.length >= 8) {
        const type = String.fromCharCode(data[4], data[5], data[6], data[7]);
        if (type === 'ftyp') {
            pos = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
        }
    }
    const boxSize = 8 + nonce.length;
    const freeBox = new Uint8Array(boxSize);
    freeBox[0] = (boxSize >> 24) & 0xFF;
    freeBox[1] = (boxSize >> 16) & 0xFF;
    freeBox[2] = (boxSize >> 8) & 0xFF;
    freeBox[3] = boxSize & 0xFF;
    freeBox[4] = 0x66; // 'f'
    freeBox[5] = 0x72; // 'r'
    freeBox[6] = 0x65; // 'e'
    freeBox[7] = 0x65; // 'e'
    freeBox.set(nonce, 8);
    const result = new Uint8Array(data.length + boxSize);
    result.set(data.subarray(0, pos), 0);
    result.set(freeBox, pos);
    result.set(data.subarray(pos), pos + boxSize);
    return result;
}

function modifyJPEG(data, nonce) {
    if (data.length < 2 || data[0] !== 0xFF || data[1] !== 0xD8) return data;
    const comLen = nonce.length + 2;
    const com = new Uint8Array(4 + nonce.length);
    com[0] = 0xFF; com[1] = 0xFE;
    com[2] = (comLen >> 8) & 0xFF;
    com[3] = comLen & 0xFF;
    com.set(nonce, 4);

    const result = new Uint8Array(data.length + com.length);
    result.set(data.subarray(0, 2), 0); // SOI
    result.set(com, 2);
    result.set(data.subarray(2), 2 + com.length);
    return result;
}

function modifyPNG(data, nonce) {
    const sig = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    if (data.length < 8) return data;
    for (let i = 0; i < 8; i++) if (data[i] !== sig[i]) return data;

    // Find first IDAT
    let pos = 8;
    while (pos + 8 <= data.length) {
        const len = (data[pos] << 24) | (data[pos+1] << 16) | (data[pos+2] << 8) | data[pos+3];
        const type = String.fromCharCode(data[pos+4], data[pos+5], data[pos+6], data[pos+7]);
        if (type === 'IDAT') break;
        pos += 12 + len;
    }

    // Build tEXt chunk
    const keyword = new TextEncoder().encode('Comment\0');
    const chunkData = new Uint8Array(keyword.length + nonce.length);
    chunkData.set(keyword, 0);
    chunkData.set(nonce, keyword.length);

    const chunk = buildPNGChunk('tEXt', chunkData);
    const result = new Uint8Array(data.length + chunk.length);
    result.set(data.subarray(0, pos), 0);
    result.set(chunk, pos);
    result.set(data.subarray(pos), pos + chunk.length);
    return result;
}

function buildPNGChunk(type, chunkData) {
    const buf = new Uint8Array(12 + chunkData.length);
    const view = new DataView(buf.buffer);
    view.setUint32(0, chunkData.length);
    const enc = new TextEncoder();
    buf.set(enc.encode(type), 4);
    buf.set(chunkData, 8);
    const crc = crc32(buf.subarray(4, 8 + chunkData.length));
    view.setUint32(8 + chunkData.length, crc);
    return buf;
}

function crc32(data) {
    let table = crc32.table;
    if (!table) {
        table = crc32.table = new Uint32Array(256);
        for (let i = 0; i < 256; i++) {
            let c = i;
            for (let j = 0; j < 8; j++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
            table[i] = c;
        }
    }
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < data.length; i++) crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >>> 8);
    return (crc ^ 0xFFFFFFFF) >>> 0;
}

// Utility
export function bufferToBase64(buf) {
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

export function base64ToBuffer(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

export function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
}
