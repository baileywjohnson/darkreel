// Client-side cryptography using Web Crypto API
// All encryption/decryption happens in the browser — server never sees plaintext.

const CHUNK_SIZE = 1024 * 1024; // 1 MB — must match server
const ARGON2_PARAMS = { time: 3, mem: 65536, threads: 4, keyLen: 32 };

let _masterKey = null;
let _masterKeyRaw = null;

// Shape 2: X25519 keypair. Public key is used to seal per-file AES keys
// (browser uploads now use the same sealing path delegated clients use).
// Private key lives only as a non-extractable CryptoKey — even a successful
// XSS cannot exfiltrate the raw bytes, it can only use it for deriveBits.
let _privateKey = null;    // CryptoKey (non-extractable), X25519 deriveBits
let _publicKeyRaw = null;  // Uint8Array, 32 bytes, used to seal to self
const SEAL_INFO = new TextEncoder().encode('darkreel-seal-v1');
const SEAL_EPHPK_LEN = 32;
const SEAL_NONCE_LEN = 12;
const SEAL_TAG_LEN = 16;
const SEAL_OVERHEAD = SEAL_EPHPK_LEN + SEAL_NONCE_LEN + SEAL_TAG_LEN; // 60

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

// Install the user's X25519 keypair. privKeyBytes is zeroed as soon as it is
// imported as a non-extractable CryptoKey. pubKeyBytes stays around because
// uploads (including the user's own browser uploads) seal keys to the user's
// public key, so we need it in raw form for every upload.
//
// The Web Crypto X25519 spec accepts 'raw' ONLY for public keys; private keys
// must come in as JWK or PKCS#8. JWK is the least ceremony: two base64url
// fields with the raw scalar and matching public point.
export async function setKeypair(privKeyBytes, pubKeyBytes) {
    if (privKeyBytes.length !== 32) throw new Error('private key must be 32 bytes');
    if (pubKeyBytes.length !== 32) throw new Error('public key must be 32 bytes');
    _publicKeyRaw = new Uint8Array(pubKeyBytes);
    const jwk = {
        kty: 'OKP',
        crv: 'X25519',
        d: bytesToBase64Url(privKeyBytes),
        x: bytesToBase64Url(pubKeyBytes),
        ext: false,
        key_ops: ['deriveBits'],
    };
    _privateKey = await crypto.subtle.importKey(
        'jwk', jwk, { name: 'X25519' }, false, ['deriveBits']
    );
    // Zero the raw scalar buffer. The JWK object's `d` field is a JS string
    // and cannot be wiped — GC will eventually reclaim it. This is a minor
    // residue window vs. the raw buffer, inherent to the JWK import API.
    new Uint8Array(privKeyBytes.buffer, privKeyBytes.byteOffset, privKeyBytes.byteLength).fill(0);
}

function bytesToBase64Url(u8) {
    let binary = '';
    for (let i = 0; i < u8.length; i++) binary += String.fromCharCode(u8[i]);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function hasKeypair() {
    return _privateKey !== null;
}

export function getPublicKey() {
    return _publicKeyRaw;
}

export function clearKeypair() {
    _privateKey = null;
    if (_publicKeyRaw) _publicKeyRaw.fill(0);
    _publicKeyRaw = null;
}

// Derive a single-use AES-256-GCM key from an X25519 ECDH. Both seal and
// open call through here; X25519 is symmetric so whether "priv" is the
// ephemeral or the recipient private half, the shared secret is the same.
async function deriveSealCipherKey(privKey, peerPubBytes) {
    const peerPub = await crypto.subtle.importKey(
        'raw', peerPubBytes, { name: 'X25519' }, false, []
    );
    const sharedBits = await crypto.subtle.deriveBits(
        { name: 'X25519', public: peerPub }, privKey, 256
    );
    const hkdfKey = await crypto.subtle.importKey(
        'raw', sharedBits, 'HKDF', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: SEAL_INFO },
        hkdfKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

// Seal msg to recipientPubBytes. Output matches the server's SealBox format:
// ephemeral_pk(32) || nonce(12) || AES-256-GCM(derived_key, nonce, msg).
// Called per upload to wrap per-file/thumb/metadata AES keys; the recipient
// is the uploading user's own public key.
export async function sealTo(msg, recipientPubBytes) {
    if (recipientPubBytes.length !== 32) throw new Error('recipient pubkey must be 32 bytes');
    // Web Crypto generates extractable X25519 keypairs so we can export the
    // public half; the private half is used once for deriveBits and then
    // dropped along with the keypair when this function returns.
    const ephKp = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const ephPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', ephKp.publicKey));
    const aesKey = await deriveSealCipherKey(ephKp.privateKey, recipientPubBytes);
    const nonce = crypto.getRandomValues(new Uint8Array(SEAL_NONCE_LEN));
    const ct = new Uint8Array(await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce }, aesKey, msg
    ));
    const out = new Uint8Array(SEAL_EPHPK_LEN + SEAL_NONCE_LEN + ct.length);
    out.set(ephPubRaw, 0);
    out.set(nonce, SEAL_EPHPK_LEN);
    out.set(ct, SEAL_EPHPK_LEN + SEAL_NONCE_LEN);
    return out;
}

// Open a sealed box using the user's cached private key. Used on every view
// to recover per-file AES keys from the sealed blobs stored on the server.
export async function openSealed(sealed) {
    if (!_privateKey) throw new Error('keypair not loaded');
    if (sealed.length < SEAL_OVERHEAD) throw new Error('sealed blob too short');
    const ephPubBytes = sealed.subarray(0, SEAL_EPHPK_LEN);
    const nonce = sealed.subarray(SEAL_EPHPK_LEN, SEAL_EPHPK_LEN + SEAL_NONCE_LEN);
    const ct = sealed.subarray(SEAL_EPHPK_LEN + SEAL_NONCE_LEN);
    const aesKey = await deriveSealCipherKey(_privateKey, ephPubBytes);
    return new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce }, aesKey, ct
    ));
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

// Build chunk AAD: UTF-8(mediaId) || BigEndian(uint64(chunkIndex))
// This binds each chunk to its specific file and position, preventing both
// reordering and cross-file chunk substitution.
function buildChunkAAD(mediaId, chunkIndex) {
    const mediaIdBytes = new TextEncoder().encode(mediaId);
    const aad = new Uint8Array(mediaIdBytes.length + 8);
    aad.set(mediaIdBytes, 0);
    new DataView(aad.buffer, aad.byteOffset).setBigUint64(mediaIdBytes.length, BigInt(chunkIndex));
    return aad;
}

// Encrypt a chunk with AAD (mediaId + chunk index)
export async function encryptChunk(plaintext, keyBytes, chunkIndex, mediaId) {
    const key = await crypto.subtle.importKey(
        'raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aad = buildChunkAAD(mediaId, chunkIndex);

    const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: aad }, key, plaintext
    ));
    const result = new Uint8Array(12 + ciphertext.length);
    result.set(iv, 0);
    result.set(ciphertext, 12);
    return result;
}

// Decrypt a chunk with AAD (mediaId + chunk index)
export async function decryptChunk(data, keyBytes, chunkIndex, mediaId) {
    const key = await crypto.subtle.importKey(
        'raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']
    );
    const iv = data.slice(0, 12);
    const ciphertext = data.slice(12);
    const aad = buildChunkAAD(mediaId, chunkIndex);

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
export async function encryptFile(fileData, fileKey, mediaId) {
    const chunks = [];
    const totalChunks = Math.ceil(fileData.length / CHUNK_SIZE);

    for (let i = 0; i < totalChunks; i++) {
        const start = i * CHUNK_SIZE;
        const end = Math.min(start + CHUNK_SIZE, fileData.length);
        const chunk = fileData.slice(start, end);
        const encrypted = await encryptChunk(chunk, fileKey, i, mediaId);
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
    // Unsupported format — throw instead of silently appending
    throw new Error('Hash modification not supported for: ' + mimeType);
}

function modifyMP4(data, nonce) {
    // Append a 'free' box at the END of the file.
    // Inserting before moov would corrupt stco/co64 byte offsets.
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
    result.set(data, 0);
    result.set(freeBox, data.length);
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
        const len = ((data[pos] << 24) | (data[pos+1] << 16) | (data[pos+2] << 8) | data[pos+3]) >>> 0;
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
