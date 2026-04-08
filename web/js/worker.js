// Decryption Web Worker — runs AES-256-GCM decryption off the main thread.

self.onmessage = async function(e) {
    const { type, id, data, keyBytes, chunkIndex, mediaId, aad } = e.data;

    try {
        if (type === 'decryptChunk') {
            const result = await decryptChunk(data, keyBytes, chunkIndex, mediaId);
            self.postMessage({ id, result }, [result.buffer]);
        } else if (type === 'decryptBlock') {
            const result = await decryptBlock(data, keyBytes, aad);
            self.postMessage({ id, result }, [result.buffer]);
        }
    } catch (err) {
        self.postMessage({ id, error: err.message });
    }
};

// Build chunk AAD: UTF-8(mediaId) || BigEndian(uint64(chunkIndex))
function buildChunkAAD(mediaId, chunkIndex) {
    const mediaIdBytes = new TextEncoder().encode(mediaId);
    const aad = new Uint8Array(mediaIdBytes.length + 8);
    aad.set(mediaIdBytes, 0);
    new DataView(aad.buffer, aad.byteOffset).setBigUint64(mediaIdBytes.length, BigInt(chunkIndex));
    return aad;
}

async function decryptChunk(data, keyBytes, chunkIndex, mediaId) {
    const key = await crypto.subtle.importKey(
        'raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']
    );
    const iv = data.slice(0, 12);
    const ciphertext = data.slice(12);
    const chunkAad = buildChunkAAD(mediaId, chunkIndex);

    return new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: chunkAad }, key, ciphertext
    ));
}

async function decryptBlock(data, keyBytes, aad) {
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
