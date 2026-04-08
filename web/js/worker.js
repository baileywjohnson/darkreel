// Decryption Web Worker — runs AES-256-GCM decryption off the main thread.

self.onmessage = async function(e) {
    const { type, id, data, keyBytes, chunkIndex, aad } = e.data;

    try {
        if (type === 'decryptChunk') {
            const result = await decryptChunk(data, keyBytes, chunkIndex);
            self.postMessage({ id, result }, [result.buffer]);
        } else if (type === 'decryptBlock') {
            const result = await decryptBlock(data, keyBytes, aad);
            self.postMessage({ id, result }, [result.buffer]);
        }
    } catch (err) {
        self.postMessage({ id, error: err.message });
    }
};

async function decryptChunk(data, keyBytes, chunkIndex) {
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
