import {
    setMasterKeyDirect, clearMasterKey, hasMasterKey, getMasterKeyRaw,
    generateFileKey, generateHashNonce, encryptFileKey, decryptFileKey,
    encryptChunk, decryptChunk, encryptBlock, decryptBlock,
    encryptName, decryptName, generateThumbnail, modifyHash,
    bufferToBase64, base64ToBuffer, formatSize
} from './crypto.js';

// ─── State ───
let token = null;
let userId = null;
let kdfSalt = null;
let serverConfig = { persistSession: false, allowRegistration: true };
let mediaItems = [];
let currentPage = 1;
let totalItems = 0;
const PAGE_SIZE = 50;
const CHUNK_SIZE = 1024 * 1024;

// Decryption worker pool
const WORKER_COUNT = navigator.hardwareConcurrency || 4;
const workers = [];
const pendingWork = {};
let workIdCounter = 0;

function initWorkers() {
    for (let i = 0; i < WORKER_COUNT; i++) {
        const w = new Worker('/js/worker.js');
        w.onmessage = (e) => {
            const { id, result, error } = e.data;
            const pending = pendingWork[id];
            if (pending) {
                delete pendingWork[id];
                if (error) pending.reject(new Error(error));
                else pending.resolve(result);
            }
        };
        workers.push(w);
    }
}

function workerDecrypt(type, data, keyBytes, chunkIndex) {
    return new Promise((resolve, reject) => {
        const id = workIdCounter++;
        pendingWork[id] = { resolve, reject };
        const worker = workers[id % workers.length];
        worker.postMessage({ type, id, data, keyBytes, chunkIndex });
    });
}

// ─── API helpers ───
async function api(path, opts = {}) {
    const headers = { ...opts.headers };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    if (opts.json) {
        headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify(opts.json);
        if (!opts.method) opts.method = 'POST';
    }
    const res = await fetch(path, { ...opts, headers });
    if (!res.ok) {
        const text = await res.text();
        throw new Error(text || res.statusText);
    }
    if (res.status === 204) return null;
    return res.json();
}

// ─── Auth ───
const authView = document.getElementById('auth-view');
const galleryView = document.getElementById('gallery-view');
const header = document.getElementById('header');
const authForm = document.getElementById('auth-form');
const authError = document.getElementById('auth-error');
const loginBtn = document.getElementById('login-btn');
const registerBtn = document.getElementById('register-btn');

function showError(msg) {
    authError.textContent = msg;
    authError.classList.remove('hidden');
}

async function handleLogin() {
    const username = document.getElementById('auth-username').value;
    const password = document.getElementById('auth-password').value;
    try {
        const res = await api('/api/auth/login', { json: { username, password } });
        token = res.token;
        userId = res.user_id;
        kdfSalt = res.kdf_salt;

        // Receive encrypted master key and decrypt it
        if (res.encrypted_master_key) {
            const encMK = base64ToBuffer(res.encrypted_master_key);
            const sessionKeyMaterial = await crypto.subtle.importKey(
                'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits', 'deriveKey']
            );
            const sessionKey = await crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt: new TextEncoder().encode('darkreel-session-key'), iterations: 100000, hash: 'SHA-256' },
                sessionKeyMaterial, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
            );
            const iv = encMK.slice(0, 12);
            const ct = encMK.slice(12);
            const mk = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, sessionKey, ct));
            await setMasterKeyDirect(mk);
        }

        // Store session
        sessionStorage.setItem('token', token);
        sessionStorage.setItem('userId', userId);

        // Optionally persist master key for refresh survival
        if (serverConfig.persistSession) {
            const mkRaw = getMasterKeyRaw();
            if (mkRaw) {
                sessionStorage.setItem('masterKey', bufferToBase64(mkRaw));
            }
        }

        showGallery();
    } catch (e) {
        showError(e.message);
    }
}

async function handleRegister() {
    const username = document.getElementById('auth-username').value;
    const password = document.getElementById('auth-password').value;
    try {
        await api('/api/auth/register', { json: { username, password } });
        // Auto-login after register
        await handleLogin();
    } catch (e) {
        showError(e.message);
    }
}

authForm.addEventListener('submit', (e) => { e.preventDefault(); handleLogin(); });
registerBtn.addEventListener('click', handleRegister);

document.getElementById('logout-btn').addEventListener('click', async () => {
    try { await api('/api/auth/logout', { method: 'POST' }); } catch {}
    clearMasterKey();
    token = null;
    userId = null;
    sessionStorage.clear(); // clears token, userId, and masterKey
    showAuth();
});

function showAuth() {
    authView.classList.remove('hidden');
    galleryView.classList.add('hidden');
    header.classList.add('hidden');
    authError.classList.add('hidden');
}

function showGallery() {
    authView.classList.add('hidden');
    galleryView.classList.remove('hidden');
    header.classList.remove('hidden');
    loadMedia();
}

// ─── Gallery ───
const galleryGrid = document.getElementById('gallery-grid');
const galleryEmpty = document.getElementById('gallery-empty');
const galleryLoading = document.getElementById('gallery-loading');
const pagination = document.getElementById('pagination');
const sortSelect = document.getElementById('sort-select');
const typeFilter = document.getElementById('type-filter');

sortSelect.addEventListener('change', () => { currentPage = 1; loadMedia(); });
typeFilter.addEventListener('change', () => { currentPage = 1; loadMedia(); });

document.getElementById('prev-page').addEventListener('click', () => {
    if (currentPage > 1) { currentPage--; loadMedia(); }
});
document.getElementById('next-page').addEventListener('click', () => {
    if (currentPage * PAGE_SIZE < totalItems) { currentPage++; loadMedia(); }
});

async function loadMedia() {
    galleryLoading.classList.remove('hidden');
    galleryGrid.innerHTML = '';
    galleryEmpty.classList.add('hidden');
    pagination.classList.add('hidden');

    const [sort, order] = sortSelect.value.split('-');
    const type = typeFilter.value;

    try {
        const res = await api(`/api/media?sort=${sort}&order=${order}&type=${type}&page=${currentPage}&limit=${PAGE_SIZE}`);
        mediaItems = res.items || [];
        totalItems = res.total;

        if (mediaItems.length === 0) {
            galleryEmpty.classList.remove('hidden');
        } else {
            for (const item of mediaItems) {
                const el = await createGalleryItem(item);
                galleryGrid.appendChild(el);
            }
            if (totalItems > PAGE_SIZE) {
                pagination.classList.remove('hidden');
                document.getElementById('page-info').textContent =
                    `Page ${currentPage} of ${Math.ceil(totalItems / PAGE_SIZE)}`;
                document.getElementById('prev-page').disabled = currentPage <= 1;
                document.getElementById('next-page').disabled = currentPage * PAGE_SIZE >= totalItems;
            }
        }
    } catch (e) {
        console.error('Failed to load media:', e);
    }

    galleryLoading.classList.add('hidden');
}

async function createGalleryItem(item) {
    const div = document.createElement('div');
    div.className = 'gallery-item';
    div.dataset.id = item.id;

    // Decrypt thumbnail
    const img = document.createElement('img');
    img.loading = 'lazy';
    img.alt = '';

    // Load thumbnail asynchronously
    loadThumbnail(item, img);

    const badge = document.createElement('span');
    badge.className = 'badge';
    badge.textContent = item.media_type === 'video' ? 'VID' : 'IMG';

    const nameEl = document.createElement('span');
    nameEl.className = 'item-name';

    // Decrypt name asynchronously
    if (hasMasterKey()) {
        try {
            const encName = base64ToBuffer(item.name);
            const name = await decryptName(encName);
            nameEl.textContent = name;
        } catch {
            nameEl.textContent = 'Encrypted';
        }
    } else {
        nameEl.textContent = 'Encrypted';
    }

    div.appendChild(img);
    div.appendChild(badge);
    div.appendChild(nameEl);
    div.addEventListener('click', () => openViewer(item));

    return div;
}

async function loadThumbnail(item, img) {
    try {
        const res = await fetch(`/api/media/${item.id}/thumbnail`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const encData = new Uint8Array(await res.arrayBuffer());

        // Decrypt thumbnail key
        const thumbKeyEnc = base64ToBuffer(item.thumb_key_enc);
        const thumbKey = await decryptFileKey(thumbKeyEnc);

        // Decrypt thumbnail (it's encrypted as chunk index 0)
        const decrypted = await workerDecrypt('decryptChunk', encData, thumbKey, 0);
        const blob = new Blob([decrypted], { type: 'image/jpeg' });
        img.src = URL.createObjectURL(blob);
    } catch (e) {
        console.error('Failed to load thumbnail:', e);
    }
}

// ─── Viewer ───
const viewer = document.getElementById('viewer');
const viewerVideo = document.getElementById('viewer-video');
const viewerImage = document.getElementById('viewer-image');
const viewerTitle = document.getElementById('viewer-title');
let currentViewerItem = null;

document.getElementById('viewer-close').addEventListener('click', closeViewer);
document.getElementById('viewer-delete').addEventListener('click', deleteCurrentItem);
document.getElementById('viewer-download').addEventListener('click', downloadCurrentItem);

async function openViewer(item) {
    currentViewerItem = item;
    viewer.classList.remove('hidden');
    viewerVideo.classList.add('hidden');
    viewerImage.classList.add('hidden');

    // Decrypt name for title
    try {
        const encName = base64ToBuffer(item.name);
        viewerTitle.textContent = await decryptName(encName);
    } catch {
        viewerTitle.textContent = 'Encrypted file';
    }

    // Decrypt file key
    const fileKeyEnc = base64ToBuffer(item.file_key_enc);
    const fileKey = await decryptFileKey(fileKeyEnc);

    if (item.media_type === 'video') {
        await playVideo(item, fileKey);
    } else {
        await showImage(item, fileKey);
    }
}

function closeViewer() {
    viewer.classList.add('hidden');
    viewerVideo.pause();
    viewerVideo.removeAttribute('src');
    viewerVideo.classList.add('hidden');
    viewerImage.classList.add('hidden');
    viewerImage.src = '';
    if (viewerVideo._mediaSource) {
        try { viewerVideo._mediaSource.endOfStream(); } catch {}
        viewerVideo._mediaSource = null;
    }
    currentViewerItem = null;
}

async function showImage(item, fileKey) {
    viewerImage.classList.remove('hidden');
    // Fetch and decrypt all chunks
    const chunks = [];
    for (let i = 0; i < item.chunk_count; i++) {
        const res = await fetch(`/api/media/${item.id}/chunk/${i}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const encData = new Uint8Array(await res.arrayBuffer());
        const dec = await workerDecrypt('decryptChunk', encData, fileKey, i);
        chunks.push(dec);
    }
    const totalLen = chunks.reduce((s, c) => s + c.length, 0);
    const merged = new Uint8Array(totalLen);
    let offset = 0;
    for (const c of chunks) { merged.set(c, offset); offset += c.length; }

    const blob = new Blob([merged], { type: item.mime_type });
    viewerImage.src = URL.createObjectURL(blob);
}

async function playVideo(item, fileKey) {
    viewerVideo.classList.remove('hidden');

    // Check for MSE support
    if (!('MediaSource' in window) || !MediaSource.isTypeSupported(item.mime_type)) {
        // Fallback: download entire file and set as blob URL
        await playVideoFallback(item, fileKey);
        return;
    }

    const mediaSource = new MediaSource();
    viewerVideo._mediaSource = mediaSource;
    viewerVideo.src = URL.createObjectURL(mediaSource);

    mediaSource.addEventListener('sourceopen', async () => {
        let sourceBuffer;
        try {
            sourceBuffer = mediaSource.addSourceBuffer(item.mime_type);
        } catch {
            await playVideoFallback(item, fileKey);
            return;
        }

        let currentChunk = 0;
        const prefetchCount = 3;

        async function fetchAndAppend(index) {
            if (index >= item.chunk_count) {
                if (mediaSource.readyState === 'open') {
                    try { mediaSource.endOfStream(); } catch {}
                }
                return;
            }
            const res = await fetch(`/api/media/${item.id}/chunk/${index}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const encData = new Uint8Array(await res.arrayBuffer());
            const decrypted = await workerDecrypt('decryptChunk', encData, fileKey, index);

            await waitForBuffer(sourceBuffer);
            sourceBuffer.appendBuffer(decrypted);
            await new Promise(r => sourceBuffer.addEventListener('updateend', r, { once: true }));
        }

        // Load initial chunks
        for (let i = 0; i < Math.min(prefetchCount, item.chunk_count); i++) {
            try {
                await fetchAndAppend(currentChunk++);
            } catch (e) {
                console.error('MSE error, falling back:', e);
                await playVideoFallback(item, fileKey);
                return;
            }
        }

        // Continue loading remaining chunks
        async function loadMore() {
            while (currentChunk < item.chunk_count) {
                try {
                    await fetchAndAppend(currentChunk++);
                } catch (e) {
                    console.error('Chunk load error:', e);
                    break;
                }
            }
        }

        loadMore();
        viewerVideo.play().catch(() => {});
    });
}

async function playVideoFallback(item, fileKey) {
    const chunks = [];
    for (let i = 0; i < item.chunk_count; i++) {
        const res = await fetch(`/api/media/${item.id}/chunk/${i}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const encData = new Uint8Array(await res.arrayBuffer());
        const dec = await workerDecrypt('decryptChunk', encData, fileKey, i);
        chunks.push(dec);
    }
    const totalLen = chunks.reduce((s, c) => s + c.length, 0);
    const merged = new Uint8Array(totalLen);
    let offset = 0;
    for (const c of chunks) { merged.set(c, offset); offset += c.length; }

    const blob = new Blob([merged], { type: item.mime_type });
    viewerVideo.src = URL.createObjectURL(blob);
    viewerVideo.play().catch(() => {});
}

function waitForBuffer(sb) {
    return new Promise(resolve => {
        if (!sb.updating) { resolve(); return; }
        sb.addEventListener('updateend', resolve, { once: true });
    });
}

async function deleteCurrentItem() {
    if (!currentViewerItem) return;
    if (!confirm('Delete this item? This cannot be undone.')) return;
    try {
        await api(`/api/media/${currentViewerItem.id}`, { method: 'DELETE' });
        closeViewer();
        loadMedia();
    } catch (e) {
        alert('Delete failed: ' + e.message);
    }
}

async function downloadCurrentItem() {
    if (!currentViewerItem) return;
    const item = currentViewerItem;

    try {
        const fileKeyEnc = base64ToBuffer(item.file_key_enc);
        const fileKey = await decryptFileKey(fileKeyEnc);

        const chunks = [];
        for (let i = 0; i < item.chunk_count; i++) {
            const res = await fetch(`/api/media/${item.id}/chunk/${i}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const encData = new Uint8Array(await res.arrayBuffer());
            const dec = await workerDecrypt('decryptChunk', encData, fileKey, i);
            chunks.push(dec);
        }

        const totalLen = chunks.reduce((s, c) => s + c.length, 0);
        const merged = new Uint8Array(totalLen);
        let offset = 0;
        for (const c of chunks) { merged.set(c, offset); offset += c.length; }

        // Decrypt filename
        let filename = 'download';
        try {
            const encName = base64ToBuffer(item.name);
            filename = await decryptName(encName);
        } catch {}

        const blob = new Blob([merged], { type: item.mime_type });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
    } catch (e) {
        alert('Download failed: ' + e.message);
    }
}

// ─── Upload ───
const uploadModal = document.getElementById('upload-modal');
const uploadInput = document.getElementById('upload-input');
const uploadDropzone = document.getElementById('upload-dropzone');
const uploadProgress = document.getElementById('upload-progress');
const uploadList = document.getElementById('upload-list');

document.getElementById('upload-btn').addEventListener('click', () => {
    uploadModal.classList.remove('hidden');
    uploadProgress.classList.add('hidden');
    uploadList.innerHTML = '';
});
document.getElementById('upload-cancel').addEventListener('click', () => {
    uploadModal.classList.add('hidden');
});

uploadDropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadDropzone.classList.add('dragover');
});
uploadDropzone.addEventListener('dragleave', () => {
    uploadDropzone.classList.remove('dragover');
});
uploadDropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadDropzone.classList.remove('dragover');
    handleFiles(e.dataTransfer.files);
});
uploadInput.addEventListener('change', (e) => handleFiles(e.target.files));

async function handleFiles(files) {
    if (!files.length) return;
    uploadProgress.classList.remove('hidden');

    for (const file of files) {
        const itemEl = createUploadItem(file.name);
        uploadList.appendChild(itemEl);

        try {
            await uploadFile(file, itemEl);
            setUploadStatus(itemEl, 'Done');
        } catch (e) {
            console.error('Upload failed:', e);
            setUploadStatus(itemEl, 'Error: ' + e.message);
        }
    }
    loadMedia();
}

function createUploadItem(name) {
    const div = document.createElement('div');
    div.className = 'upload-item';
    div.innerHTML = `
        <span class="name">${escapeHtml(name)}</span>
        <span class="status">Preparing...</span>
        <div class="progress-bar"><div class="fill" style="width:0%"></div></div>
    `;
    return div;
}

function setUploadStatus(el, status) {
    el.querySelector('.status').textContent = status;
}

function setUploadProgress(el, pct) {
    el.querySelector('.fill').style.width = pct + '%';
}

async function uploadFile(file, itemEl) {
    setUploadStatus(itemEl, 'Reading...');
    const fileData = new Uint8Array(await file.arrayBuffer());

    setUploadStatus(itemEl, 'Generating thumbnail...');
    let thumbData;
    try {
        thumbData = await generateThumbnail(file);
    } catch {
        // Fallback: 1px placeholder
        thumbData = new Uint8Array([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46]);
    }

    setUploadStatus(itemEl, 'Encrypting...');
    const fileKey = generateFileKey();
    const thumbKey = generateFileKey();
    const hashNonce = generateHashNonce();

    // Hash modification
    const mediaType = file.type.startsWith('video/') ? 'video' : 'image';
    const modifiedData = modifyHash(fileData, file.type, hashNonce);

    // Encrypt thumbnail
    const encThumb = await encryptChunk(thumbData, thumbKey, 0);

    // Encrypt file chunks
    const chunkCount = Math.ceil(modifiedData.length / CHUNK_SIZE);
    const encChunks = [];
    for (let i = 0; i < chunkCount; i++) {
        const start = i * CHUNK_SIZE;
        const end = Math.min(start + CHUNK_SIZE, modifiedData.length);
        const chunk = modifiedData.slice(start, end);
        encChunks.push(await encryptChunk(chunk, fileKey, i));
        setUploadProgress(itemEl, Math.round(((i + 1) / chunkCount) * 50));
    }

    // Encrypt keys with master key
    const encFileKey = await encryptFileKey(fileKey);
    const encThumbKey = await encryptFileKey(thumbKey);
    const encName = await encryptName(file.name);

    // Build multipart upload
    setUploadStatus(itemEl, 'Uploading...');

    const metadata = {
        name: bufferToBase64(encName),
        media_type: mediaType,
        mime_type: file.type || 'application/octet-stream',
        size: file.size,
        chunk_count: chunkCount,
        file_key_enc: bufferToBase64(encFileKey),
        thumb_key_enc: bufferToBase64(encThumbKey),
        hash_nonce: bufferToBase64(hashNonce),
    };

    // Get video dimensions/duration
    if (mediaType === 'video') {
        try {
            const info = await getVideoInfo(file);
            metadata.width = info.width;
            metadata.height = info.height;
            metadata.duration = info.duration;
        } catch {}
    } else {
        try {
            const info = await getImageInfo(file);
            metadata.width = info.width;
            metadata.height = info.height;
        } catch {}
    }

    const formData = new FormData();
    formData.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }));
    formData.append('thumbnail', new Blob([encThumb]));
    for (let i = 0; i < encChunks.length; i++) {
        formData.append(`chunk_${i}`, new Blob([encChunks[i]]));
        setUploadProgress(itemEl, 50 + Math.round(((i + 1) / encChunks.length) * 50));
    }

    const res = await fetch('/api/media/upload', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` },
        body: formData,
    });

    if (!res.ok) throw new Error(await res.text());
    setUploadProgress(itemEl, 100);
}

function getVideoInfo(file) {
    return new Promise((resolve, reject) => {
        const video = document.createElement('video');
        video.preload = 'metadata';
        video.onloadedmetadata = () => {
            resolve({ width: video.videoWidth, height: video.videoHeight, duration: video.duration });
            URL.revokeObjectURL(video.src);
        };
        video.onerror = reject;
        video.src = URL.createObjectURL(file);
    });
}

function getImageInfo(file) {
    return new Promise((resolve, reject) => {
        const img = new Image();
        img.onload = () => {
            resolve({ width: img.width, height: img.height });
            URL.revokeObjectURL(img.src);
        };
        img.onerror = reject;
        img.src = URL.createObjectURL(file);
    });
}

// ─── Utilities ───
function escapeHtml(s) {
    const div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
}

// ─── Init ───
initWorkers();

// Fetch server config, then restore session
(async () => {
    try {
        const res = await fetch('/api/config');
        if (res.ok) serverConfig = await res.json();
    } catch {}

    // Hide register button if registration is disabled
    if (!serverConfig.allowRegistration) {
        registerBtn.classList.add('hidden');
    }

    // Try to restore session
    const savedToken = sessionStorage.getItem('token');
    if (savedToken) {
        token = savedToken;
        userId = sessionStorage.getItem('userId');

        // Try to restore master key if persist-session is enabled
        const savedMK = sessionStorage.getItem('masterKey');
        if (savedMK && serverConfig.persistSession) {
            try {
                await setMasterKeyDirect(base64ToBuffer(savedMK));
                showGallery();
                return;
            } catch {
                sessionStorage.removeItem('masterKey');
            }
        }
    }
    showAuth();
})();
