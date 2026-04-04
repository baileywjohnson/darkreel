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
const adminView = document.getElementById('admin-view');
const header = document.getElementById('header');
const authForm = document.getElementById('auth-form');
const authError = document.getElementById('auth-error');
const loginBtn = document.getElementById('login-btn');
const registerBtn = document.getElementById('register-btn');
const adminBtn = document.getElementById('admin-btn');

function showError(msg) {
    authError.textContent = msg;
    authError.classList.remove('hidden');
}

async function handleLogin(overrideUsername, overridePassword) {
    const username = overrideUsername || document.getElementById('auth-username').value;
    const password = overridePassword || document.getElementById('auth-password').value;
    try {
        const res = await api('/api/auth/login', { json: { username, password } });
        token = res.token;
        userId = res.user_id;
        kdfSalt = res.kdf_salt;

        // Receive encrypted master key and decrypt it using per-user KDF salt
        if (res.encrypted_master_key) {
            const encMK = base64ToBuffer(res.encrypted_master_key);
            const sessionKeyMaterial = await crypto.subtle.importKey(
                'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits', 'deriveKey']
            );
            const sessionKey = await crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt: base64ToBuffer(res.kdf_salt), iterations: 600000, hash: 'SHA-256' },
                sessionKeyMaterial, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
            );
            const iv = encMK.slice(0, 12);
            const ct = encMK.slice(12);
            const mk = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, sessionKey, ct));
            await setMasterKeyDirect(mk);
        }

        // Store session
        serverConfig.isAdmin = res.is_admin || false;
        sessionStorage.setItem('token', token);
        sessionStorage.setItem('userId', userId);
        sessionStorage.setItem('isAdmin', serverConfig.isAdmin ? '1' : '0');

        // Optionally persist master key for refresh survival
        if (serverConfig.persistSession) {
            const mkRaw = getMasterKeyRaw();
            if (mkRaw) {
                sessionStorage.setItem('masterKey', bufferToBase64(mkRaw));
            }
        }

        showGallery();
    } catch (e) {
        // If auth view was hidden (e.g., auto-login from registration), show it back
        if (authView.classList.contains('hidden')) {
            showAuth();
        }
        showError(e.message);
    }
}

authForm.addEventListener('submit', (e) => { e.preventDefault(); handleLogin(); });

// --- Register flow ---
const registerFormEl = document.getElementById('register-form');
const regError = document.getElementById('reg-error');
const regSuccess = document.getElementById('reg-success');

registerBtn.addEventListener('click', () => {
    authFormEl.classList.add('hidden');
    registerFormEl.classList.remove('hidden');
    regError.classList.add('hidden');
    regSuccess.classList.add('hidden');
    // Reset form fields visibility in case they were hidden after a successful registration
    registerFormEl.querySelectorAll('input, .auth-buttons, .btn-link').forEach(el => el.style.display = '');
    // Remove any dynamically added continue button
    const oldContinue = regSuccess.querySelector('button');
    if (oldContinue) oldContinue.remove();
});

document.getElementById('back-to-login-from-reg').addEventListener('click', () => {
    registerFormEl.classList.add('hidden');
    authFormEl.classList.remove('hidden');
});

registerFormEl.addEventListener('submit', async (e) => {
    e.preventDefault();
    regError.classList.add('hidden');
    regSuccess.classList.add('hidden');

    const username = document.getElementById('reg-username').value;
    const password = document.getElementById('reg-password').value;
    const confirm = document.getElementById('reg-password-confirm').value;

    if (password !== confirm) {
        regError.textContent = 'Passwords do not match';
        regError.classList.remove('hidden');
        return;
    }

    try {
        const res = await api('/api/auth/register', { json: { username, password } });

        // Hide form fields, show only recovery code + continue button
        registerFormEl.querySelectorAll('input, .auth-buttons, .btn-link').forEach(el => el.style.display = 'none');
        regSuccess.innerHTML = 'Account created! Your recovery code:<br><br><code style="user-select:all;font-size:11px;word-break:break-all;display:block;padding:12px;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius)">' + escapeHtml(res.recovery_code || '') + '</code><br>Save this code somewhere safe — it cannot be shown again.';
        regSuccess.classList.remove('hidden');

        // Add continue button
        const continueBtn = document.createElement('button');
        continueBtn.className = 'btn btn-primary';
        continueBtn.style.width = '100%';
        continueBtn.style.marginTop = '8px';
        continueBtn.style.padding = '12px';
        continueBtn.textContent = 'Continue to Darkreel';
        continueBtn.addEventListener('click', async () => {
            // Hide everything before auto-login to prevent flashes
            authView.classList.add('hidden');
            await handleLogin(username, password);
        });
        regSuccess.appendChild(continueBtn);
    } catch (err) {
        regError.textContent = err.message || 'Registration failed';
        regError.classList.remove('hidden');
    }
});

// --- Recovery flow ---
const authFormEl = document.getElementById('auth-form');
const recoveryForm = document.getElementById('recovery-form');
const forgotBtn = document.getElementById('forgot-btn');
const backToLoginBtn = document.getElementById('back-to-login-btn');
const recoveryError = document.getElementById('recovery-error');
const recoverySuccess = document.getElementById('recovery-success');

// Display a recovery code with a continue button. Survives page refresh
// because the code is persisted in sessionStorage until dismissed.
function showRecoveryCode(code, username, password) {
    recoveryForm.querySelectorAll('input, .auth-buttons, .btn-link').forEach(el => el.style.display = 'none');
    recoverySuccess.innerHTML = 'Password reset! Your new recovery code:<br><br><code style="user-select:all;font-size:11px;word-break:break-all;display:block;padding:12px;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius)">' + escapeHtml(code) + '</code><br>Save this code somewhere safe — it cannot be shown again.';
    recoverySuccess.classList.remove('hidden');

    const continueBtn = document.createElement('button');
    continueBtn.className = 'btn btn-primary';
    continueBtn.style.width = '100%';
    continueBtn.style.marginTop = '8px';
    continueBtn.style.padding = '12px';
    continueBtn.textContent = 'Continue to Darkreel';
    continueBtn.addEventListener('click', async () => {
        sessionStorage.removeItem('pendingRecoveryCode');
        sessionStorage.removeItem('pendingRecoveryUser');
        if (password) {
            authView.classList.add('hidden');
            await handleLogin(username, password);
        } else {
            showAuth();
        }
    });
    recoverySuccess.appendChild(continueBtn);

    authView.classList.remove('hidden');
    authFormEl.classList.add('hidden');
    registerFormEl.classList.add('hidden');
    recoveryForm.classList.remove('hidden');
}

forgotBtn.addEventListener('click', () => {
    authFormEl.classList.add('hidden');
    recoveryForm.classList.remove('hidden');
    recoveryError.classList.add('hidden');
    recoverySuccess.classList.add('hidden');
    // Reset form fields visibility in case they were hidden after a successful recovery
    recoveryForm.querySelectorAll('input, .auth-buttons, .btn-link').forEach(el => el.style.display = '');
    const oldContinue = recoverySuccess.querySelector('button');
    if (oldContinue) oldContinue.remove();
});

backToLoginBtn.addEventListener('click', () => {
    recoveryForm.classList.add('hidden');
    authFormEl.classList.remove('hidden');
});

recoveryForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    recoveryError.classList.add('hidden');
    recoverySuccess.classList.add('hidden');

    const username = document.getElementById('recovery-username').value;
    const recoveryCode = document.getElementById('recovery-code').value.trim();
    const newPassword = document.getElementById('recovery-new-password').value;
    const confirmPassword = document.getElementById('recovery-confirm-password').value;

    if (newPassword !== confirmPassword) {
        recoveryError.textContent = 'Passwords do not match';
        recoveryError.classList.remove('hidden');
        return;
    }

    try {
        const res = await fetch('/api/auth/recover', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, recovery_code: recoveryCode, new_password: newPassword }),
        });

        if (!res.ok) {
            const text = await res.text();
            recoveryError.textContent = text || 'Recovery failed';
            recoveryError.classList.remove('hidden');
            return;
        }

        const data = await res.json();

        // Persist recovery code so it survives page refresh
        sessionStorage.setItem('pendingRecoveryCode', data.recovery_code);
        sessionStorage.setItem('pendingRecoveryUser', username);

        showRecoveryCode(data.recovery_code, username, newPassword);
    } catch {
        recoveryError.textContent = 'Connection failed';
        recoveryError.classList.remove('hidden');
    }
});

// --- Admin panel ---
const adminCreateForm = document.getElementById('admin-create-form');
const adminCreateError = document.getElementById('admin-create-error');
const adminCreateSuccess = document.getElementById('admin-create-success');
const adminUserList = document.getElementById('admin-user-list');

adminBtn.addEventListener('click', async () => {
    galleryView.classList.add('hidden');
    settingsView.classList.add('hidden');
    adminView.classList.remove('hidden');
    sessionStorage.setItem('activeView', 'admin');
    loadAdminUsers();
    // Fetch current registration state
    try {
        const config = await fetch('/api/config').then(r => r.json());
        adminRegToggle.checked = config.allowRegistration;
    } catch {}
});

document.getElementById('admin-back-btn').addEventListener('click', () => {
    adminView.classList.add('hidden');
    galleryView.classList.remove('hidden');
    sessionStorage.setItem('activeView', 'gallery');
});

adminCreateForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    adminCreateError.classList.add('hidden');
    adminCreateSuccess.classList.add('hidden');

    const username = document.getElementById('admin-new-username').value;
    const password = document.getElementById('admin-new-password').value;
    const confirm = document.getElementById('admin-new-password-confirm').value;
    const isAdmin = document.getElementById('admin-new-is-admin').checked;

    if (password !== confirm) {
        adminCreateError.textContent = 'Passwords do not match';
        adminCreateError.classList.remove('hidden');
        return;
    }

    try {
        const res = await api('/api/admin/users', { json: { username, password, is_admin: isAdmin } });
        adminCreateSuccess.innerHTML = 'User "' + escapeHtml(res.username) + '" created.<br>Recovery code:<br><code style="user-select:all;font-size:11px;word-break:break-all;display:block;padding:8px;margin-top:4px;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius)">' + escapeHtml(res.recovery_code) + '</code>';
        adminCreateSuccess.classList.remove('hidden');
        adminCreateForm.reset();
        loadAdminUsers();
    } catch (err) {
        adminCreateError.textContent = err.message || 'Failed to create user';
        adminCreateError.classList.remove('hidden');
    }
});

async function loadAdminUsers() {
    try {
        const users = await api('/api/admin/users');
        if (!users || users.length === 0) {
            adminUserList.innerHTML = '<p style="color:var(--text-dim);font-size:14px">No users</p>';
            return;
        }
        adminUserList.innerHTML = users.map(u => `
            <div class="admin-user-card">
                <div class="admin-user-info">
                    ${escapeHtml(u.username)}
                    ${u.is_admin ? '<span class="admin-badge">Admin</span>' : ''}
                </div>
                ${u.id === userId ? '<span style="font-size:12px;color:var(--text-dim)">You</span>' : '<button class="btn btn-danger" data-delete-uid="' + u.id + '">Delete</button>'}
            </div>
        `).join('');

        adminUserList.querySelectorAll('[data-delete-uid]').forEach(btn => {
            btn.addEventListener('click', async () => {
                if (!confirm('Delete this user and all their media? This cannot be undone.')) return;
                try {
                    await api('/api/admin/users/' + btn.dataset.deleteUid, { method: 'DELETE' });
                    loadAdminUsers();
                } catch (err) {
                    alert(err.message || 'Failed to delete user');
                }
            });
        });
    } catch {}
}

// --- Registration toggle (admin) ---
const adminRegToggle = document.getElementById('admin-reg-toggle');
adminRegToggle.addEventListener('change', async () => {
    try {
        await api('/api/admin/registration', { json: { enabled: adminRegToggle.checked } });
        serverConfig.allowRegistration = adminRegToggle.checked;
    } catch {
        adminRegToggle.checked = !adminRegToggle.checked;
    }
});

// --- Settings page ---
const settingsView = document.getElementById('settings-view');
const settingsBtn = document.getElementById('settings-btn');

settingsBtn.addEventListener('click', () => {
    galleryView.classList.add('hidden');
    adminView.classList.add('hidden');
    settingsView.classList.remove('hidden');
    sessionStorage.setItem('activeView', 'settings');
});

document.getElementById('settings-back-btn').addEventListener('click', () => {
    settingsView.classList.add('hidden');
    galleryView.classList.remove('hidden');
    sessionStorage.setItem('activeView', 'gallery');
});

document.getElementById('settings-change-pw-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const errEl = document.getElementById('settings-pw-error');
    const succEl = document.getElementById('settings-pw-success');
    errEl.classList.add('hidden');
    succEl.classList.add('hidden');

    const oldPw = document.getElementById('settings-old-pw').value;
    const newPw = document.getElementById('settings-new-pw').value;
    const confirmPw = document.getElementById('settings-new-pw-confirm').value;

    if (newPw !== confirmPw) {
        errEl.textContent = 'Passwords do not match';
        errEl.classList.remove('hidden');
        return;
    }

    try {
        const res = await api('/api/auth/change-password', { json: { old_password: oldPw, new_password: newPw } });

        // Update session with new token and master key
        if (res.token) {
            token = res.token;
            sessionStorage.setItem('token', token);
        }
        if (res.encrypted_master_key) {
            if (res.kdf_salt) kdfSalt = res.kdf_salt;
            const encMK = base64ToBuffer(res.encrypted_master_key);
            const sessionKeyMaterial = await crypto.subtle.importKey(
                'raw', new TextEncoder().encode(newPw), 'PBKDF2', false, ['deriveBits', 'deriveKey']
            );
            const sessionKey = await crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt: base64ToBuffer(kdfSalt), iterations: 600000, hash: 'SHA-256' },
                sessionKeyMaterial, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
            );
            const iv = encMK.slice(0, 12);
            const ct = encMK.slice(12);
            const mk = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, sessionKey, ct));
            await setMasterKeyDirect(mk);
            if (serverConfig.persistSession) {
                sessionStorage.setItem('masterKey', bufferToBase64(getMasterKeyRaw()));
            }
        }

        succEl.textContent = 'Password changed successfully.';
        succEl.classList.remove('hidden');
        document.getElementById('settings-change-pw-form').reset();
    } catch (err) {
        errEl.textContent = err.message || 'Failed to change password';
        errEl.classList.remove('hidden');
    }
});

document.getElementById('settings-delete-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const errEl = document.getElementById('settings-delete-error');
    errEl.classList.add('hidden');

    if (!confirm('Are you sure you want to delete your account? All your encrypted media will be permanently destroyed.')) return;

    const password = document.getElementById('settings-delete-pw').value;

    try {
        await api('/api/auth/account', { method: 'DELETE', json: { password } });
        sessionStorage.clear();
        showAuth();
    } catch (err) {
        errEl.textContent = err.message || 'Failed to delete account';
        errEl.classList.remove('hidden');
    }
});

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
    adminView.classList.add('hidden');
    settingsView.classList.add('hidden');
    header.classList.add('hidden');
    authError.classList.add('hidden');
    // Reset to login form (not recovery/register)
    authFormEl.classList.remove('hidden');
    recoveryForm.classList.add('hidden');
    registerFormEl.classList.add('hidden');
    // Show/hide register button based on current registration state
    registerBtn.classList.toggle('hidden', !serverConfig.allowRegistration);
    // Clear all form fields
    authFormEl.reset();
    recoveryForm.reset();
    registerFormEl.reset();
    // Reset visibility of fields (in case hidden after success)
    recoveryForm.querySelectorAll('input, .auth-buttons, .btn-link').forEach(el => el.style.display = '');
    registerFormEl.querySelectorAll('input, .auth-buttons, .btn-link').forEach(el => el.style.display = '');
    // Clear any pending recovery code
    sessionStorage.removeItem('pendingRecoveryCode');
    sessionStorage.removeItem('pendingRecoveryUser');
    // Remove dynamically added continue buttons
    const recContinue = recoverySuccess.querySelector('button');
    if (recContinue) recContinue.remove();
    const regContinue = regSuccess.querySelector('button');
    if (regContinue) regContinue.remove();
    // Hide success/error messages
    recoveryError.classList.add('hidden');
    recoverySuccess.classList.add('hidden');
    regError.classList.add('hidden');
    regSuccess.classList.add('hidden');
    authError.classList.add('hidden');
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

let pollTimer = null;

function showGallery() {
    authView.classList.add('hidden');
    header.classList.remove('hidden');
    // Show admin button if user is admin
    adminBtn.classList.toggle('hidden', !serverConfig.isAdmin);

    // Restore active view
    const activeViewName = sessionStorage.getItem('activeView');
    galleryView.classList.add('hidden');
    adminView.classList.add('hidden');
    settingsView.classList.add('hidden');

    if (activeViewName === 'admin' && serverConfig.isAdmin) {
        adminView.classList.remove('hidden');
        loadAdminUsers();
        // Set registration toggle state
        adminRegToggle.checked = serverConfig.allowRegistration || false;
    } else if (activeViewName === 'settings') {
        settingsView.classList.remove('hidden');
    } else {
        galleryView.classList.remove('hidden');
        loadMedia();
    }
    // Poll for new media every 10 seconds
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(() => {
        if (!viewer.classList.contains('hidden')) return;
        if (!uploadModal.classList.contains('hidden')) return;
        pollMedia();
    }, 10000);
}

// ─── Folders ───
// Folder tree: [{id, name, parentId}] — decrypted client-side, encrypted at rest
let folders = [];
let currentFolderId = null; // null = root

const breadcrumb = document.getElementById('breadcrumb');

async function loadFolderTree() {
    try {
        const res = await api('/api/folders');
        if (res.folder_tree_enc && res.folder_tree_nonce && hasMasterKey()) {
            const encData = base64ToBuffer(res.folder_tree_enc);
            const nonce = base64ToBuffer(res.folder_tree_nonce);
            const combined = new Uint8Array(nonce.length + encData.length);
            combined.set(nonce, 0);
            combined.set(encData, nonce.length);
            const decrypted = await decryptBlock(combined, getMasterKeyRaw());
            folders = JSON.parse(new TextDecoder().decode(decrypted));
        } else {
            folders = [];
        }
    } catch {
        folders = [];
    }
}

async function saveFolderTree() {
    const data = new TextEncoder().encode(JSON.stringify(folders));
    const enc = await encryptBlock(data, getMasterKeyRaw());
    const nonce = enc.slice(0, 12);
    const ciphertext = enc.slice(12);
    await api('/api/folders', {
        method: 'PUT',
        json: {
            folder_tree_enc: bufferToBase64(ciphertext),
            folder_tree_nonce: bufferToBase64(nonce),
        },
    });
}

function getFolderChildren(parentId) {
    return folders.filter(f => f.parentId === parentId);
}

function getFolderPath(folderId) {
    const path = [];
    let current = folderId;
    while (current) {
        const folder = folders.find(f => f.id === current);
        if (!folder) break;
        path.unshift(folder);
        current = folder.parentId;
    }
    return path;
}

function renderBreadcrumb() {
    const path = getFolderPath(currentFolderId);
    let html = '<span class="breadcrumb-item" data-folder-id="">All Media</span>';
    for (const folder of path) {
        html += '<span class="breadcrumb-sep">/</span>';
        if (folder.id === currentFolderId) {
            html += `<span class="breadcrumb-current">${escapeHtml(folder.name)}</span>`;
        } else {
            html += `<span class="breadcrumb-item" data-folder-id="${folder.id}">${escapeHtml(folder.name)}</span>`;
        }
    }
    breadcrumb.innerHTML = html;
    breadcrumb.querySelectorAll('.breadcrumb-item').forEach(el => {
        el.addEventListener('click', () => {
            currentFolderId = el.dataset.folderId || null;
            renderFolders();
            renderGalleryItems();
        });

        // Drop target for breadcrumb (drag to parent/root)
        el.addEventListener('dragover', (e) => { e.preventDefault(); e.dataTransfer.dropEffect = 'move'; el.style.background = 'var(--surface)'; });
        el.addEventListener('dragleave', () => { el.style.background = ''; });
        el.addEventListener('drop', async (e) => {
            e.preventDefault();
            el.style.background = '';
            if (!draggedItem) return;
            const targetFolderId = el.dataset.folderId || null;
            try {
                await moveItemToFolder(draggedItem, targetFolderId);
                renderGalleryItems();
            } catch {}
            draggedItem = null;
        });
    });
}

function renderFolders() {
    renderBreadcrumb();
}

function createFolderElements() {
    const children = getFolderChildren(currentFolderId);
    const elements = [];

    for (const f of children) {
        const el = document.createElement('div');
        el.className = 'folder-item';
        el.dataset.folderId = f.id;
        el.innerHTML = `
            <span class="folder-icon">📁</span>
            <span class="folder-name">${escapeHtml(f.name)}</span>
            <button class="folder-menu-btn" data-folder-action="${f.id}" title="Folder options">⋮</button>
        `;

        el.addEventListener('click', (e) => {
            if (e.target.classList.contains('folder-menu-btn')) return;
            currentFolderId = f.id;
            renderFolders();
            renderGalleryItems();
        });

        // Drop target
        el.addEventListener('dragover', (e) => { e.preventDefault(); e.dataTransfer.dropEffect = 'move'; el.classList.add('drag-over'); });
        el.addEventListener('dragleave', () => { el.classList.remove('drag-over'); });
        el.addEventListener('drop', async (e) => {
            e.preventDefault();
            el.classList.remove('drag-over');
            if (!draggedItem) return;
            try {
                await moveItemToFolder(draggedItem, f.id);
                renderGalleryItems();
            } catch {}
            draggedItem = null;
        });

        const menuBtn = el.querySelector('.folder-menu-btn');
        menuBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            // Close any existing context menu
            document.querySelectorAll('.folder-context-menu').forEach(m => m.remove());

            const menu = document.createElement('div');
            menu.className = 'folder-context-menu';

            const renameBtn = document.createElement('button');
            renameBtn.textContent = 'Rename';
            renameBtn.addEventListener('click', (ev) => {
                ev.stopPropagation();
                menu.remove();
                const newName = prompt('New folder name:', f.name);
                if (newName && newName.trim()) {
                    f.name = newName.trim();
                    saveFolderTree();
                    renderGalleryItems();
                }
            });

            const deleteBtn = document.createElement('button');
            deleteBtn.textContent = 'Delete';
            deleteBtn.className = 'danger';
            deleteBtn.addEventListener('click', (ev) => {
                ev.stopPropagation();
                menu.remove();

                // Collect all sub-folder IDs recursively
                function getAllDescendantIds(parentId) {
                    const ids = [parentId];
                    for (const child of folders.filter(x => x.parentId === parentId)) {
                        ids.push(...getAllDescendantIds(child.id));
                    }
                    return ids;
                }
                const allFolderIds = new Set(getAllDescendantIds(f.id));
                const affectedMedia = mediaItems.filter(m => allFolderIds.has(m.folderId));
                const subFolderCount = allFolderIds.size - 1;

                let msg = `Delete folder "${f.name}"?`;
                if (affectedMedia.length > 0 || subFolderCount > 0) {
                    const parts = [];
                    if (affectedMedia.length > 0) parts.push(`${affectedMedia.length} media item${affectedMedia.length !== 1 ? 's' : ''}`);
                    if (subFolderCount > 0) parts.push(`${subFolderCount} sub-folder${subFolderCount !== 1 ? 's' : ''}`);
                    msg += `\n\nThis will also permanently delete ${parts.join(' and ')} inside it.`;
                }

                showDeleteFolderConfirm(msg, async () => {
                    // Delete all media in the folder and sub-folders
                    for (const item of affectedMedia) {
                        try {
                            await api(`/api/media/${item.id}`, { method: 'DELETE' });
                        } catch {}
                    }
                    mediaItems = mediaItems.filter(m => !allFolderIds.has(m.folderId));

                    // Remove folder and all descendants
                    folders = folders.filter(x => !allFolderIds.has(x.id));
                    await saveFolderTree();

                    // If we were inside the deleted folder, go to parent
                    if (allFolderIds.has(currentFolderId)) {
                        currentFolderId = f.parentId;
                    }
                    renderGalleryItems();
                });
            });

            menu.appendChild(renameBtn);
            menu.appendChild(deleteBtn);
            el.appendChild(menu);

            // Close menu on outside click
            const closeMenu = (ev) => {
                if (!menu.contains(ev.target)) {
                    menu.remove();
                    document.removeEventListener('click', closeMenu);
                }
            };
            setTimeout(() => document.addEventListener('click', closeMenu), 0);
        });

        elements.push(el);
    }
    return elements;
}

function renderGalleryItems() {
    renderBreadcrumb();
    galleryGrid.innerHTML = '';

    // Render folders first, then media
    const folderEls = createFolderElements();
    for (const el of folderEls) {
        galleryGrid.appendChild(el);
    }

    const filtered = mediaItems.filter(m => (m.folderId || null) === currentFolderId);
    if (filtered.length === 0 && folderEls.length === 0) {
        galleryEmpty.classList.remove('hidden');
    } else {
        galleryEmpty.classList.add('hidden');
    }
    (async () => {
        for (const item of filtered) {
            const el = await createGalleryItem(item);
            galleryGrid.appendChild(el);
        }
    })();
}

document.getElementById('new-folder-btn').addEventListener('click', async () => {
    const name = prompt('Folder name:');
    if (!name || !name.trim()) return;
    const id = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2);
    folders.push({ id, name: name.trim(), parentId: currentFolderId });
    await saveFolderTree();
    renderGalleryItems();
});

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
        const res = await api(`/api/media?page=${currentPage}&limit=${PAGE_SIZE}`);
        const rawItems = res.items || [];
        totalItems = res.total;

        // Decrypt metadata for each item
        mediaItems = [];
        for (const item of rawItems) {
            try {
                if (item.metadata_enc && item.metadata_nonce && hasMasterKey()) {
                    const encData = base64ToBuffer(item.metadata_enc);
                    const nonce = base64ToBuffer(item.metadata_nonce);
                    const combined = new Uint8Array(nonce.length + encData.length);
                    combined.set(nonce, 0);
                    combined.set(encData, nonce.length);
                    const decrypted = await decryptBlock(combined, getMasterKeyRaw());
                    const meta = JSON.parse(new TextDecoder().decode(decrypted));
                    // Store trusted chunk count from encrypted metadata (tamper-proof)
                    if (meta.chunk_count) {
                        meta.chunk_count_trusted = meta.chunk_count;
                    }
                    Object.assign(item, meta);
                }
            } catch (e) {
                console.warn('Failed to decrypt metadata for', item.id, e);
            }
            mediaItems.push(item);
        }

        // Load folder tree and render
        await loadFolderTree();
        renderFolders();
        renderGalleryItems();

        if (totalItems > PAGE_SIZE) {
            pagination.classList.remove('hidden');
            document.getElementById('page-info').textContent =
                `Page ${currentPage} of ${Math.ceil(totalItems / PAGE_SIZE)}`;
            document.getElementById('prev-page').disabled = currentPage <= 1;
            document.getElementById('next-page').disabled = currentPage * PAGE_SIZE >= totalItems;
        }
    } catch (e) {
        console.error('Failed to load media:', e);
    }

    galleryLoading.classList.add('hidden');
}

// Silent background poll — only adds new items, no spinner, no grid reset
async function pollMedia() {
    try {
        const res = await api(`/api/media?page=${currentPage}&limit=${PAGE_SIZE}`);
        const rawItems = res.items || [];
        const newTotal = res.total;

        if (newTotal === totalItems) return; // nothing changed

        // Find IDs we already have
        const existingIds = new Set(mediaItems.map((m) => m.id));
        const newItems = [];

        for (const item of rawItems) {
            if (existingIds.has(item.id)) continue;
            try {
                if (item.metadata_enc && item.metadata_nonce && hasMasterKey()) {
                    const encData = base64ToBuffer(item.metadata_enc);
                    const nonce = base64ToBuffer(item.metadata_nonce);
                    const combined = new Uint8Array(nonce.length + encData.length);
                    combined.set(nonce, 0);
                    combined.set(encData, nonce.length);
                    const decrypted = await decryptBlock(combined, getMasterKeyRaw());
                    const meta = JSON.parse(new TextDecoder().decode(decrypted));
                    if (meta.chunk_count) meta.chunk_count_trusted = meta.chunk_count;
                    Object.assign(item, meta);
                }
            } catch {}
            newItems.push(item);
        }

        if (newItems.length > 0) {
            for (const item of newItems) {
                mediaItems.push(item);
            }
            renderGalleryItems();
        }

        totalItems = newTotal;

        // Also detect deletions
        if (rawItems.length < mediaItems.length) {
            loadMedia();
        }
    } catch {}
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

    // Name is already decrypted from metadata blob
    nameEl.textContent = item.name || 'Encrypted';

    div.appendChild(img);
    div.appendChild(badge);
    div.appendChild(nameEl);
    div.addEventListener('click', () => openViewer(item));

    // Drag support
    div.draggable = true;
    div.addEventListener('dragstart', (e) => {
        draggedItem = item;
        div.classList.add('dragging');
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/plain', item.id);
    });
    div.addEventListener('dragend', () => {
        div.classList.remove('dragging');
        draggedItem = null;
    });

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
document.getElementById('viewer-move').addEventListener('click', moveCurrentItem);

// --- Move item to folder (shared logic) ---
async function moveItemToFolder(item, newFolderId) {
    const meta = {
        name: item.name,
        media_type: item.media_type,
        mime_type: item.mime_type,
        size: item.size,
        chunk_count: item.chunk_count_trusted || item.chunk_count,
        folderId: newFolderId,
    };
    if (item.width) meta.width = item.width;
    if (item.height) meta.height = item.height;
    if (item.duration) meta.duration = item.duration;

    const metaBytes = new TextEncoder().encode(JSON.stringify(meta));
    const enc = await encryptBlock(metaBytes, getMasterKeyRaw());
    const nonce = enc.slice(0, 12);
    const ciphertext = enc.slice(12);

    await api(`/api/media/${item.id}`, {
        method: 'PATCH',
        json: {
            metadata_enc: bufferToBase64(ciphertext),
            metadata_nonce: bufferToBase64(nonce),
        },
    });
    item.folderId = newFolderId;
}

// --- Move modal ---
const moveModal = document.getElementById('move-modal');
const moveFolderList = document.getElementById('move-folder-list');
let moveTargetItem = null;

function openMoveModal(item) {
    moveTargetItem = item;
    moveFolderList.innerHTML = '';

    // Root option
    const rootEl = document.createElement('div');
    rootEl.className = 'move-folder-item' + ((item.folderId || null) === null ? ' active' : '');
    rootEl.innerHTML = '📂 All Media (root)';
    rootEl.addEventListener('click', () => doMove(null));
    moveFolderList.appendChild(rootEl);

    // Recursively add folders
    function addFolders(parentId, depth) {
        for (const f of folders.filter(x => x.parentId === parentId)) {
            const el = document.createElement('div');
            el.className = 'move-folder-item' + (item.folderId === f.id ? ' active' : '');
            el.innerHTML = `<span class="move-folder-indent" style="width:${depth * 20}px"></span>📁 ${escapeHtml(f.name)}`;
            el.addEventListener('click', () => doMove(f.id));
            moveFolderList.appendChild(el);
            addFolders(f.id, depth + 1);
        }
    }
    addFolders(null, 1);

    moveModal.classList.remove('hidden');
}

async function doMove(folderId) {
    if (!moveTargetItem) return;
    try {
        await moveItemToFolder(moveTargetItem, folderId);
        moveModal.classList.add('hidden');
        closeViewer();
        renderGalleryItems();
    } catch (e) {
        alert('Failed to move: ' + e.message);
    }
}

document.getElementById('move-cancel').addEventListener('click', () => {
    moveModal.classList.add('hidden');
    moveTargetItem = null;
});

function moveCurrentItem() {
    if (currentViewerItem) openMoveModal(currentViewerItem);
}

// --- Delete folder confirmation ---
function showDeleteFolderConfirm(message, onConfirm) {
    // Reuse modal overlay pattern
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `
        <div class="modal-card">
            <h3>Delete Folder</h3>
            <p style="font-size:14px;color:var(--text-dim);white-space:pre-line;margin-bottom:20px">${escapeHtml(message)}</p>
            <div style="display:flex;gap:8px">
                <button class="btn btn-danger" style="flex:1;padding:12px" id="confirm-delete-folder">Delete</button>
                <button class="btn btn-ghost" style="flex:1;padding:12px" id="cancel-delete-folder">Cancel</button>
            </div>
        </div>
    `;
    document.body.appendChild(overlay);

    overlay.querySelector('#confirm-delete-folder').addEventListener('click', () => {
        overlay.remove();
        onConfirm();
    });
    overlay.querySelector('#cancel-delete-folder').addEventListener('click', () => {
        overlay.remove();
    });
}

// --- Drag and drop ---
let draggedItem = null;

// --- Gallery drag-to-upload ---
const galleryDropOverlay = document.getElementById('gallery-drop-overlay');
let dragCounter = 0;

document.addEventListener('dragenter', (e) => {
    // Only show overlay for external file drops when gallery is visible
    if (draggedItem) return;
    if (!e.dataTransfer.types.includes('Files')) return;
    if (galleryView.classList.contains('hidden')) return;
    e.preventDefault();
    dragCounter++;
    galleryDropOverlay.classList.remove('hidden');
});

document.addEventListener('dragleave', (e) => {
    if (draggedItem) return;
    dragCounter--;
    if (dragCounter <= 0) {
        dragCounter = 0;
        galleryDropOverlay.classList.add('hidden');
    }
});

document.addEventListener('dragover', (e) => {
    if (draggedItem) return;
    if (!e.dataTransfer.types.includes('Files')) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
});

document.addEventListener('drop', (e) => {
    if (draggedItem) return;
    e.preventDefault();
    dragCounter = 0;
    galleryDropOverlay.classList.add('hidden');
    if (e.dataTransfer.files.length > 0) {
        handleDropUpload(e.dataTransfer.files);
    }
});

// --- Drop-to-upload (no modal) ---
const dropUploadStatus = document.getElementById('drop-upload-status');

async function handleDropUpload(files) {
    dropUploadStatus.innerHTML = '';
    dropUploadStatus.classList.remove('hidden');

    for (const file of files) {
        const row = document.createElement('div');
        row.className = 'drop-upload-item';
        const nameSpan = document.createElement('span');
        nameSpan.textContent = file.name;
        nameSpan.style.overflow = 'hidden';
        nameSpan.style.textOverflow = 'ellipsis';
        nameSpan.style.whiteSpace = 'nowrap';
        const statusSpan = document.createElement('span');
        statusSpan.className = 'status';
        statusSpan.textContent = 'Uploading...';
        row.appendChild(nameSpan);
        row.appendChild(statusSpan);
        dropUploadStatus.appendChild(row);

        // Add a placeholder tile to the gallery
        const placeholder = document.createElement('div');
        placeholder.className = 'gallery-item';
        placeholder.innerHTML = '<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;gap:8px"><div class="spinner"></div><span style="font-size:12px;color:var(--text-dim)">' + escapeHtml(file.name) + '</span></div>';
        galleryGrid.appendChild(placeholder);

        try {
            const dummyEl = createUploadItem(file.name);
            dummyEl.style.display = 'none';
            document.body.appendChild(dummyEl);
            await uploadFile(file, dummyEl);
            dummyEl.remove();
            statusSpan.textContent = 'Done';
            statusSpan.className = 'status done';
        } catch (e) {
            console.error('Drop upload failed:', e);
            placeholder.remove();
            statusSpan.textContent = 'Error';
            statusSpan.className = 'status error';
        }
    }

    // Fade out toast after 2 seconds, then refresh gallery
    setTimeout(() => {
        dropUploadStatus.style.opacity = '0';
        setTimeout(() => {
            dropUploadStatus.classList.add('hidden');
            dropUploadStatus.style.opacity = '';
        }, 500);
    }, 2000);
    loadMedia();
}

/**
 * Verify the number of chunks received matches the trusted count from encrypted metadata.
 * Detects truncation attacks where an attacker deletes chunks from the server.
 */
function verifyChunkCount(item, actualCount) {
    const expectedCount = item.chunk_count_trusted || item.chunk_count;
    if (actualCount !== expectedCount) {
        throw new Error(`File integrity error: expected ${expectedCount} chunks but received ${actualCount}. The file may have been tampered with.`);
    }
}

async function openViewer(item) {
    currentViewerItem = item;
    viewer.classList.remove('hidden');
    viewerVideo.classList.add('hidden');
    viewerImage.classList.add('hidden');

    viewerTitle.textContent = item.name || 'Encrypted file';

    // Decrypt file key
    const fileKeyEnc = base64ToBuffer(item.file_key_enc);
    const fileKey = await decryptFileKey(fileKeyEnc);

    if (item.media_type === 'video') {
        await playVideo(item, fileKey);
    } else {
        await showImage(item, fileKey);
    }
}

let _viewerBlobUrl = null;

function closeViewer() {
    viewer.classList.add('hidden');
    viewerVideo.pause();
    viewerVideo.removeAttribute('src');
    viewerVideo.classList.add('hidden');
    viewerImage.classList.add('hidden');
    viewerImage.src = '';
    if (_viewerBlobUrl) {
        URL.revokeObjectURL(_viewerBlobUrl);
        _viewerBlobUrl = null;
    }
    if (viewerVideo._mediaSource) {
        try { viewerVideo._mediaSource.endOfStream(); } catch {}
        viewerVideo._mediaSource = null;
    }
    currentViewerItem = null;
}

async function showImage(item, fileKey) {
    viewerImage.classList.remove('hidden');
    const chunks = [];
    for (let i = 0; i < item.chunk_count; i++) {
        const res = await fetch(`/api/media/${item.id}/chunk/${i}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const encData = new Uint8Array(await res.arrayBuffer());
        const dec = await workerDecrypt('decryptChunk', encData, fileKey, i);
        chunks.push(dec);
    }
    verifyChunkCount(item, chunks.length);
    const totalLen = chunks.reduce((s, c) => s + c.length, 0);
    const merged = new Uint8Array(totalLen);
    let offset = 0;
    for (const c of chunks) { merged.set(c, offset); offset += c.length; }

    const blob = new Blob([merged], { type: item.mime_type });
    if (_viewerBlobUrl) URL.revokeObjectURL(_viewerBlobUrl);
    _viewerBlobUrl = URL.createObjectURL(blob);
    viewerImage.src = _viewerBlobUrl;
}

async function playVideo(item, fileKey) {
    viewerVideo.classList.remove('hidden');
    viewerTitle.textContent = `Decrypting... 0/${item.chunk_count} chunks`;

    try {
        const chunks = [];
        for (let i = 0; i < item.chunk_count; i++) {
            viewerTitle.textContent = `Decrypting... ${i + 1}/${item.chunk_count} chunks`;
            const res = await fetch(`/api/media/${item.id}/chunk/${i}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (!res.ok) throw new Error(`Chunk ${i} fetch failed: ${res.status}`);
            const encData = new Uint8Array(await res.arrayBuffer());
            const dec = await workerDecrypt('decryptChunk', encData, fileKey, i);
            chunks.push(dec);
        }
        verifyChunkCount(item, chunks.length);
        const totalLen = chunks.reduce((s, c) => s + c.length, 0);
        const merged = new Uint8Array(totalLen);
        let offset = 0;
        for (const c of chunks) { merged.set(c, offset); offset += c.length; }

        viewerTitle.textContent = item.name || 'Video';

        const blob = new Blob([merged], { type: item.mime_type || 'video/mp4' });
        if (_viewerBlobUrl) URL.revokeObjectURL(_viewerBlobUrl);
        _viewerBlobUrl = URL.createObjectURL(blob);
        viewerVideo.src = _viewerBlobUrl;
        viewerVideo.play().catch(() => {});
    } catch (e) {
        viewerTitle.textContent = 'Playback failed: ' + e.message;
    }
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

        verifyChunkCount(item, chunks.length);
        const totalLen = chunks.reduce((s, c) => s + c.length, 0);
        const merged = new Uint8Array(totalLen);
        let offset = 0;
        for (const c of chunks) { merged.set(c, offset); offset += c.length; }

        const filename = item.name || 'download';

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

    // Build and encrypt metadata blob
    const metaPlain = {
        name: file.name,
        media_type: mediaType,
        mime_type: file.type || 'application/octet-stream',
        size: file.size,
        chunk_count: chunkCount,
    };

    // Get video dimensions/duration
    if (mediaType === 'video') {
        try {
            const info = await getVideoInfo(file);
            metaPlain.width = info.width;
            metaPlain.height = info.height;
            metaPlain.duration = info.duration;
        } catch {}
    } else {
        try {
            const info = await getImageInfo(file);
            metaPlain.width = info.width;
            metaPlain.height = info.height;
        } catch {}
    }

    const metaBytes = new TextEncoder().encode(JSON.stringify(metaPlain));
    const encMetadata = await encryptBlock(metaBytes, getMasterKeyRaw());
    // encryptBlock returns nonce (12 bytes) || ciphertext
    const metadataNonce = encMetadata.slice(0, 12);
    const metadataCiphertext = encMetadata.slice(12);

    // Build multipart upload
    setUploadStatus(itemEl, 'Uploading...');

    const metadata = {
        chunk_count: chunkCount,
        file_key_enc: bufferToBase64(encFileKey),
        thumb_key_enc: bufferToBase64(encThumbKey),
        hash_nonce: bufferToBase64(hashNonce),
        metadata_enc: bufferToBase64(metadataCiphertext),
        metadata_nonce: bufferToBase64(metadataNonce),
    };

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

        // Validate the token is still accepted by the server
        try {
            const checkRes = await fetch('/api/media?limit=0', {
                headers: { 'Authorization': `Bearer ${savedToken}` },
            });
            if (!checkRes.ok) throw new Error('invalid token');
        } catch {
            // Token rejected (server restarted, expired, etc.)
            token = null;
            userId = null;
            sessionStorage.clear();
            showAuth();
            return;
        }

        // Restore admin flag
        serverConfig.isAdmin = sessionStorage.getItem('isAdmin') === '1';

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

        // Token is valid but no master key — need to re-login for decryption
        token = null;
        userId = null;
        sessionStorage.clear();
    }
    // Check for a pending recovery code that should survive refresh
    const pendingCode = sessionStorage.getItem('pendingRecoveryCode');
    const pendingUser = sessionStorage.getItem('pendingRecoveryUser');
    if (pendingCode) {
        showRecoveryCode(pendingCode, pendingUser, null);
        return;
    }

    showAuth();
})();
