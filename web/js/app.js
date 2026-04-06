import {
    setMasterKeyDirect, clearMasterKey, hasMasterKey, getMasterKeyRaw,
    generateFileKey, generateHashNonce, encryptFileKey, decryptFileKey,
    encryptChunk, decryptChunk, encryptBlock, decryptBlock,
    encryptName, decryptName, generateThumbnail, modifyHash,
    bufferToBase64, base64ToBuffer, formatSize
} from './crypto.js';

// ─── FFmpeg WASM (lazy-loaded for video remuxing) ───
//
// IMPORTANT: ffmpeg WASM requires SharedArrayBuffer, which requires cross-origin
// isolation headers (COEP + COOP) set in server.go's securityHeaders().
// If those headers are removed or changed, SharedArrayBuffer becomes unavailable,
// ffmpeg silently fails to load, and videos get uploaded without fMP4 remuxing —
// meaning they'll never stream and always fall back to full-file decrypt.
//
// The loading chain is:
//   1. classes.js creates a module Worker from ./worker.js (same-origin, type: "module")
//   2. worker.js tries importScripts(coreURL) — fails in module worker, catches
//   3. Falls back to import(coreURL) — loads ffmpeg-core.js as ESM
//   4. ffmpeg-core.js has "export default createFFmpegCore" (required for this path)
//   5. worker.js initializes the WASM core with SharedArrayBuffer
//
// DO NOT:
//   - Remove COEP/COOP headers from server.go (breaks SharedArrayBuffer)
//   - Load external resources without crossorigin attrs (blocked by require-corp)
//   - Use blob URLs for the worker (opaque origin breaks import() of same-origin URLs)
//   - Switch ffmpeg-core.js to a UMD build without "export default" (breaks ESM import)
//
let _ffmpegInstance = null;
let _ffmpegLoading = null;

async function loadFFmpeg() {
    if (_ffmpegInstance) return _ffmpegInstance;
    if (_ffmpegLoading) return _ffmpegLoading;
    _ffmpegLoading = (async () => {
        try {
            if (typeof SharedArrayBuffer === 'undefined') {
                console.error('FFmpeg WASM: SharedArrayBuffer not available. Cross-origin isolation headers may be missing.');
                return null;
            }
            const { FFmpeg } = await import('/js/vendor/ffmpeg/index.js');
            const ff = new FFmpeg();
            await ff.load({
                coreURL: new URL('/js/vendor/ffmpeg/ffmpeg-core.js', location.origin).href,
                wasmURL: new URL('/js/vendor/ffmpeg/ffmpeg-core.wasm', location.origin).href,
            });
            _ffmpegInstance = ff;
            return ff;
        } catch (e) {
            console.error('FFmpeg WASM failed to load:', e);
            _ffmpegLoading = null;
            return null;
        }
    })();
    return _ffmpegLoading;
}

async function remuxToFMP4(data, filename) {
    const ff = await loadFFmpeg();
    if (!ff) return null;
    try {
        const ext = filename.split('.').pop()?.toLowerCase() || 'mp4';
        const inName = `input.${ext}`;
        await ff.writeFile(inName, data);
        const exitCode = await ff.exec([
            '-y', '-i', inName,
            '-c', 'copy',
            '-movflags', 'frag_keyframe+empty_moov+default_base_moof',
            '-f', 'mp4',
            'output.mp4',
        ]);
        if (exitCode !== 0) {
            try { await ff.deleteFile(inName); } catch {}
            return null;
        }
        const result = await ff.readFile('output.mp4');
        await ff.deleteFile(inName);
        await ff.deleteFile('output.mp4');
        return new Uint8Array(result);
    } catch (e) {
        console.warn('fMP4 remux failed:', e);
        return null;
    }
}

// Preload FFmpeg after page is idle so it's ready for video uploads
if (typeof requestIdleCallback !== 'undefined') {
    requestIdleCallback(() => loadFFmpeg(), { timeout: 10000 });
} else {
    setTimeout(() => loadFFmpeg(), 3000);
}

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

const authUsername = document.getElementById('auth-username');
const authPassword = document.getElementById('auth-password');
loginBtn.disabled = true;

function checkLoginFields() {
    loginBtn.disabled = !(authUsername.value.length > 0 && authPassword.value.length > 0);
}
authUsername.addEventListener('input', checkLoginFields);
authPassword.addEventListener('input', checkLoginFields);

function showError(msg) {
    authError.textContent = msg;
    authError.classList.remove('hidden');
}

function btnLoading(btn) {
    btn.disabled = true;
    btn.dataset.origText = btn.textContent;
    btn.innerHTML = '<div class="spinner spinner-sm"></div>';
}
function btnReset(btn) {
    btn.textContent = btn.dataset.origText || '';
    btn.disabled = false;
}

async function handleLogin(overrideUsername, overridePassword) {
    const username = overrideUsername || document.getElementById('auth-username').value;
    const password = overridePassword || document.getElementById('auth-password').value;
    authError.classList.add('hidden');
    loginBtn.disabled = true;
    loginBtn.dataset.origText = loginBtn.textContent;
    loginBtn.innerHTML = '<div class="spinner spinner-sm"></div>';
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
        loginBtn.textContent = loginBtn.dataset.origText || 'Login';
        loginBtn.disabled = false;
        // If auth view was hidden (e.g., auto-login from registration), show it back
        if (authView.classList.contains('hidden')) {
            showAuth();
        }
        showError(e instanceof TypeError ? 'Connection failed.' : e.message);
    }
}

authForm.addEventListener('submit', (e) => { e.preventDefault(); handleLogin(); });

// --- Register flow ---
const registerFormEl = document.getElementById('register-form');
const regError = document.getElementById('reg-error');
const regSuccess = document.getElementById('reg-success');

registerBtn.addEventListener('click', () => {
    // Carry over username/password from login form
    document.getElementById('reg-username').value = document.getElementById('auth-username').value;
    document.getElementById('reg-password').value = document.getElementById('auth-password').value;
    authFormEl.classList.add('hidden');
    registerFormEl.classList.remove('hidden');
    regError.classList.add('hidden');
    regSuccess.classList.add('hidden');
    // Reset form fields visibility in case they were hidden after a successful registration
    registerFormEl.querySelectorAll('input, .auth-buttons, .btn-link').forEach(el => el.style.display = '');
    // Remove any dynamically added continue button
    const oldContinue = regSuccess.querySelector('button');
    if (oldContinue) oldContinue.remove();
    // Check and force-show unmet requirement messages
    checkUsernameReqs();
    checkPasswordReqs();
    const u = regUsernameInput.value;
    const uMet = u.length >= 3 && u.length <= 64;
    if (!uMet && u.length > 0) regUsernameReqs.classList.remove('hidden');
    const pw = regPasswordInput.value;
    const pwMet = pw.length >= 16 && /[a-zA-Z]/.test(pw) && /\d/.test(pw) && /[^a-zA-Z0-9]/.test(pw);
    if (!pwMet && pw.length > 0) regPasswordReqs.classList.remove('hidden');
});

document.getElementById('back-to-login-from-reg').addEventListener('click', () => {
    registerFormEl.classList.add('hidden');
    authFormEl.classList.remove('hidden');
    authFormEl.reset();
    checkLoginFields();
});

// Input filtering: usernames alphanumeric only, passwords no spaces
function filterUsername(e) {
    const el = e.target;
    el.value = el.value.replace(/[^a-zA-Z0-9]/g, '');
}
function filterPassword(e) {
    const el = e.target;
    el.value = el.value.replace(/\s/g, '');
}
let _lastFocusedInput = null;
function cursorToEnd(e) {
    const el = e.target;
    if (_lastFocusedInput === el) return;
    _lastFocusedInput = el;
    setTimeout(() => el.setSelectionRange(el.value.length, el.value.length), 0);
}
document.querySelectorAll('#auth-username, #reg-username, #admin-new-username, #recovery-username').forEach(el => {
    el.addEventListener('input', filterUsername);
    el.addEventListener('focus', cursorToEnd);
    el.addEventListener('blur', () => { if (_lastFocusedInput === el) _lastFocusedInput = null; });
});
document.querySelectorAll('#auth-password, #reg-password, #reg-password-confirm, #recovery-new-password, #recovery-confirm-password, #settings-current-pw, #settings-new-pw, #settings-new-pw-confirm, #admin-new-password, #admin-new-password-confirm, #delete-confirm-pw').forEach(el => {
    if (!el) return;
    el.addEventListener('input', filterPassword);
    el.addEventListener('focus', cursorToEnd);
    el.addEventListener('blur', () => { if (_lastFocusedInput === el) _lastFocusedInput = null; });
});

const regUsernameInput = document.getElementById('reg-username');
const regUsernameReqs = document.getElementById('reg-username-reqs');
const regConfirmHint = document.getElementById('reg-confirm-hint');
const regPasswordReqs = document.getElementById('reg-password-reqs');
const regPasswordInput = document.getElementById('reg-password');
const regPasswordConfirm = document.getElementById('reg-password-confirm');
const regSubmitBtn = registerFormEl.querySelector('button[type="submit"]');
regSubmitBtn.disabled = true;
regPasswordConfirm.disabled = true;

function checkUsernameReqs() {
    const u = regUsernameInput.value;
    const checks = {
        ulen: u.length >= 3,
        umax: u.length <= 64,
    };
    const allMet = Object.values(checks).every(Boolean);

    for (const [key, met] of Object.entries(checks)) {
        const el = regUsernameReqs.querySelector(`[data-req="${key}"]`);
        if (el) el.classList.toggle('met', met);
    }

    if (allMet) {
        regUsernameReqs.classList.add('hidden');
    } else if (document.activeElement === regUsernameInput) {
        regUsernameReqs.classList.remove('hidden');
    }


    checkPasswordReqs();
}

regUsernameInput.addEventListener('input', () => { filterUsername({ target: regUsernameInput }); checkUsernameReqs(); });
regUsernameInput.addEventListener('focus', () => {
    const u = regUsernameInput.value;
    const allMet = u.length >= 3 && u.length <= 64;
    if (!allMet) regUsernameReqs.classList.remove('hidden');
});
regUsernameInput.addEventListener('blur', () => {
    const u = regUsernameInput.value;
    const allMet = u.length >= 3 && u.length <= 64;
    if (allMet) regUsernameReqs.classList.add('hidden');
});

function checkPasswordReqs() {
    const pw = regPasswordInput.value;
    const confirm = regPasswordConfirm.value;
    const checks = {
        length: pw.length >= 16,
        letter: /[a-zA-Z]/.test(pw),
        number: /\d/.test(pw),
        symbol: /[^a-zA-Z0-9]/.test(pw),
    };

    const allMet = Object.values(checks).every(Boolean);
    // Show if not all met, hide only if all met
    if (allMet) {
        regPasswordReqs.classList.add('hidden');
    } else if (document.activeElement === regPasswordInput) {
        regPasswordReqs.classList.remove('hidden');
    }

    for (const [key, met] of Object.entries(checks)) {
        const el = regPasswordReqs.querySelector(`[data-req="${key}"]`);
        if (el) el.classList.toggle('met', met);
    }

    regPasswordConfirm.disabled = !allMet;
    if (!allMet) {
        regPasswordConfirm.value = '';
        regConfirmHint.classList.add('hidden');
    }

    const passwordsMatch = pw === confirm && confirm.length > 0;
    const u = regUsernameInput.value;
    const usernameOk = u.length >= 3 && u.length <= 64;
    regSubmitBtn.disabled = !(allMet && passwordsMatch && usernameOk);
}

regPasswordInput.addEventListener('input', checkPasswordReqs);
regPasswordInput.addEventListener('focus', () => {
    const pw = regPasswordInput.value;
    const allMet = pw.length >= 16 && /[a-zA-Z]/.test(pw) && /\d/.test(pw) && /[^a-zA-Z0-9]/.test(pw);
    if (!allMet) regPasswordReqs.classList.remove('hidden');
});
regPasswordInput.addEventListener('blur', () => {
    const pw = regPasswordInput.value;
    const allMet = pw.length >= 16 && /[a-zA-Z]/.test(pw) && /\d/.test(pw) && /[^a-zA-Z0-9]/.test(pw);
    if (allMet) regPasswordReqs.classList.add('hidden');
});

function checkConfirmMatch() {
    const pw = regPasswordInput.value;
    const confirm = regPasswordConfirm.value;
    const matches = pw === confirm && confirm.length > 0;
    if (matches) {
        regConfirmHint.classList.add('hidden');
    } else if (document.activeElement === regPasswordConfirm) {
        regConfirmHint.classList.remove('hidden');
    }
}

regPasswordConfirm.addEventListener('input', () => { checkPasswordReqs(); checkConfirmMatch(); });
regPasswordInput.addEventListener('input', () => { checkConfirmMatch(); });
regPasswordConfirm.addEventListener('focus', () => {
    const matches = regPasswordInput.value === regPasswordConfirm.value && regPasswordConfirm.value.length > 0;
    if (!matches) regConfirmHint.classList.remove('hidden');
});
regPasswordConfirm.addEventListener('blur', () => {
    const matches = regPasswordInput.value === regPasswordConfirm.value && regPasswordConfirm.value.length > 0;
    if (matches) regConfirmHint.classList.add('hidden');
});

registerFormEl.addEventListener('submit', async (e) => {
    e.preventDefault();
    regError.classList.add('hidden');
    regSuccess.classList.add('hidden');

    const username = document.getElementById('reg-username').value;
    const password = regPasswordInput.value;
    const confirm = regPasswordConfirm.value;

    if (password !== confirm) {
        regError.textContent = 'Passwords do not match';
        regError.classList.remove('hidden');
        return;
    }

    try {
        const res = await api('/api/auth/register', { json: { username, password } });

        // Hide form fields, show only recovery code + continue button
        registerFormEl.querySelectorAll('input, .auth-buttons, .btn-link').forEach(el => el.style.display = 'none');
        regSuccess.innerHTML = 'Account created! Your recovery code:<br><br><code style="user-select:all;font-size:11px;word-break:break-all;display:block;padding:12px;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius)">' + escapeHtml(res.recovery_code || '') + '</code><br><span style="display:block;margin-bottom:6px">Save this code somewhere safe — it cannot be shown again.</span>';
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
        regError.textContent = err instanceof TypeError ? 'Connection failed.' : (err.message || 'Registration failed');
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
    recoverySuccess.innerHTML = 'Password reset! Your new recovery code:<br><br><code style="user-select:all;font-size:11px;word-break:break-all;display:block;padding:12px;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius)">' + escapeHtml(code) + '</code><br><span style="display:block;margin-bottom:6px">Save this code somewhere safe — it cannot be shown again.</span>';
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
    // Carry over username from login form
    const loginUsername = document.getElementById('auth-username').value;
    document.getElementById('recovery-username').value = loginUsername;
    // Reset password/confirm fields and initialize validation state
    rcPwInput.value = '';
    rcPwConfirm.value = '';
    rcPwConfirm.disabled = true;
    rcPwReqs.classList.add('hidden');
    rcConfirmHint.classList.add('hidden');
    checkRecoveryReqs();
});

backToLoginBtn.addEventListener('click', () => {
    recoveryForm.classList.add('hidden');
    authFormEl.classList.remove('hidden');
    authFormEl.reset();
    checkLoginFields();
});

// Recovery form validation
const rcPwInput = document.getElementById('recovery-new-password');
const rcPwConfirm = document.getElementById('recovery-confirm-password');
const rcPwReqs = document.getElementById('recovery-password-reqs');
const rcConfirmHint = document.getElementById('recovery-confirm-hint');
const rcSubmitBtn = recoveryForm.querySelector('button[type="submit"]');
rcSubmitBtn.disabled = true;
rcPwConfirm.disabled = true;

function checkRecoveryReqs() {
    const pw = rcPwInput.value;
    const confirm = rcPwConfirm.value;
    const checks = {
        length: pw.length >= 16,
        letter: /[a-zA-Z]/.test(pw),
        number: /\d/.test(pw),
        symbol: /[^a-zA-Z0-9]/.test(pw),
    };
    const allMet = Object.values(checks).every(Boolean);

    for (const [key, met] of Object.entries(checks)) {
        const el = rcPwReqs.querySelector(`[data-req="${key}"]`);
        if (el) el.classList.toggle('met', met);
    }

    if (allMet) {
        rcPwReqs.classList.add('hidden');
    } else if (document.activeElement === rcPwInput) {
        rcPwReqs.classList.remove('hidden');
    }

    rcPwConfirm.disabled = !allMet;
    if (!allMet) {
        rcPwConfirm.value = '';
        rcConfirmHint.classList.add('hidden');
    }

    const passwordsMatch = pw === confirm && confirm.length > 0;
    const usernameOk = document.getElementById('recovery-username').value.length > 0;
    const codeOk = document.getElementById('recovery-code').value.trim().length > 0;
    rcSubmitBtn.disabled = !(allMet && passwordsMatch && usernameOk && codeOk);
}

function checkRecoveryConfirm() {
    const pw = rcPwInput.value;
    const confirm = rcPwConfirm.value;
    const matches = pw === confirm && confirm.length > 0;
    if (matches) {
        rcConfirmHint.classList.add('hidden');
    } else if (document.activeElement === rcPwConfirm) {
        rcConfirmHint.classList.remove('hidden');
    }
    checkRecoveryReqs();
}

rcPwInput.addEventListener('input', checkRecoveryReqs);
rcPwInput.addEventListener('focus', () => {
    const pw = rcPwInput.value;
    const allMet = pw.length >= 16 && /[a-zA-Z]/.test(pw) && /\d/.test(pw) && /[^a-zA-Z0-9]/.test(pw);
    if (!allMet) rcPwReqs.classList.remove('hidden');
});
rcPwInput.addEventListener('blur', () => {
    const pw = rcPwInput.value;
    const allMet = pw.length >= 16 && /[a-zA-Z]/.test(pw) && /\d/.test(pw) && /[^a-zA-Z0-9]/.test(pw);
    if (allMet) rcPwReqs.classList.add('hidden');
});
rcPwConfirm.addEventListener('input', checkRecoveryConfirm);
rcPwConfirm.addEventListener('focus', () => {
    const matches = rcPwInput.value === rcPwConfirm.value && rcPwConfirm.value.length > 0;
    if (!matches) rcConfirmHint.classList.remove('hidden');
});
rcPwConfirm.addEventListener('blur', () => {
    const matches = rcPwInput.value === rcPwConfirm.value && rcPwConfirm.value.length > 0;
    if (matches) rcConfirmHint.classList.add('hidden');
});
document.getElementById('recovery-username').addEventListener('input', checkRecoveryReqs);
document.getElementById('recovery-code').addEventListener('input', checkRecoveryReqs);

recoveryForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    recoveryError.classList.add('hidden');
    recoverySuccess.classList.add('hidden');

    const username = document.getElementById('recovery-username').value;
    const recoveryCode = document.getElementById('recovery-code').value.trim();
    const newPassword = rcPwInput.value;
    const confirmPassword = rcPwConfirm.value;

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
            recoveryError.textContent = text || 'Username and/or recovery code is incorrect.';
            recoveryError.classList.remove('hidden');
            return;
        }

        const data = await res.json();

        // Persist recovery code so it survives page refresh
        sessionStorage.setItem('pendingRecoveryCode', data.recovery_code);
        sessionStorage.setItem('pendingRecoveryUser', username);

        showRecoveryCode(data.recovery_code, username, newPassword);
    } catch {
        recoveryError.textContent = 'Connection failed.';
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
    updateNavActive('admin');
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
    updateNavActive('gallery');
    renderBreadcrumb();
});

// Admin create user validation
const adminUsername = document.getElementById('admin-new-username');
const adminPassword = document.getElementById('admin-new-password');
const adminPwConfirm = document.getElementById('admin-new-password-confirm');
const adminUsernameReqs = document.getElementById('admin-username-reqs');
const adminPwReqs = document.getElementById('admin-password-reqs');
const adminConfirmHint = document.getElementById('admin-confirm-hint');
const adminCreateBtn = adminCreateForm.querySelector('button[type="submit"]');
adminCreateBtn.disabled = true;
adminPwConfirm.disabled = true;

function checkAdminUsernameReqs() {
    const u = adminUsername.value;
    const checks = {
        ulen: u.length >= 3,
        umax: u.length <= 64,
    };
    const allMet = Object.values(checks).every(Boolean);
    for (const [key, met] of Object.entries(checks)) {
        const el = adminUsernameReqs.querySelector(`[data-req="${key}"]`);
        if (el) el.classList.toggle('met', met);
    }
    if (allMet) {
        adminUsernameReqs.classList.add('hidden');
    } else if (document.activeElement === adminUsername) {
        adminUsernameReqs.classList.remove('hidden');
    }
    checkAdminCreateBtn();
}

function checkAdminPwReqs() {
    const pw = adminPassword.value;
    const confirm = adminPwConfirm.value;
    const checks = {
        length: pw.length >= 16,
        letter: /[a-zA-Z]/.test(pw),
        number: /\d/.test(pw),
        symbol: /[^a-zA-Z0-9]/.test(pw),
    };
    const allMet = Object.values(checks).every(Boolean);
    for (const [key, met] of Object.entries(checks)) {
        const el = adminPwReqs.querySelector(`[data-req="${key}"]`);
        if (el) el.classList.toggle('met', met);
    }
    if (allMet) {
        adminPwReqs.classList.add('hidden');
    } else if (document.activeElement === adminPassword) {
        adminPwReqs.classList.remove('hidden');
    }
    adminPwConfirm.disabled = !allMet;
    if (!allMet) {
        adminPwConfirm.value = '';
        adminConfirmHint.classList.add('hidden');
    }
    checkAdminCreateBtn();
}

function checkAdminConfirm() {
    const pw = adminPassword.value;
    const confirm = adminPwConfirm.value;
    const matches = pw === confirm && confirm.length > 0;
    if (matches) {
        adminConfirmHint.classList.add('hidden');
    } else if (document.activeElement === adminPwConfirm) {
        adminConfirmHint.classList.remove('hidden');
    }
    checkAdminCreateBtn();
}

function checkAdminCreateBtn() {
    const u = adminUsername.value;
    const uMet = u.length >= 3 && u.length <= 64;
    const pw = adminPassword.value;
    const pwMet = pw.length >= 16 && /[a-zA-Z]/.test(pw) && /\d/.test(pw) && /[^a-zA-Z0-9]/.test(pw);
    const confirm = adminPwConfirm.value;
    const matches = pw === confirm && confirm.length > 0;
    adminCreateBtn.disabled = !(uMet && pwMet && matches);
}

adminUsername.addEventListener('input', () => { filterUsername({ target: adminUsername }); checkAdminUsernameReqs(); });
adminUsername.addEventListener('focus', () => {
    const u = adminUsername.value;
    const allMet = u.length >= 3 && u.length <= 64;
    if (!allMet) adminUsernameReqs.classList.remove('hidden');
});
adminUsername.addEventListener('blur', () => {
    const u = adminUsername.value;
    const allMet = u.length >= 3 && u.length <= 64;
    if (allMet) adminUsernameReqs.classList.add('hidden');
});
adminPassword.addEventListener('input', checkAdminPwReqs);
adminPassword.addEventListener('focus', () => {
    const pw = adminPassword.value;
    const allMet = pw.length >= 16 && /[a-zA-Z]/.test(pw) && /\d/.test(pw) && /[^a-zA-Z0-9]/.test(pw);
    if (!allMet) adminPwReqs.classList.remove('hidden');
});
adminPassword.addEventListener('blur', () => {
    const pw = adminPassword.value;
    const allMet = pw.length >= 16 && /[a-zA-Z]/.test(pw) && /\d/.test(pw) && /[^a-zA-Z0-9]/.test(pw);
    if (allMet) adminPwReqs.classList.add('hidden');
});
adminPwConfirm.addEventListener('input', checkAdminConfirm);
adminPwConfirm.addEventListener('focus', () => {
    const matches = adminPassword.value === adminPwConfirm.value && adminPwConfirm.value.length > 0;
    if (!matches) adminConfirmHint.classList.remove('hidden');
});
adminPwConfirm.addEventListener('blur', () => {
    const matches = adminPassword.value === adminPwConfirm.value && adminPwConfirm.value.length > 0;
    if (matches) adminConfirmHint.classList.add('hidden');
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

    btnLoading(adminCreateBtn);
    try {
        const res = await api('/api/admin/users', { json: { username, password, is_admin: isAdmin } });
        adminCreateSuccess.innerHTML = 'User "' + escapeHtml(res.username) + '" created.<br>Recovery code:<br><code style="user-select:all;font-size:11px;word-break:break-all;display:block;padding:8px;margin-top:4px;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius)">' + escapeHtml(res.recovery_code) + '</code>';
        adminCreateSuccess.classList.remove('hidden');
        adminCreateForm.reset();
        btnReset(adminCreateBtn);
        adminPwConfirm.disabled = true;
        adminCreateBtn.disabled = true;
        adminUsernameReqs.classList.add('hidden');
        adminPwReqs.classList.add('hidden');
        adminConfirmHint.classList.add('hidden');
        loadAdminUsers();
    } catch (err) {
        btnReset(adminCreateBtn);
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

document.querySelector('.logo').addEventListener('click', () => {
    document.getElementById('settings-view')?.classList.add('hidden');
    document.getElementById('admin-view')?.classList.add('hidden');
    galleryView.classList.remove('hidden');
    currentFolderId = null;
    renderGalleryItems();
    sessionStorage.setItem('activeView', 'gallery');
    updateNavActive('gallery');
});

function updateNavActive(view) {
    settingsBtn.classList.toggle('nav-active', view === 'settings');
    adminBtn.classList.toggle('nav-active', view === 'admin');
}

// --- Settings page ---
const settingsView = document.getElementById('settings-view');
const settingsBtn = document.getElementById('settings-btn');

function resetSettingsForm() {
    document.getElementById('settings-change-pw-form').reset();
    settingsNewPwConfirm.disabled = true;
    settingsChangePwBtn.disabled = true;
    settingsPwReqs.classList.add('hidden');
    settingsConfirmHint.classList.add('hidden');
    document.getElementById('settings-pw-error').classList.add('hidden');
    document.getElementById('settings-pw-success').classList.add('hidden');
    document.getElementById('settings-delete-form').reset();
    document.getElementById('settings-delete-error').classList.add('hidden');
}

settingsBtn.addEventListener('click', () => {
    galleryView.classList.add('hidden');
    adminView.classList.add('hidden');
    settingsView.classList.remove('hidden');
    sessionStorage.setItem('activeView', 'settings');
    updateNavActive('settings');
    resetSettingsForm();
});

document.getElementById('settings-back-btn').addEventListener('click', () => {
    settingsView.classList.add('hidden');
    galleryView.classList.remove('hidden');
    sessionStorage.setItem('activeView', 'gallery');
    updateNavActive('gallery');
    renderBreadcrumb();
});

// Theme picker
function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('darkreel-theme', theme);
    document.querySelectorAll('.theme-swatch').forEach(s => {
        s.classList.toggle('active', s.dataset.theme === theme);
    });
}
// Apply saved theme on load
applyTheme(localStorage.getItem('darkreel-theme') || 'classic');
document.getElementById('theme-picker').addEventListener('click', (e) => {
    const swatch = e.target.closest('.theme-swatch');
    if (swatch) applyTheme(swatch.dataset.theme);
});

// Settings password validation
const settingsOldPw = document.getElementById('settings-old-pw');
const settingsNewPw = document.getElementById('settings-new-pw');
const settingsNewPwConfirm = document.getElementById('settings-new-pw-confirm');
const settingsPwReqs = document.getElementById('settings-pw-reqs');
const settingsConfirmHint = document.getElementById('settings-confirm-hint');
const settingsChangePwBtn = document.getElementById('settings-change-pw-form').querySelector('button[type="submit"]');
settingsChangePwBtn.disabled = true;
settingsNewPwConfirm.disabled = true;

function checkSettingsPwReqs() {
    const pw = settingsNewPw.value;
    const confirm = settingsNewPwConfirm.value;
    const checks = {
        length: pw.length >= 16,
        letter: /[a-zA-Z]/.test(pw),
        number: /\d/.test(pw),
        symbol: /[^a-zA-Z0-9]/.test(pw),
    };
    const allMet = Object.values(checks).every(Boolean);

    for (const [key, met] of Object.entries(checks)) {
        const el = settingsPwReqs.querySelector(`[data-req="${key}"]`);
        if (el) el.classList.toggle('met', met);
    }

    if (allMet) {
        settingsPwReqs.classList.add('hidden');
    } else if (document.activeElement === settingsNewPw) {
        settingsPwReqs.classList.remove('hidden');
    }

    settingsNewPwConfirm.disabled = !allMet;
    if (!allMet) {
        settingsNewPwConfirm.value = '';
        settingsConfirmHint.classList.add('hidden');
    }

    const passwordsMatch = pw === confirm && confirm.length > 0;
    const oldPwOk = settingsOldPw.value.length > 0;
    settingsChangePwBtn.disabled = !(allMet && passwordsMatch && oldPwOk);
}

function checkSettingsConfirm() {
    const pw = settingsNewPw.value;
    const confirm = settingsNewPwConfirm.value;
    const matches = pw === confirm && confirm.length > 0;
    if (matches) {
        settingsConfirmHint.classList.add('hidden');
    } else if (document.activeElement === settingsNewPwConfirm) {
        settingsConfirmHint.classList.remove('hidden');
    }
    checkSettingsPwReqs();
}

settingsNewPw.addEventListener('input', checkSettingsPwReqs);
settingsNewPw.addEventListener('focus', () => {
    const pw = settingsNewPw.value;
    const allMet = pw.length >= 16 && /[a-zA-Z]/.test(pw) && /\d/.test(pw) && /[^a-zA-Z0-9]/.test(pw);
    if (!allMet) settingsPwReqs.classList.remove('hidden');
});
settingsNewPw.addEventListener('blur', () => {
    const pw = settingsNewPw.value;
    const allMet = pw.length >= 16 && /[a-zA-Z]/.test(pw) && /\d/.test(pw) && /[^a-zA-Z0-9]/.test(pw);
    if (allMet) settingsPwReqs.classList.add('hidden');
});
settingsNewPwConfirm.addEventListener('input', checkSettingsConfirm);
settingsNewPwConfirm.addEventListener('focus', () => {
    const matches = settingsNewPw.value === settingsNewPwConfirm.value && settingsNewPwConfirm.value.length > 0;
    if (!matches) settingsConfirmHint.classList.remove('hidden');
});
settingsNewPwConfirm.addEventListener('blur', () => {
    const matches = settingsNewPw.value === settingsNewPwConfirm.value && settingsNewPwConfirm.value.length > 0;
    if (matches) settingsConfirmHint.classList.add('hidden');
});
settingsOldPw.addEventListener('input', checkSettingsPwReqs);

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

    btnLoading(settingsChangePwBtn);
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
        settingsNewPwConfirm.disabled = true;
        btnReset(settingsChangePwBtn);
        settingsChangePwBtn.disabled = true;
        settingsPwReqs.classList.add('hidden');
        settingsConfirmHint.classList.add('hidden');
    } catch (err) {
        btnReset(settingsChangePwBtn);
        errEl.textContent = err.message || 'Failed to change password';
        errEl.classList.remove('hidden');
    }
});

document.getElementById('settings-delete-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const errEl = document.getElementById('settings-delete-error');
    errEl.classList.add('hidden');

    const password = document.getElementById('settings-delete-pw').value;
    const deleteBtn = e.target.querySelector('button[type="submit"]');

    showConfirmModal('Delete account', 'Are you sure you want to delete your account? All of your encrypted media will be permanently destroyed.', async () => {
        btnLoading(deleteBtn);
        try {
            await api('/api/auth/account', { method: 'DELETE', json: { password } });
            sessionStorage.clear();
            showAuth();
        } catch (err) {
            btnReset(deleteBtn);
            errEl.textContent = err.message || 'Failed to delete account';
            errEl.classList.remove('hidden');
        }
    });
});

const headerMenuBtn = document.getElementById('header-menu-btn');
const headerMenuPopup = document.getElementById('header-menu-popup');
const adminBtnMobile = document.getElementById('admin-btn-mobile');

function setGalleryDimmed(dimmed) {
    galleryGrid.classList.toggle('filter-dimmed', dimmed);
    galleryEmpty.classList.toggle('filter-dimmed', dimmed);
    document.getElementById('refresh-wrap')?.classList.toggle('filter-dimmed', dimmed);
}

function setFullDimmed(dimmed) {
    setGalleryDimmed(dimmed);
    document.getElementById('folder-bar').classList.toggle('filter-dimmed', dimmed);
}

headerMenuBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    filterPopup.classList.add('hidden');
    filterMenuBtn.classList.remove('nav-active');
    setGalleryDimmed(false);
    headerMenuPopup.classList.toggle('hidden');
    const open = !headerMenuPopup.classList.contains('hidden');
    headerMenuBtn.classList.toggle('nav-active', open);
    setFullDimmed(open);
});
document.addEventListener('click', (e) => {
    if (!headerMenuPopup.classList.contains('hidden') && !headerMenuPopup.contains(e.target) && e.target !== headerMenuBtn) {
        headerMenuPopup.classList.add('hidden');
        headerMenuBtn.classList.remove('nav-active');
        setFullDimmed(false);
    }
});

function closeHeaderMenu() {
    headerMenuPopup.classList.add('hidden');
    headerMenuBtn.classList.remove('nav-active');
    setFullDimmed(false);
}

async function doLogout() {
    try { await api('/api/auth/logout', { method: 'POST' }); } catch {}
    clearMasterKey();
    token = null;
    userId = null;
    sessionStorage.clear();
    showAuth();
}

document.getElementById('logout-btn').addEventListener('click', doLogout);
document.getElementById('logout-btn-mobile').addEventListener('click', () => { closeHeaderMenu(); doLogout(); });

document.getElementById('settings-btn-mobile').addEventListener('click', () => {
    closeHeaderMenu();
    galleryView.classList.add('hidden');
    adminView.classList.add('hidden');
    settingsView.classList.remove('hidden');
    sessionStorage.setItem('activeView', 'settings');
    updateNavActive('settings');
    resetSettingsForm();
});

document.getElementById('admin-btn-mobile').addEventListener('click', () => {
    closeHeaderMenu();
    galleryView.classList.add('hidden');
    settingsView.classList.add('hidden');
    adminView.classList.remove('hidden');
    sessionStorage.setItem('activeView', 'admin');
    updateNavActive('admin');
    loadAdminUsers();
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
    loginBtn.textContent = 'Login';
    checkLoginFields();
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
    document.getElementById('auth-username').focus();
}

let pollTimer = null;

async function showGallery() {
    authView.classList.add('hidden');
    header.classList.remove('hidden');
    // Show admin button if user is admin
    adminBtn.classList.toggle('hidden', !serverConfig.isAdmin);
    adminBtnMobile.classList.toggle('hidden', !serverConfig.isAdmin);

    // Restore active view
    const activeViewName = sessionStorage.getItem('activeView');
    galleryView.classList.add('hidden');
    adminView.classList.add('hidden');
    settingsView.classList.add('hidden');

    if (activeViewName === 'admin' && serverConfig.isAdmin) {
        adminView.classList.remove('hidden');
        loadAdminUsers();
        adminRegToggle.checked = serverConfig.allowRegistration || false;
        updateNavActive('admin');
    } else if (activeViewName === 'settings') {
        settingsView.classList.remove('hidden');
        updateNavActive('settings');
    } else {
        galleryView.classList.remove('hidden');
        updateNavActive('gallery');
        await loadMedia();
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

function folderNameExists(name, parentId, excludeId) {
    return getFolderChildren(parentId).some(f => f.id !== excludeId && f.name.toLowerCase() === name.toLowerCase());
}

function isFolderDescendant(folderId, ancestorId) {
    let current = folderId;
    while (current) {
        if (current === ancestorId) return true;
        const f = folders.find(x => x.id === current);
        current = f ? f.parentId : null;
    }
    return false;
}

function fileNameExistsInFolder(name, folderId) {
    return mediaItems.some(m => (m.folderId || null) === folderId && m.name && m.name.toLowerCase() === name.toLowerCase());
}

function uniqueFileName(name, folderId) {
    if (!fileNameExistsInFolder(name, folderId)) return name;
    const dot = name.lastIndexOf('.');
    const base = dot !== -1 ? name.substring(0, dot) : name;
    const ext = dot !== -1 ? name.substring(dot) : '';
    let n = 1;
    while (fileNameExistsInFolder(`${base} (${n})${ext}`, folderId)) n++;
    return `${base} (${n})${ext}`;
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

    // Full breadcrumb (desktop)
    let fullHtml = '<span class="breadcrumb-sep">/</span>';
    if (!currentFolderId && path.length === 0) {
        fullHtml += '<span class="breadcrumb-current">All Media</span>';
    } else {
        fullHtml += '<span class="breadcrumb-item" data-folder-id="">All Media</span>';
    }
    for (const folder of path) {
        fullHtml += '<span class="breadcrumb-sep">/</span>';
        if (folder.id === currentFolderId) {
            fullHtml += `<span class="breadcrumb-current">${escapeHtml(folder.name)}</span>`;
        } else {
            fullHtml += `<span class="breadcrumb-item" data-folder-id="${folder.id}">${escapeHtml(folder.name)}</span>`;
        }
    }

    // Compact breadcrumb (mobile) — / .. / CurrentFolder
    let compactHtml = '<span class="breadcrumb-sep">/</span>';
    if (!currentFolderId) {
        compactHtml += '<span class="breadcrumb-current">All Media</span>';
    } else {
        const parentId = path.length >= 2 ? path[path.length - 2].id : '';
        compactHtml += `<span class="breadcrumb-item" data-folder-id="${parentId}">..</span>`;
        compactHtml += '<span class="breadcrumb-sep">/</span>';
        const current = path[path.length - 1];
        compactHtml += `<span class="breadcrumb-current">${escapeHtml(current.name)}</span>`;
    }

    breadcrumb.innerHTML = `<span class="breadcrumb-full">${fullHtml}</span><span class="breadcrumb-compact">${compactHtml}</span>`;
    breadcrumb.querySelectorAll('.breadcrumb-item').forEach(el => {
        el.addEventListener('click', () => {
            currentFolderId = el.dataset.folderId || null;
            renderFolders();
            renderGalleryItems();
        });

        // Drop target for breadcrumb (drag to parent/root)
        el.addEventListener('dragover', (e) => { e.preventDefault(); e.dataTransfer.dropEffect = 'move'; el.classList.add('drag-over'); });
        el.addEventListener('dragleave', () => { el.classList.remove('drag-over'); });
        el.addEventListener('drop', async (e) => {
            e.preventDefault();
            el.classList.remove('drag-over');
            const targetFolderId = el.dataset.folderId || null;
            if (draggedFolder) {
                if ((draggedFolder.parentId || null) === (targetFolderId || null)) { draggedFolder = null; return; }
                if (targetFolderId && (draggedFolder.id === targetFolderId || isFolderDescendant(targetFolderId, draggedFolder.id))) return;
                if (folderNameExists(draggedFolder.name, targetFolderId, draggedFolder.id)) {
                    alert('A folder with that name already exists in the destination.');
                    return;
                }
                draggedFolder.parentId = targetFolderId;
                await saveFolderTree();
                renderGalleryItems();
                draggedFolder = null;
                return;
            }
            if (draggedItem) {
                try {
                    await moveItemToFolder(draggedItem, targetFolderId);
                    renderGalleryItems();
                } catch {}
                draggedItem = null;
                return;
            }
            // Desktop file drop onto breadcrumb
            e.stopPropagation();
            if (e.dataTransfer.files.length > 0) {
                handleDropUpload(e.dataTransfer.files, targetFolderId);
            }
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
            <svg class="folder-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
            <span class="folder-name">${escapeHtml(f.name)}</span>
            <button class="folder-menu-btn" data-folder-action="${f.id}" title="Folder options">⋮</button>
        `;

        el.addEventListener('click', (e) => {
            if (e.target.classList.contains('folder-menu-btn')) return;
            currentFolderId = f.id;
            renderFolders();
            renderGalleryItems();
        });

        // Drag source (folder, desktop)
        el.draggable = true;
        el.addEventListener('dragstart', (e) => {
            draggedFolder = f;
            el.classList.add('dragging');
            e.dataTransfer.effectAllowed = 'move';
            e.dataTransfer.setData('text/plain', f.id);
        });
        el.addEventListener('dragend', () => {
            el.classList.remove('dragging');
            draggedFolder = null;
        });

        // Touch drag (mobile)
        initTouchDrag(el, () => ({ type: 'folder', value: f }));

        // Drop target
        el.addEventListener('dragover', (e) => { e.preventDefault(); e.dataTransfer.dropEffect = 'move'; el.classList.add('drag-over'); });
        el.addEventListener('dragleave', () => { el.classList.remove('drag-over'); });
        el.addEventListener('drop', async (e) => {
            e.preventDefault();
            e.stopPropagation();
            el.classList.remove('drag-over');
            if (draggedFolder) {
                if (draggedFolder.id === f.id) return;
                if (isFolderDescendant(f.id, draggedFolder.id)) return;
                if ((draggedFolder.parentId || null) === f.id) { draggedFolder = null; return; }
                if (folderNameExists(draggedFolder.name, f.id, draggedFolder.id)) {
                    alert('A folder with that name already exists in the destination.');
                    return;
                }
                draggedFolder.parentId = f.id;
                await saveFolderTree();
                renderGalleryItems();
                draggedFolder = null;
                return;
            }
            if (draggedItem) {
                try {
                    await moveItemToFolder(draggedItem, f.id);
                    renderGalleryItems();
                } catch {}
                draggedItem = null;
                return;
            }
            // Desktop file drop into this folder
            if (e.dataTransfer.files.length > 0) {
                handleDropUpload(e.dataTransfer.files, f.id);
            }
        });

        const menuBtn = el.querySelector('.folder-menu-btn');
        menuBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            // Close any existing context menu
            document.querySelectorAll('.menu-active').forEach(el2 => el2.classList.remove('menu-active'));
            document.querySelectorAll('.folder-context-menu').forEach(m => m.remove());

            el.classList.add('menu-active');
            const menu = document.createElement('div');
            menu.className = 'folder-context-menu';

            const renameBtn = document.createElement('button');
            renameBtn.textContent = 'Rename';
            renameBtn.addEventListener('click', (ev) => {
                ev.stopPropagation();
                menu.remove();
                showRenameModal('Rename folder', f.name, (newName) => {
                    if (folderNameExists(newName, f.parentId, f.id)) {
                        return 'A folder with that name already exists here.';
                    }
                    f.name = newName;
                    saveFolderTree();
                    renderGalleryItems();
                    return null;
                });
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

            const moveBtn = document.createElement('button');
            moveBtn.textContent = 'Move';
            moveBtn.addEventListener('click', (ev) => {
                ev.stopPropagation();
                menu.remove();
                openMoveFolderModal(f);
            });

            const downloadBtn = document.createElement('button');
            downloadBtn.textContent = 'Download';
            downloadBtn.addEventListener('click', (ev) => {
                ev.stopPropagation();
                menu.remove();
                downloadFolder(f);
            });

            menu.appendChild(renameBtn);
            menu.appendChild(moveBtn);
            menu.appendChild(downloadBtn);
            menu.appendChild(deleteBtn);
            el.appendChild(menu);

            // Close menu on outside click
            const closeMenu = (ev) => {
                if (!menu.contains(ev.target)) {
                    menu.remove();
                    el.classList.remove('menu-active');
                    document.removeEventListener('click', closeMenu);
                }
            };
            setTimeout(() => document.addEventListener('click', closeMenu), 0);
        });

        elements.push(el);
    }
    return elements;
}

async function renderGalleryItems() {
    renderBreadcrumb();

    const folderEls = createFolderElements();

    let filtered = mediaItems.filter(m => (m.folderId || null) === currentFolderId);

    // Type filter
    const type = typeFilter.value;
    if (type) {
        filtered = filtered.filter(m => m.media_type === type);
    }

    // Sort
    const [sort, order] = sortSelect.value.split('-');
    filtered.sort((a, b) => {
        let cmp = 0;
        if (sort === 'date') {
            cmp = (a.created_at || '').localeCompare(b.created_at || '');
        } else if (sort === 'size') {
            cmp = (a.size || 0) - (b.size || 0);
        } else if (sort === 'name') {
            cmp = (a.name || '').localeCompare(b.name || '');
        }
        return order === 'desc' ? -cmp : cmp;
    });

    const allInFolder = mediaItems.filter(m => (m.folderId || null) === currentFolderId);
    if (filtered.length === 0 && folderEls.length === 0) {
        galleryEmpty.classList.remove('hidden');
        galleryEmpty.querySelector('p').textContent = allInFolder.length > 0
            ? 'No media found matching these filters.'
            : 'No media yet. Drag files here or click Upload to get started.';
    } else {
        galleryEmpty.classList.add('hidden');
    }

    // Build all elements first, then swap in one shot
    const fragment = document.createDocumentFragment();
    for (const el of folderEls) {
        fragment.appendChild(el);
    }
    for (const item of filtered) {
        const el = await createGalleryItem(item);
        fragment.appendChild(el);
    }

    // Remove old refresh button and swap grid content
    document.getElementById('refresh-wrap')?.remove();
    galleryGrid.innerHTML = '';
    galleryGrid.appendChild(fragment);
    addRefreshButton();
}

document.getElementById('new-folder-btn').addEventListener('click', () => {
    showRenameModal('New Folder', '', (name) => {
        if (folderNameExists(name, currentFolderId)) {
            return 'A folder with that name already exists here.';
        }
        const id = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2);
        folders.push({ id, name, parentId: currentFolderId });
        saveFolderTree();
        renderGalleryItems();
        return null;
    }, { placeholder: 'Folder name', buttonLabel: 'Create' });
});

// ─── Gallery ───
const galleryGrid = document.getElementById('gallery-grid');
const galleryEmpty = document.getElementById('gallery-empty');
const galleryLoading = document.getElementById('gallery-loading');
const pagination = document.getElementById('pagination');
// Custom select components
const sortSelect = { value: 'date-desc' };
const typeFilter = { value: '' };

function initCustomSelect(wrapId, state, key, linkedId) {
    const wrap = document.getElementById(wrapId);
    const trigger = wrap.querySelector('.custom-select-trigger');
    const optionsEl = wrap.querySelector('.custom-select-options');

    trigger.addEventListener('click', (e) => {
        e.stopPropagation();
        // Close all other custom selects
        document.querySelectorAll('.custom-select-options').forEach(o => {
            if (o !== optionsEl) o.classList.add('hidden');
        });
        optionsEl.classList.toggle('hidden');
    });

    optionsEl.addEventListener('click', (e) => {
        const opt = e.target.closest('.custom-select-option');
        if (!opt) return;
        e.stopPropagation();
        const val = opt.dataset.value;
        state[key] = val;
        wrap.dataset.value = val;
        trigger.innerHTML = opt.textContent + ' <span class="caret"></span>' + '<svg class="caret" width="10" height="10" viewBox="0 0 10 10"><path d="M2 4l3 3 3-3" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>';
        optionsEl.querySelectorAll('.custom-select-option').forEach(o => o.classList.toggle('selected', o.dataset.value === val));
        optionsEl.classList.add('hidden');

        // Sync linked select
        if (linkedId) {
            const linked = document.getElementById(linkedId);
            linked.dataset.value = val;
            const linkedTrigger = linked.querySelector('.custom-select-trigger');
            linkedTrigger.innerHTML = opt.textContent + ' <span class="caret"></span>' + '<svg class="caret" width="10" height="10" viewBox="0 0 10 10"><path d="M2 4l3 3 3-3" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>';
            linked.querySelectorAll('.custom-select-option').forEach(o => o.classList.toggle('selected', o.dataset.value === val));
        }
        renderGalleryItems();
    });
}

initCustomSelect('sort-select-wrap', sortSelect, 'value', 'sort-select-mobile-wrap');
initCustomSelect('type-filter-wrap', typeFilter, 'value', 'type-filter-mobile-wrap');
initCustomSelect('sort-select-mobile-wrap', sortSelect, 'value', 'sort-select-wrap');
initCustomSelect('type-filter-mobile-wrap', typeFilter, 'value', 'type-filter-wrap');

// Close custom selects on outside click
document.addEventListener('click', () => {
    document.querySelectorAll('.custom-select-options').forEach(o => o.classList.add('hidden'));
});

const filterPopup = document.getElementById('filter-popup');
const filterMenuBtn = document.getElementById('filter-menu-btn');
// Move popup to body so it's not clipped by any parent stacking context
document.body.appendChild(filterPopup);

filterMenuBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    closeHeaderMenu();
    filterPopup.classList.toggle('hidden');
    const open = !filterPopup.classList.contains('hidden');
    if (open) {
        const rect = filterMenuBtn.getBoundingClientRect();
        filterPopup.style.top = (rect.bottom + 18) + 'px';
        filterPopup.style.left = (rect.left + rect.width / 2) + 'px';
        filterPopup.style.transform = 'translateX(-50%)';
    }
    setGalleryDimmed(open);
    filterMenuBtn.classList.toggle('nav-active', open);
});
document.addEventListener('click', (e) => {
    if (!filterPopup.classList.contains('hidden') && !filterPopup.contains(e.target) && e.target !== filterMenuBtn) {
        filterPopup.classList.add('hidden');
        setGalleryDimmed(false);
        filterMenuBtn.classList.remove('nav-active');
    }
});

document.getElementById('prev-page').addEventListener('click', () => {
    if (currentPage > 1) { currentPage--; loadMedia(); }
});
document.getElementById('next-page').addEventListener('click', () => {
    if (currentPage * PAGE_SIZE < totalItems) { currentPage++; loadMedia(); }
});

let _silentRefresh = false;
function addRefreshButton() {
    document.getElementById('refresh-wrap')?.remove();
    const refreshBtn = document.createElement('button');
    refreshBtn.className = 'btn-refresh';
    refreshBtn.setAttribute('aria-label', 'Refresh');
    refreshBtn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>';
    refreshBtn.addEventListener('click', onRefreshClick);

    const hasItems = galleryGrid.querySelector('.gallery-item:not(.refresh-tile)') || galleryGrid.querySelector('.folder-item');
    if (hasItems) {
        const refreshTile = document.createElement('div');
        refreshTile.id = 'refresh-wrap';
        refreshTile.className = 'gallery-item refresh-tile';
        refreshTile.appendChild(refreshBtn);
        galleryGrid.appendChild(refreshTile);
    } else {
        const refreshWrap = document.createElement('div');
        refreshWrap.id = 'refresh-wrap';
        refreshWrap.className = 'gallery-refresh';
        refreshWrap.appendChild(refreshBtn);
        galleryEmpty.after(refreshWrap);
    }
}
function onRefreshClick() {
    _silentRefresh = true;
    const oldIds = mediaItems.map(m => m.id).join(',');
    const oldFolders = folders.map(f => f.id + f.name + (f.parentId || '')).join(',');
    galleryView.classList.add('refreshing');
    galleryGrid.style.minHeight = galleryGrid.offsetHeight + 'px';
    const wrap = document.getElementById('refresh-wrap');
    if (wrap) {
        const btn = wrap.querySelector('.btn-refresh');
        if (btn) btn.replaceWith(Object.assign(document.createElement('div'), { className: 'spinner' }));
    }
    const minDelay = new Promise(r => setTimeout(r, 1000));
    Promise.all([loadMedia(), minDelay]).finally(async () => {
        _silentRefresh = false;
        galleryGrid.style.minHeight = '';
        galleryView.classList.remove('refreshing');
        const newIds = mediaItems.map(m => m.id).join(',');
        const newFolders = folders.map(f => f.id + f.name + (f.parentId || '')).join(',');
        if (newIds !== oldIds || newFolders !== oldFolders) {
            await renderGalleryItems();
        }
        addRefreshButton();
    });
}

async function loadMedia() {
    if (!_silentRefresh) {
        galleryLoading.classList.remove('hidden');
        galleryGrid.innerHTML = '';
    }
    if (!_silentRefresh) galleryEmpty.classList.add('hidden');
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
        if (!_silentRefresh) await renderGalleryItems();

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

    if (!_silentRefresh) galleryLoading.classList.add('hidden');
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

    const menuBtn = document.createElement('button');
    menuBtn.className = 'item-menu-btn';
    menuBtn.textContent = '⋮';
    menuBtn.title = 'Options';
    menuBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        openItemContextMenu(item, div, menuBtn);
    });

    const nameEl = document.createElement('span');
    nameEl.className = 'item-name';

    // Name is already decrypted from metadata blob
    nameEl.textContent = item.name || 'Encrypted';

    div.appendChild(img);
    div.appendChild(badge);
    div.appendChild(menuBtn);
    div.appendChild(nameEl);
    div.addEventListener('click', (e) => {
        if (e.target.closest('.item-menu-btn') || e.target.closest('.folder-context-menu')) return;
        openViewer(item);
    });

    // Drag support (desktop)
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

    // Touch drag (mobile)
    initTouchDrag(div, () => ({ type: 'item', value: item }));

    return div;
}

function openItemContextMenu(item, parentEl, anchorBtn) {
    document.querySelectorAll('.menu-active').forEach(el => el.classList.remove('menu-active'));
    document.querySelectorAll('.folder-context-menu').forEach(m => m.remove());

    const menu = document.createElement('div');
    menu.className = 'folder-context-menu';

    const actions = [
        { label: 'Rename', handler: () => { menu.remove(); parentEl.classList.remove('menu-active'); renameItem(item); } },
        { label: 'Move', handler: () => { menu.remove(); parentEl.classList.remove('menu-active'); openMoveModal(item); } },
        { label: 'Download', handler: () => { menu.remove(); parentEl.classList.remove('menu-active'); downloadItem(item); } },
        { label: 'Delete', cls: 'danger', handler: () => { menu.remove(); parentEl.classList.remove('menu-active'); deleteItem(item); } },
    ];

    for (const a of actions) {
        const btn = document.createElement('button');
        btn.textContent = a.label;
        if (a.cls) btn.className = a.cls;
        btn.addEventListener('click', (e) => { e.stopPropagation(); a.handler(); });
        menu.appendChild(btn);
    }

    document.body.appendChild(menu);
    const btnRect = anchorBtn.getBoundingClientRect();
    menu.style.top = (btnRect.bottom + 4) + 'px';
    menu.style.right = (window.innerWidth - btnRect.right) + 'px';
    parentEl.classList.add('menu-active');

    const closeMenu = (ev) => {
        if (!menu.contains(ev.target)) {
            menu.remove();
            parentEl.classList.remove('menu-active');
            document.removeEventListener('click', closeMenu);
        }
    };
    setTimeout(() => document.addEventListener('click', closeMenu), 0);
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
const viewerPrev = document.getElementById('viewer-prev');
const viewerNext = document.getElementById('viewer-next');
let currentViewerItem = null;
let viewerList = [];
let viewerIndex = -1;

document.getElementById('viewer-close').addEventListener('click', closeViewer);
document.getElementById('viewer-delete').addEventListener('click', deleteCurrentItem);
document.getElementById('viewer-download').addEventListener('click', downloadCurrentItem);
document.getElementById('viewer-move').addEventListener('click', moveCurrentItem);
document.getElementById('viewer-rotate').addEventListener('click', rotateCurrentItem);
document.getElementById('viewer-rename').addEventListener('click', () => {
    if (!currentViewerItem) return;
    renameItem(currentViewerItem);
});
viewerPrev.addEventListener('click', (e) => { e.stopPropagation(); navigateViewer(-1); });
viewerNext.addEventListener('click', (e) => { e.stopPropagation(); navigateViewer(1); });

// Mobile three-dots menu
const viewerMoreBtn = document.getElementById('viewer-more');
const viewerMoreMenu = document.getElementById('viewer-more-menu');
viewerMoreBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    viewerMoreMenu.classList.toggle('hidden');
});
viewerMoreMenu.addEventListener('click', (e) => {
    const btn = e.target.closest('button');
    if (!btn) return;
    viewerMoreMenu.classList.add('hidden');
    const action = btn.dataset.action;
    if (action === 'move') moveCurrentItem();
    else if (action === 'rotate') rotateCurrentItem();
    else if (action === 'download') downloadCurrentItem();
    else if (action === 'delete') deleteCurrentItem();
});
document.addEventListener('click', () => viewerMoreMenu.classList.add('hidden'));

// Keyboard navigation
document.addEventListener('keydown', (e) => {
    if (viewer.classList.contains('hidden')) return;
    if (e.key === 'ArrowLeft') { e.preventDefault(); navigateViewer(-1); }
    else if (e.key === 'ArrowRight') { e.preventDefault(); navigateViewer(1); }
    else if (e.key === 'Escape') { e.preventDefault(); closeViewer(); }
});

// Touch swipe for mobile
let _touchStartX = 0;
let _touchStartY = 0;
viewer.addEventListener('touchstart', (e) => {
    _touchStartX = e.touches[0].clientX;
    _touchStartY = e.touches[0].clientY;
}, { passive: true });
viewer.addEventListener('touchend', (e) => {
    const dx = e.changedTouches[0].clientX - _touchStartX;
    const dy = e.changedTouches[0].clientY - _touchStartY;
    // Only trigger if horizontal swipe is dominant and long enough
    if (Math.abs(dx) > 60 && Math.abs(dx) > Math.abs(dy) * 1.5) {
        if (dx < 0) navigateViewer(1);
        else navigateViewer(-1);
    }
});

function navigateViewer(dir) {
    const newIndex = viewerIndex + dir;
    if (newIndex < 0 || newIndex >= viewerList.length) return;
    viewerIndex = newIndex;
    // Clean up current playback before switching
    if (viewerVideo._abortStreaming) {
        viewerVideo._abortStreaming();
        viewerVideo._abortStreaming = null;
    }
    viewerVideo.pause();
    viewerVideo.removeAttribute('src');
    viewerVideo.load();
    viewerImage.src = '';
    if (_viewerBlobUrl) {
        URL.revokeObjectURL(_viewerBlobUrl);
        _viewerBlobUrl = null;
    }
    if (viewerVideo._mediaSource) {
        try { viewerVideo._mediaSource.endOfStream(); } catch {}
        viewerVideo._mediaSource = null;
    }
    openViewer(viewerList[viewerIndex]);
}

function updateViewerNav() {
    viewerPrev.disabled = viewerIndex <= 0;
    viewerNext.disabled = viewerIndex >= viewerList.length - 1;
}

// --- Move item to folder (shared logic) ---
async function moveItemToFolder(item, newFolderId, skipDupeCheck) {
    // Already in this folder — no-op
    if ((item.folderId || null) === (newFolderId || null)) return true;
    if (!skipDupeCheck && item.name && fileNameExistsInFolder(item.name, newFolderId)) {
        alert('A file with that name already exists in the destination folder.');
        return false;
    }
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
    if (item.rotation) meta.rotation = item.rotation;

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
    return true;
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
    rootEl.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg> All Media (root)';
    rootEl.addEventListener('click', () => doMove(null));
    moveFolderList.appendChild(rootEl);

    // Recursively add folders
    function addFolders(parentId, depth) {
        for (const f of folders.filter(x => x.parentId === parentId)) {
            const el = document.createElement('div');
            el.className = 'move-folder-item' + (item.folderId === f.id ? ' active' : '');
            el.innerHTML = `<span class="move-folder-indent" style="width:${depth * 20}px"></span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg> ${escapeHtml(f.name)}`;
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
    moveFolderTarget = null;
});

let moveFolderTarget = null;

function openMoveFolderModal(folder) {
    moveFolderTarget = folder;
    moveFolderList.innerHTML = '';

    const descendantIds = new Set();
    function collectDescendants(id) {
        descendantIds.add(id);
        for (const child of folders.filter(x => x.parentId === id)) {
            collectDescendants(child.id);
        }
    }
    collectDescendants(folder.id);

    // Root option
    const rootEl = document.createElement('div');
    rootEl.className = 'move-folder-item' + ((folder.parentId || null) === null ? ' active' : '');
    rootEl.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg> All Media (root)';
    rootEl.addEventListener('click', () => doMoveFolder(null));
    moveFolderList.appendChild(rootEl);

    function addFolders(parentId, depth) {
        for (const f of folders.filter(x => x.parentId === parentId)) {
            if (descendantIds.has(f.id)) continue;
            const el = document.createElement('div');
            el.className = 'move-folder-item' + (folder.parentId === f.id ? ' active' : '');
            el.innerHTML = `<span class="move-folder-indent" style="width:${depth * 20}px"></span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg> ${escapeHtml(f.name)}`;
            el.addEventListener('click', () => doMoveFolder(f.id));
            moveFolderList.appendChild(el);
            addFolders(f.id, depth + 1);
        }
    }
    addFolders(null, 1);

    moveModal.classList.remove('hidden');
}

async function doMoveFolder(newParentId) {
    if (!moveFolderTarget) return;
    if ((moveFolderTarget.parentId || null) === (newParentId || null)) {
        moveModal.classList.add('hidden');
        moveFolderTarget = null;
        return;
    }
    if (folderNameExists(moveFolderTarget.name, newParentId, moveFolderTarget.id)) {
        alert('A folder with that name already exists in the destination.');
        return;
    }
    moveFolderTarget.parentId = newParentId;
    await saveFolderTree();
    moveModal.classList.add('hidden');
    moveFolderTarget = null;
    renderGalleryItems();
}

function moveCurrentItem() {
    if (currentViewerItem) openMoveModal(currentViewerItem);
}

// --- Delete folder confirmation ---
function showDeleteFolderConfirm(message, onConfirm) {
    showConfirmModal('Delete folder', message, onConfirm);
}

// --- Drag and drop ---
let draggedItem = null;
let draggedFolder = null;

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

// --- Touch drag-and-drop (mobile) ---
let _touchDragState = null;

function initTouchDrag(el, getData) {
    let timer = null;
    let startX, startY;

    el.addEventListener('contextmenu', (e) => e.preventDefault());

    el.addEventListener('touchstart', (e) => {
        if (_touchDragState) return;
        const touch = e.touches[0];
        startX = touch.clientX;
        startY = touch.clientY;
        timer = setTimeout(() => {
            timer = null;
            const data = getData();
            if (!data) return;
            e.preventDefault();

            // Create ghost
            const ghost = el.cloneNode(true);
            ghost.className = 'touch-drag-ghost';
            ghost.style.width = el.offsetWidth + 'px';
            ghost.style.height = el.offsetHeight + 'px';
            ghost.style.left = (startX - el.offsetWidth / 2) + 'px';
            ghost.style.top = (startY - el.offsetHeight / 2) + 'px';
            document.body.appendChild(ghost);

            el.classList.add('dragging');
            _touchDragState = { data, ghost, sourceEl: el };

            if (data.type === 'item') draggedItem = data.value;
            else if (data.type === 'folder') draggedFolder = data.value;
        }, 400);
    }, { passive: false });

    el.addEventListener('touchmove', (e) => {
        if (timer) {
            const t = e.touches[0];
            if (Math.abs(t.clientX - startX) > 10 || Math.abs(t.clientY - startY) > 10) {
                clearTimeout(timer);
                timer = null;
            }
            return;
        }
        if (!_touchDragState) return;
        e.preventDefault();
        const touch = e.touches[0];
        _touchDragState.ghost.style.left = (touch.clientX - _touchDragState.ghost.offsetWidth / 2) + 'px';
        _touchDragState.ghost.style.top = (touch.clientY - _touchDragState.ghost.offsetHeight / 2) + 'px';

        // Highlight drop targets
        const target = findDropTarget(touch.clientX, touch.clientY);
        document.querySelectorAll('.touch-drag-over').forEach(el => el.classList.remove('touch-drag-over'));
        if (target) target.classList.add('touch-drag-over');
    }, { passive: false });

    el.addEventListener('touchend', (e) => {
        if (timer) { clearTimeout(timer); timer = null; return; }
        if (!_touchDragState) return;
        e.preventDefault();

        const touch = e.changedTouches[0];
        const target = findDropTarget(touch.clientX, touch.clientY);
        document.querySelectorAll('.touch-drag-over').forEach(el => el.classList.remove('touch-drag-over'));

        if (target && _touchDragState) {
            const data = _touchDragState.data;
            // Find the target folder ID
            let targetFolderId = null;
            const folderItem = target.closest('.folder-item');
            const breadcrumbItem = target.closest('.breadcrumb-item');
            if (folderItem && folderItem.dataset.folderId) {
                targetFolderId = folderItem.dataset.folderId;
            } else if (breadcrumbItem && breadcrumbItem.dataset.folderId) {
                targetFolderId = breadcrumbItem.dataset.folderId;
            } else if (breadcrumbItem && !breadcrumbItem.dataset.folderId) {
                targetFolderId = null; // root
            }

            if (data.type === 'item') {
                moveItemToFolder(data.value, targetFolderId).then(() => renderGalleryItems()).catch(() => {});
            } else if (data.type === 'folder' && data.value.id !== targetFolderId) {
                data.value.parentId = targetFolderId;
                saveFolderTree().then(() => renderGalleryItems());
            }
        }

        cleanupTouchDrag();
    });

    el.addEventListener('touchcancel', () => {
        if (timer) { clearTimeout(timer); timer = null; }
        if (_touchDragState) cleanupTouchDrag();
    });
}

function cleanupTouchDrag() {
    if (!_touchDragState) return;
    _touchDragState.ghost.remove();
    _touchDragState.sourceEl.classList.remove('dragging');
    _touchDragState = null;
    draggedItem = null;
    draggedFolder = null;
}

function findDropTarget(x, y) {
    // Hide ghost temporarily so elementFromPoint doesn't hit it
    const ghost = _touchDragState?.ghost;
    if (ghost) ghost.style.display = 'none';
    const el = document.elementFromPoint(x, y);
    if (ghost) ghost.style.display = '';

    if (!el) return null;
    // Check for folder item drop target
    const folderItem = el.closest('.folder-item');
    if (folderItem) return folderItem;
    // Check for breadcrumb drop target
    const breadcrumb = el.closest('.breadcrumb-item');
    if (breadcrumb) return breadcrumb;
    return null;
}

// --- Drop-to-upload (no modal) ---
const dropUploadStatus = document.getElementById('drop-upload-status');

async function handleDropUpload(files, targetFolderId) {
    dropUploadStatus.innerHTML = '';
    let hasErrors = false;

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

        // Hide empty state and move refresh button out of the way
        galleryEmpty.classList.add('hidden');
        document.getElementById('refresh-wrap')?.remove();

        // Add a placeholder tile to the gallery
        const placeholder = document.createElement('div');
        placeholder.className = 'gallery-item';
        placeholder.innerHTML = '<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;gap:8px"><div class="spinner"></div><span style="font-size:12px;color:var(--text-dim)">' + escapeHtml(file.name) + '</span></div>';
        galleryGrid.appendChild(placeholder);

        try {
            const dummyEl = createUploadItem(file.name);
            dummyEl.style.display = 'none';
            document.body.appendChild(dummyEl);
            await uploadFile(file, dummyEl, targetFolderId);
            dummyEl.remove();
            statusSpan.textContent = 'Done';
            statusSpan.className = 'status done';
        } catch (e) {
            console.error('Drop upload failed:', e);
            placeholder.remove();
            statusSpan.textContent = 'Error';
            statusSpan.className = 'status error';
            hasErrors = true;
        }
    }

    if (hasErrors) {
        // Only show toast for failed uploads
        dropUploadStatus.querySelectorAll('.drop-upload-item').forEach(row => {
            if (!row.querySelector('.status.error')) row.remove();
        });
        dropUploadStatus.classList.remove('hidden');
        setTimeout(() => {
            dropUploadStatus.style.opacity = '0';
            setTimeout(() => {
                dropUploadStatus.classList.add('hidden');
                dropUploadStatus.style.opacity = '';
            }, 500);
        }, 3000);
    }
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

    // Build navigation list from current folder's media (only on first open, not during navigation)
    if (viewerList.length === 0 || !viewerList.includes(item)) {
        viewerList = mediaItems.filter(m => (m.folderId || null) === currentFolderId);
    }
    viewerIndex = viewerList.indexOf(item);
    updateViewerNav();

    viewerTitle.textContent = item.name || 'Encrypted file';
    // Only apply CSS rotation for videos (images are rotated at the file level)
    viewerImage.style.transform = '';
    viewerVideo.style.transform = (item.media_type === 'video' && item.rotation) ? `rotate(${item.rotation}deg)` : '';

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
    viewerVideo.srcObject = null;
    viewerVideo.load();
    viewerVideo.classList.add('hidden');
    viewerImage.classList.add('hidden');
    viewerImage.src = '';
    applyRotation(0);
    if (_viewerBlobUrl) {
        URL.revokeObjectURL(_viewerBlobUrl);
        _viewerBlobUrl = null;
    }
    if (viewerVideo._abortStreaming) {
        viewerVideo._abortStreaming();
        viewerVideo._abortStreaming = null;
    }
    if (viewerVideo._mediaSource) {
        try { viewerVideo._mediaSource.endOfStream(); } catch {}
        viewerVideo._mediaSource = null;
    }
    currentViewerItem = null;
    viewerList = [];
    viewerIndex = -1;
}

// Fetch with automatic retry on 429 (rate limit)
async function fetchRetry(url, options) {
    for (let attempt = 0; attempt < 5; attempt++) {
        const res = await fetch(url, options);
        if (res.status !== 429) return res;
        await new Promise(r => setTimeout(r, 1000 * Math.pow(2, attempt)));
    }
    return fetch(url, options);
}

async function showImage(item, fileKey) {
    viewerImage.classList.remove('hidden');
    const chunks = [];
    for (let i = 0; i < item.chunk_count; i++) {
        const res = await fetchRetry(`/api/media/${item.id}/chunk/${i}`, {
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
    const mime = item.mime_type || 'video/mp4';

    if (item.fragmented) {
        try {
            await playVideoMSE(item, fileKey);
        } catch (e) {
            console.error('MSE playback failed, falling back to blob:', e);
            await playVideoBlob(item, fileKey, mime);
        }
    } else {
        await playVideoBlob(item, fileKey, mime);
    }
}

/**
 * Read a 32-bit big-endian unsigned int from a Uint8Array.
 */
function readU32(buf, offset) {
    return ((buf[offset] << 24) | (buf[offset+1] << 16) | (buf[offset+2] << 8) | buf[offset+3]) >>> 0;
}

/**
 * Split fMP4 data at moof boundaries for segment-aligned chunking.
 * Returns [init_segment, segment_1, segment_2, ...] where the init segment
 * is everything before the first moof, and each media segment is a moof+mdat pair.
 */
function splitFMP4Segments(data) {
    const segments = [];
    let pos = 0;
    let initEnd = 0;

    while (pos + 8 <= data.length) {
        const size = readU32(data, pos);
        const type = String.fromCharCode(data[pos+4], data[pos+5], data[pos+6], data[pos+7]);

        let boxSize = size;
        if (size === 1 && pos + 16 <= data.length) {
            const hi = readU32(data, pos + 8);
            const lo = readU32(data, pos + 12);
            boxSize = hi * 0x100000000 + lo;
        }
        if (size === 0) boxSize = data.length - pos;
        if (boxSize < 8 || pos + boxSize > data.length) break;

        if (type === 'moof') {
            if (initEnd === 0) initEnd = pos;
            // moof + following mdat = one segment
            const moofEnd = pos + boxSize;
            let segEnd = moofEnd;
            // Check if next box is mdat
            if (moofEnd + 8 <= data.length) {
                const nextSize = readU32(data, moofEnd);
                const nextType = String.fromCharCode(data[moofEnd+4], data[moofEnd+5], data[moofEnd+6], data[moofEnd+7]);
                if (nextType === 'mdat') {
                    let mdatSize = nextSize;
                    if (nextSize === 1 && moofEnd + 16 <= data.length) {
                        const hi = readU32(data, moofEnd + 8);
                        const lo = readU32(data, moofEnd + 12);
                        mdatSize = hi * 0x100000000 + lo;
                    }
                    if (nextSize === 0) mdatSize = data.length - moofEnd;
                    segEnd = moofEnd + mdatSize;
                }
            }
            segments.push(data.slice(pos, segEnd));
            pos = segEnd;
            continue;
        }

        pos += boxSize;
    }

    // Init segment is everything before first moof
    if (initEnd > 0) {
        segments.unshift(data.slice(0, initEnd));
    }

    return segments;
}

async function playVideoMSE(item, fileKey) {
    const codecString = item.codecs || 'avc1.64001f,mp4a.40.2';
    const mseType = `video/mp4; codecs="${codecString}"`;

    const MSE = window.MediaSource || window.ManagedMediaSource;
    if (!MSE || !MSE.isTypeSupported(mseType)) {
        return playVideoBlob(item, fileKey, item.mime_type || 'video/mp4');
    }

    const isManagedMSE = MSE === window.ManagedMediaSource;
    const ms = new MSE();
    viewerVideo._mediaSource = ms;
    viewerVideo.disableRemotePlayback = true;
    if (isManagedMSE) {
        viewerVideo.srcObject = ms;
    } else {
        viewerVideo.src = URL.createObjectURL(ms);
    }
    // Call play() immediately while still in the user gesture context —
    // the browser queues it until SourceBuffer has data
    viewerVideo.play().catch(() => {});

    const sb = await new Promise((resolve, reject) => {
        if (ms.readyState === 'open') {
            try { resolve(ms.addSourceBuffer(mseType)); }
            catch (e) { reject(e); }
            return;
        }
        const timeout = setTimeout(() => reject(new Error('sourceopen timeout')), 5000);
        ms.addEventListener('sourceopen', () => {
            clearTimeout(timeout);
            try { resolve(ms.addSourceBuffer(mseType)); }
            catch (e) { reject(e); }
        }, { once: true });
    }).catch((e) => { console.warn('MSE setup failed:', e); return null; });

    if (!sb) {
        viewerVideo._mediaSource = null;
        return playVideoBlob(item, fileKey, item.mime_type || 'video/mp4');
    }

    if (item.duration && isFinite(item.duration)) {
        ms.duration = item.duration;
    }

    let aborted = false;
    viewerVideo._abortStreaming = () => { aborted = true; };

    // ManagedMediaSource (iOS) uses streaming events to control data flow
    let streamingAllowed = !isManagedMSE;
    if (isManagedMSE) {
        ms.addEventListener('startstreaming', () => { streamingAllowed = true; });
        ms.addEventListener('endstreaming', () => { streamingAllowed = false; });
    }

    // Cache for decrypted chunks (keeps init segment + recently fetched)
    const chunkCache = new Map();
    let fetchGeneration = 0; // incremented on seek to cancel stale fetches

    function waitForUpdate() {
        if (!sb.updating) return Promise.resolve();
        return new Promise(r => sb.addEventListener('updateend', r, { once: true }));
    }

    async function fetchChunk(index) {
        if (chunkCache.has(index)) return chunkCache.get(index);
        const res = await fetchRetry(`/api/media/${item.id}/chunk/${index}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!res.ok) throw new Error(`Chunk ${index} fetch failed: ${res.status}`);
        const encData = new Uint8Array(await res.arrayBuffer());
        const dec = await workerDecrypt('decryptChunk', encData, fileKey, index);
        chunkCache.set(index, dec);
        return dec;
    }

    async function appendData(data) {
        if (ms.readyState === 'closed') return;
        // Reopen if endOfStream was called
        if (ms.readyState === 'ended') {
            try { ms.duration = item.duration; } catch { return; }
        }
        await waitForUpdate();
        if (aborted) return;
        for (let attempt = 0; attempt < 5; attempt++) {
            try {
                sb.appendBuffer(data);
                await waitForUpdate();
                return;
            } catch (e) {
                if (e.name === 'QuotaExceededError') {
                    try {
                        if (sb.buffered.length > 0) {
                            const start = sb.buffered.start(0);
                            const end = sb.buffered.end(sb.buffered.length - 1);
                            sb.remove(start, start + (end - start) * 0.25);
                            await waitForUpdate();
                        }
                    } catch {}
                } else {
                    throw e;
                }
            }
        }
    }

    // Estimate which media chunk (1-based, since 0 is init) corresponds to a time
    function timeToChunk(time) {
        if (!item.duration || item.chunk_count <= 1) return 1;
        const mediaChunks = item.chunk_count - 1; // chunk 0 is init
        const ratio = Math.max(0, Math.min(time / item.duration, 1));
        return Math.max(1, Math.floor(ratio * mediaChunks) + 1);
    }

    // Check if a time is within any buffered range
    function isBuffered(time) {
        for (let i = 0; i < sb.buffered.length; i++) {
            if (time >= sb.buffered.start(i) && time <= sb.buffered.end(i)) return true;
        }
        return false;
    }

    // Fetch and append the init segment (chunk 0) — required before any media segments
    async function ensureInit() {
        const initData = await fetchChunk(0);
        if (aborted) return;
        await appendData(initData);
    }

    // Fetch and append chunks sequentially from startChunk, respecting generation
    async function streamFrom(startChunk, generation) {
        const PREFETCH = 4;

        for (let i = startChunk; i < item.chunk_count && !aborted && generation === fetchGeneration; i++) {
            // Prefetch ahead
            for (let p = i; p < Math.min(i + PREFETCH, item.chunk_count); p++) {
                if (!chunkCache.has(p)) {
                    // Fire and forget — will be awaited when we get to it
                    fetchChunk(p).catch(() => {});
                }
            }

            const dec = await fetchChunk(i);
            if (aborted || generation !== fetchGeneration) return;

            viewerTitle.textContent = item.name || 'Video';
            await appendData(dec);
            if (aborted || generation !== fetchGeneration) return;

            // Throttle: wait if we're far ahead of playback or ManagedMediaSource paused streaming
            if (i > startChunk + 2) {
                try {
                    while (!aborted && generation === fetchGeneration) {
                        if (!streamingAllowed) {
                            await new Promise(r => setTimeout(r, 500));
                            continue;
                        }
                        if (sb.buffered.length > 0) {
                            const ahead = sb.buffered.end(sb.buffered.length - 1) - viewerVideo.currentTime;
                            if (ahead >= 60) {
                                await new Promise(r => setTimeout(r, 2000));
                                continue;
                            }
                        }
                        break;
                    }
                } catch {}
            }
        }

        // If we finished all chunks for this generation, signal end of stream
        if (!aborted && generation === fetchGeneration) {
            await waitForUpdate();
            try { if (ms.readyState === 'open') ms.endOfStream(); } catch {}
        }
    }

    // Handle seeking to unbuffered regions
    let seekTimeout = null;

    viewerVideo.addEventListener('seeking', () => {
        if (aborted) return;

        // Debounce: wait 150ms for the user to stop scrubbing
        if (seekTimeout) clearTimeout(seekTimeout);
        seekTimeout = setTimeout(() => {
            seekTimeout = null;
            if (aborted) return;
            const seekTime = viewerVideo.currentTime;

            if (isBuffered(seekTime)) return;

            // Cancel current fetch pipeline
            fetchGeneration++;
            const gen = fetchGeneration;
            // Start 2 chunks before estimate to account for imprecision
            const targetChunk = Math.max(1, timeToChunk(seekTime) - 2);

            (async () => {
                try {
                    // Reopen MediaSource if ended (setting duration transitions ended→open)
                    if (ms.readyState === 'ended') {
                        try { ms.duration = item.duration; } catch {}
                    }

                    // Wait for any pending SourceBuffer operation to finish naturally
                    await waitForUpdate();
                    if (aborted || gen !== fetchGeneration) return;

                    // Stream from near the seek position — no buffer clear needed,
                    // fMP4 segments have absolute timestamps so MSE places them correctly
                    await streamFrom(targetChunk, gen);
                } catch (e) {
                    console.error('Seek error:', e);
                }
            })();
        }, 150);
    });

    try {
        // On ManagedMediaSource (iOS), wait for startstreaming before appending
        if (isManagedMSE && !streamingAllowed) {
            await new Promise((resolve) => {
                const check = () => { if (streamingAllowed || aborted) resolve(); else setTimeout(check, 100); };
                check();
            });
        }
        if (aborted) return;

        // Start: fetch init segment, then stream from chunk 1
        viewerTitle.textContent = `Buffering...`;
        await ensureInit();
        if (aborted) return;

        viewerTitle.textContent = item.name || 'Video';

        await streamFrom(1, fetchGeneration);
    } catch (e) {
        if (!aborted) viewerTitle.textContent = 'Playback failed: ' + e.message;
    }
}

async function playVideoBlob(item, fileKey, mime) {
    viewerTitle.textContent = `Decrypting... 0/${item.chunk_count}`;

    let aborted = false;
    viewerVideo._abortStreaming = () => { aborted = true; };

    try {
        const PARALLEL = Math.min(2, item.chunk_count);
        const decrypted = new Array(item.chunk_count);
        let nextFetch = 0;
        let done = 0;

        async function fetchWorker() {
            while (!aborted) {
                const idx = nextFetch++;
                if (idx >= item.chunk_count) break;
                const res = await fetchRetry(`/api/media/${item.id}/chunk/${idx}`, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                if (!res.ok) throw new Error(`Chunk ${idx} fetch failed: ${res.status}`);
                const encData = new Uint8Array(await res.arrayBuffer());
                decrypted[idx] = await workerDecrypt('decryptChunk', encData, fileKey, idx);
                done++;
                viewerTitle.textContent = `Decrypting... ${done}/${item.chunk_count}`;
            }
        }

        const workers = [];
        for (let w = 0; w < PARALLEL; w++) workers.push(fetchWorker());
        await Promise.all(workers);

        if (aborted) return;

        verifyChunkCount(item, done);
        const totalLen = decrypted.reduce((s, c) => s + c.length, 0);
        const merged = new Uint8Array(totalLen);
        let offset = 0;
        for (const c of decrypted) { merged.set(c, offset); offset += c.length; }

        viewerTitle.textContent = item.name || 'Video';

        const finalData = (mime === 'video/mp4') ? fastStartMP4(merged) : merged;
        const blob = new Blob([finalData], { type: mime });
        if (_viewerBlobUrl) URL.revokeObjectURL(_viewerBlobUrl);
        _viewerBlobUrl = URL.createObjectURL(blob);
        viewerVideo.src = _viewerBlobUrl;
        viewerVideo.play().catch(() => {});
    } catch (e) {
        if (!aborted) viewerTitle.textContent = 'Playback failed: ' + e.message;
    }
}

/**
 * Rearrange MP4 top-level boxes so moov comes before mdat (faststart).
 * Updates stco/co64 chunk offset tables to account for the move.
 * If already faststarted or not an MP4, returns data unchanged.
 */
function fastStartMP4(data) {
    if (data.length < 8) return data;

    // Parse top-level boxes
    const boxes = [];
    let pos = 0;
    while (pos + 8 <= data.length) {
        let size = (data[pos] << 24) | (data[pos+1] << 16) | (data[pos+2] << 8) | data[pos+3];
        const type = String.fromCharCode(data[pos+4], data[pos+5], data[pos+6], data[pos+7]);
        if (size === 0) size = data.length - pos; // box extends to EOF
        if (size < 8) break;
        const boxEnd = Math.min(pos + size, data.length);
        boxes.push({ type, start: pos, size: boxEnd - pos });
        pos = boxEnd;
    }

    const moovIdx = boxes.findIndex(b => b.type === 'moov');
    const mdatIdx = boxes.findIndex(b => b.type === 'mdat');
    if (moovIdx === -1 || mdatIdx === -1 || moovIdx < mdatIdx) return data;

    // Calculate how much mdat shifts forward (moov is inserted before it)
    // Offset delta = moov.size (moov moves from after mdat to before it,
    // so mdat and everything in it shifts forward by moov.size)
    // But we also need to account for any boxes between mdat and moov that stay.
    // Simple approach: compute new mdat position vs old mdat position.
    let newMdatPos = 0;
    for (let i = 0; i < mdatIdx; i++) {
        if (i !== moovIdx) newMdatPos += boxes[i].size;
    }
    newMdatPos += boxes[moovIdx].size; // moov inserted before mdat
    const oldMdatPos = boxes[mdatIdx].start;
    const delta = newMdatPos - oldMdatPos;

    // Copy moov and adjust stco/co64 offsets
    const moov = data.slice(boxes[moovIdx].start, boxes[moovIdx].start + boxes[moovIdx].size);
    adjustMoovOffsets(moov, delta);

    // Assemble result
    const result = new Uint8Array(data.length);
    let offset = 0;
    for (let i = 0; i < mdatIdx; i++) {
        if (i === moovIdx) continue;
        result.set(data.subarray(boxes[i].start, boxes[i].start + boxes[i].size), offset);
        offset += boxes[i].size;
    }
    result.set(moov, offset);
    offset += moov.length;
    for (let i = mdatIdx; i < boxes.length; i++) {
        if (i === moovIdx) continue;
        result.set(data.subarray(boxes[i].start, boxes[i].start + boxes[i].size), offset);
        offset += boxes[i].size;
    }
    return result.subarray(0, offset);
}

/** Recursively find and adjust stco/co64 boxes inside moov */
function adjustMoovOffsets(moov, delta) {
    let pos = 8; // skip moov header
    while (pos + 8 <= moov.length) {
        let size = (moov[pos] << 24) | (moov[pos+1] << 16) | (moov[pos+2] << 8) | moov[pos+3];
        const type = String.fromCharCode(moov[pos+4], moov[pos+5], moov[pos+6], moov[pos+7]);
        if (size === 0) size = moov.length - pos;
        if (size < 8) break;

        if (type === 'trak' || type === 'mdia' || type === 'minf' || type === 'stbl') {
            // Container box — recurse into its children
            const inner = moov.subarray(pos, pos + size);
            adjustContainerOffsets(inner, delta);
        } else if (type === 'stco') {
            // 32-bit chunk offset table
            const entryCount = (moov[pos+12] << 24) | (moov[pos+13] << 16) | (moov[pos+14] << 8) | moov[pos+15];
            for (let i = 0; i < entryCount; i++) {
                const o = pos + 16 + i * 4;
                const val = (moov[o] << 24) | (moov[o+1] << 16) | (moov[o+2] << 8) | moov[o+3];
                const newVal = val + delta;
                moov[o]   = (newVal >> 24) & 0xFF;
                moov[o+1] = (newVal >> 16) & 0xFF;
                moov[o+2] = (newVal >> 8) & 0xFF;
                moov[o+3] = newVal & 0xFF;
            }
        } else if (type === 'co64') {
            // 64-bit chunk offset table
            const entryCount = (moov[pos+12] << 24) | (moov[pos+13] << 16) | (moov[pos+14] << 8) | moov[pos+15];
            const view = new DataView(moov.buffer, moov.byteOffset, moov.byteLength);
            for (let i = 0; i < entryCount; i++) {
                const o = pos + 16 + i * 8;
                const hi = view.getUint32(o);
                const lo = view.getUint32(o + 4);
                const val = hi * 0x100000000 + lo + delta;
                view.setUint32(o, Math.floor(val / 0x100000000));
                view.setUint32(o + 4, val >>> 0);
            }
        }
        pos += size;
    }
}

function adjustContainerOffsets(box, delta) {
    let pos = 8;
    while (pos + 8 <= box.length) {
        let size = (box[pos] << 24) | (box[pos+1] << 16) | (box[pos+2] << 8) | box[pos+3];
        const type = String.fromCharCode(box[pos+4], box[pos+5], box[pos+6], box[pos+7]);
        if (size === 0) size = box.length - pos;
        if (size < 8) break;

        if (type === 'trak' || type === 'mdia' || type === 'minf' || type === 'stbl') {
            adjustContainerOffsets(box.subarray(pos, pos + size), delta);
        } else if (type === 'stco') {
            const entryCount = (box[pos+12] << 24) | (box[pos+13] << 16) | (box[pos+14] << 8) | box[pos+15];
            for (let i = 0; i < entryCount; i++) {
                const o = pos + 16 + i * 4;
                const val = (box[o] << 24) | (box[o+1] << 16) | (box[o+2] << 8) | box[o+3];
                const newVal = val + delta;
                box[o]   = (newVal >> 24) & 0xFF;
                box[o+1] = (newVal >> 16) & 0xFF;
                box[o+2] = (newVal >> 8) & 0xFF;
                box[o+3] = newVal & 0xFF;
            }
        } else if (type === 'co64') {
            const entryCount = (box[pos+12] << 24) | (box[pos+13] << 16) | (box[pos+14] << 8) | box[pos+15];
            const view = new DataView(box.buffer, box.byteOffset, box.byteLength);
            for (let i = 0; i < entryCount; i++) {
                const o = pos + 16 + i * 8;
                const hi = view.getUint32(o);
                const lo = view.getUint32(o + 4);
                const val = hi * 0x100000000 + lo + delta;
                view.setUint32(o, Math.floor(val / 0x100000000));
                view.setUint32(o + 4, val >>> 0);
            }
        }
        pos += size;
    }
}

function applyRotation(deg) {
    viewerVideo.style.transform = deg ? `rotate(${deg}deg)` : '';
    viewerImage.style.transform = deg ? `rotate(${deg}deg)` : '';
}

async function rotateCurrentItem() {
    if (!currentViewerItem) return;
    const item = currentViewerItem;

    if (item.media_type === 'video') {
        // Videos: CSS rotation stored in metadata (can't re-encode in browser)
        item.rotation = ((item.rotation || 0) + 90) % 360;
        applyRotation(item.rotation);
        await updateItemMetadata(item);
        return;
    }

    // Images: actually rotate the pixel data and re-upload
    viewerTitle.textContent = 'Rotating...';
    try {
        // Decrypt file
        const fileKeyEnc = base64ToBuffer(item.file_key_enc);
        const fileKey = await decryptFileKey(fileKeyEnc);
        const chunks = [];
        for (let i = 0; i < item.chunk_count; i++) {
            const res = await fetchRetry(`/api/media/${item.id}/chunk/${i}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const encData = new Uint8Array(await res.arrayBuffer());
            chunks.push(await workerDecrypt('decryptChunk', encData, fileKey, i));
        }
        const totalLen = chunks.reduce((s, c) => s + c.length, 0);
        const merged = new Uint8Array(totalLen);
        let off = 0;
        for (const c of chunks) { merged.set(c, off); off += c.length; }

        // Rotate via canvas
        const blob = new Blob([merged], { type: item.mime_type || 'image/jpeg' });
        const rotatedData = await rotateImageData(blob, item.mime_type || 'image/jpeg');

        // Generate thumbnail from rotated data
        const thumbBlob = new Blob([rotatedData], { type: item.mime_type || 'image/jpeg' });
        const thumbFile = new File([thumbBlob], 'thumb.jpg', { type: item.mime_type || 'image/jpeg' });
        let thumbData;
        try {
            thumbData = await generateThumbnail(thumbFile);
        } catch {
            thumbData = new Uint8Array([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46]);
        }

        // New keys
        const newFileKey = generateFileKey();
        const newThumbKey = generateFileKey();
        const newHashNonce = generateHashNonce();

        // Hash modification on rotated data
        const modifiedData = modifyHash(rotatedData, item.mime_type || 'image/jpeg', newHashNonce);

        // Encrypt
        const encThumb = await encryptChunk(thumbData, newThumbKey, 0);
        const chunkCount = Math.ceil(modifiedData.length / CHUNK_SIZE);
        const encChunks = [];
        for (let i = 0; i < chunkCount; i++) {
            const start = i * CHUNK_SIZE;
            const end = Math.min(start + CHUNK_SIZE, modifiedData.length);
            encChunks.push(await encryptChunk(modifiedData.slice(start, end), newFileKey, i));
        }

        const encFileKey = await encryptFileKey(newFileKey);
        const encThumbKey = await encryptFileKey(newThumbKey);

        // Get rotated dimensions
        const rotImg = new Image();
        const dimUrl = URL.createObjectURL(thumbBlob);
        const dims = await new Promise((resolve) => {
            rotImg.onload = () => { resolve({ width: rotImg.naturalWidth, height: rotImg.naturalHeight }); URL.revokeObjectURL(dimUrl); };
            rotImg.onerror = () => { resolve({ width: item.height || 0, height: item.width || 0 }); URL.revokeObjectURL(dimUrl); };
            rotImg.src = dimUrl;
        });

        // Build metadata (preserve name, folder, etc.)
        const metaPlain = {
            name: item.name,
            media_type: 'image',
            mime_type: item.mime_type || 'image/jpeg',
            size: modifiedData.length,
            chunk_count: chunkCount,
            width: dims.width,
            height: dims.height,
        };
        if (item.folderId) metaPlain.folderId = item.folderId;

        const metaBytes = new TextEncoder().encode(JSON.stringify(metaPlain));
        const encMetadata = await encryptBlock(metaBytes, getMasterKeyRaw());
        const metadataNonce = encMetadata.slice(0, 12);
        const metadataCiphertext = encMetadata.slice(12);

        const metadata = {
            chunk_count: chunkCount,
            file_key_enc: bufferToBase64(encFileKey),
            thumb_key_enc: bufferToBase64(encThumbKey),
            hash_nonce: bufferToBase64(newHashNonce),
            metadata_enc: bufferToBase64(metadataCiphertext),
            metadata_nonce: bufferToBase64(metadataNonce),
            created_at: item.created_at,
        };

        // Delete old
        await api(`/api/media/${item.id}`, { method: 'DELETE' });

        // Upload rotated
        const formData = new FormData();
        formData.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }));
        formData.append('thumbnail', new Blob([encThumb]));
        for (let i = 0; i < encChunks.length; i++) {
            formData.append(`chunk_${i}`, new Blob([encChunks[i]]));
        }

        const uploadRes = await fetch('/api/media/upload', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` },
            body: formData,
        });
        if (!uploadRes.ok) throw new Error('Upload failed');
        const uploadData = await uploadRes.json();
        const newId = uploadData.id;

        // Reload media and re-open viewer on the new item at the same position
        const savedIndex = viewerIndex;
        viewerList = [];
        await loadMedia();
        const newItem = mediaItems.find(m => m.id === newId);
        if (newItem) {
            // Rebuild viewer list and insert the new item at the original position
            viewerList = mediaItems.filter(m => (m.folderId || null) === currentFolderId);
            const actualIdx = viewerList.indexOf(newItem);
            if (actualIdx !== -1 && actualIdx !== savedIndex && savedIndex < viewerList.length) {
                // Move it to the saved position
                viewerList.splice(actualIdx, 1);
                viewerList.splice(savedIndex, 0, newItem);
            }
            viewerIndex = viewerList.indexOf(newItem);
            openViewer(newItem);
        } else {
            closeViewer();
        }
    } catch (e) {
        viewerTitle.textContent = 'Rotate failed: ' + e.message;
    }
}

function rotateImageData(blob, mimeType) {
    return new Promise((resolve, reject) => {
        const img = new Image();
        img.onload = () => {
            const canvas = document.createElement('canvas');
            // Swap width/height for 90° rotation
            canvas.width = img.naturalHeight;
            canvas.height = img.naturalWidth;
            const ctx = canvas.getContext('2d');
            ctx.translate(canvas.width / 2, canvas.height / 2);
            ctx.rotate(Math.PI / 2);
            ctx.drawImage(img, -img.naturalWidth / 2, -img.naturalHeight / 2);
            // Use original MIME if PNG, otherwise JPEG
            const outType = mimeType.includes('png') ? 'image/png' : 'image/jpeg';
            const quality = outType === 'image/jpeg' ? 0.95 : undefined;
            canvas.toBlob(outBlob => {
                if (!outBlob) { reject(new Error('Canvas export failed')); return; }
                outBlob.arrayBuffer().then(buf => resolve(new Uint8Array(buf)));
            }, outType, quality);
            URL.revokeObjectURL(img.src);
        };
        img.onerror = () => { URL.revokeObjectURL(img.src); reject(new Error('Image decode failed')); };
        img.src = URL.createObjectURL(blob);
    });
}

async function deleteCurrentItem() {
    if (!currentViewerItem) return;
    const item = currentViewerItem;
    showConfirmModal('Delete file', 'Delete this item? This cannot be undone.', () => {
        closeViewer();
        mediaItems = mediaItems.filter(m => m.id !== item.id);
        renderGalleryItems();
        api(`/api/media/${item.id}`, { method: 'DELETE' }).catch(e => {
            mediaItems.push(item);
            renderGalleryItems();
            showConfirmModal('Error', 'Delete failed: ' + e.message, () => {}, { buttonLabel: 'OK', buttonClass: 'btn-primary' });
        });
    });
}

async function deleteItem(item) {
    showConfirmModal('Delete file', 'Delete this item? This cannot be undone.', async () => {
        // Optimistic: remove from gallery immediately
        mediaItems = mediaItems.filter(m => m.id !== item.id);
        renderGalleryItems();
        // Fire delete in background
        api(`/api/media/${item.id}`, { method: 'DELETE' }).catch(e => {
            // Restore on failure
            mediaItems.push(item);
            renderGalleryItems();
            showConfirmModal('Error', 'Delete failed: ' + e.message, () => {}, { buttonLabel: 'OK', buttonClass: 'btn-primary' });
        });
    });
}

async function downloadCurrentItem() {
    if (!currentViewerItem) return;
    await downloadItem(currentViewerItem);
}

async function downloadItem(item) {
    try {
        const fileKeyEnc = base64ToBuffer(item.file_key_enc);
        const fileKey = await decryptFileKey(fileKeyEnc);

        const chunks = [];
        for (let i = 0; i < item.chunk_count; i++) {
            const res = await fetchRetry(`/api/media/${item.id}/chunk/${i}`, {
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

async function downloadFolder(folder) {
    // Collect all descendant folder IDs
    const allFolderIds = new Set();
    function collectIds(id) {
        allFolderIds.add(id);
        for (const child of folders.filter(x => x.parentId === id)) {
            collectIds(child.id);
        }
    }
    collectIds(folder.id);

    // Build a map of folder ID -> path prefix
    const folderPaths = new Map();
    function buildPaths(id, prefix) {
        folderPaths.set(id, prefix);
        for (const child of folders.filter(x => x.parentId === id)) {
            buildPaths(child.id, prefix + child.name + '/');
        }
    }
    buildPaths(folder.id, '');

    // Gather all media items in this folder tree
    const items = mediaItems.filter(m => allFolderIds.has(m.folderId));
    if (items.length === 0) {
        showConfirmModal('Download folder', 'This folder is empty.', () => {}, { buttonLabel: 'OK', buttonClass: 'btn-primary' });
        return;
    }

    try {
        const zipFiles = [];
        for (let idx = 0; idx < items.length; idx++) {
            const item = items[idx];
            const prefix = folderPaths.get(item.folderId) || '';
            const filename = prefix + (item.name || `file-${idx}`);

            const fileKeyEnc = base64ToBuffer(item.file_key_enc);
            const fileKey = await decryptFileKey(fileKeyEnc);

            const chunks = [];
            for (let i = 0; i < item.chunk_count; i++) {
                const res = await fetchRetry(`/api/media/${item.id}/chunk/${i}`, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                const encData = new Uint8Array(await res.arrayBuffer());
                const dec = await workerDecrypt('decryptChunk', encData, fileKey, i);
                chunks.push(dec);
            }
            verifyChunkCount(item, chunks.length);
            const totalLen = chunks.reduce((s, c) => s + c.length, 0);
            const merged = new Uint8Array(totalLen);
            let off = 0;
            for (const c of chunks) { merged.set(c, off); off += c.length; }

            zipFiles.push({ name: filename, data: merged });
        }

        const zipBlob = buildZip(zipFiles);
        const url = URL.createObjectURL(zipBlob);
        const a = document.createElement('a');
        a.href = url;
        a.download = folder.name + '.zip';
        a.click();
        URL.revokeObjectURL(url);
    } catch (e) {
        alert('Folder download failed: ' + e.message);
    }
}

/**
 * Minimal ZIP builder (store method, no compression).
 * Supports filenames and binary data. No external dependencies.
 */
function buildZip(files) {
    const entries = [];
    let offset = 0;

    for (const file of files) {
        const nameBytes = new TextEncoder().encode(file.name);
        const data = file.data;

        // CRC-32
        const crc = crc32(data);

        // Local file header (30 + name length)
        const localHeader = new Uint8Array(30 + nameBytes.length);
        const lv = new DataView(localHeader.buffer);
        lv.setUint32(0, 0x04034b50, true);   // signature
        lv.setUint16(4, 20, true);            // version needed
        lv.setUint16(6, 0, true);             // flags
        lv.setUint16(8, 0, true);             // compression (store)
        lv.setUint16(10, 0, true);            // mod time
        lv.setUint16(12, 0, true);            // mod date
        lv.setUint32(14, crc, true);          // crc-32
        lv.setUint32(18, data.length, true);  // compressed size
        lv.setUint32(22, data.length, true);  // uncompressed size
        lv.setUint16(26, nameBytes.length, true); // filename length
        lv.setUint16(28, 0, true);            // extra field length
        localHeader.set(nameBytes, 30);

        entries.push({ nameBytes, data, crc, localHeaderOffset: offset, localHeader });
        offset += localHeader.length + data.length;
    }

    // Central directory
    const centralParts = [];
    let centralSize = 0;
    for (const entry of entries) {
        const cd = new Uint8Array(46 + entry.nameBytes.length);
        const cv = new DataView(cd.buffer);
        cv.setUint32(0, 0x02014b50, true);    // signature
        cv.setUint16(4, 20, true);             // version made by
        cv.setUint16(6, 20, true);             // version needed
        cv.setUint16(8, 0, true);              // flags
        cv.setUint16(10, 0, true);             // compression
        cv.setUint16(12, 0, true);             // mod time
        cv.setUint16(14, 0, true);             // mod date
        cv.setUint32(16, entry.crc, true);     // crc-32
        cv.setUint32(20, entry.data.length, true); // compressed size
        cv.setUint32(24, entry.data.length, true); // uncompressed size
        cv.setUint16(28, entry.nameBytes.length, true); // filename length
        cv.setUint16(30, 0, true);             // extra field length
        cv.setUint16(32, 0, true);             // comment length
        cv.setUint16(34, 0, true);             // disk number
        cv.setUint16(36, 0, true);             // internal attrs
        cv.setUint32(38, 0, true);             // external attrs
        cv.setUint32(42, entry.localHeaderOffset, true); // local header offset
        cd.set(entry.nameBytes, 46);
        centralParts.push(cd);
        centralSize += cd.length;
    }

    // End of central directory
    const eocd = new Uint8Array(22);
    const ev = new DataView(eocd.buffer);
    ev.setUint32(0, 0x06054b50, true);         // signature
    ev.setUint16(4, 0, true);                  // disk number
    ev.setUint16(6, 0, true);                  // disk with central dir
    ev.setUint16(8, entries.length, true);      // entries on this disk
    ev.setUint16(10, entries.length, true);     // total entries
    ev.setUint32(12, centralSize, true);        // central dir size
    ev.setUint32(16, offset, true);             // central dir offset
    ev.setUint16(20, 0, true);                 // comment length

    // Assemble final blob
    const parts = [];
    for (const entry of entries) {
        parts.push(entry.localHeader);
        parts.push(entry.data);
    }
    for (const cd of centralParts) {
        parts.push(cd);
    }
    parts.push(eocd);

    return new Blob(parts, { type: 'application/zip' });
}

/** CRC-32 (IEEE) */
const _crc32Table = (() => {
    const table = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
        let c = i;
        for (let j = 0; j < 8; j++) {
            c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
        }
        table[i] = c;
    }
    return table;
})();

function crc32(data) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < data.length; i++) {
        crc = _crc32Table[(crc ^ data[i]) & 0xFF] ^ (crc >>> 8);
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
}


const renameModal = document.getElementById('rename-modal');
const renameInput = document.getElementById('rename-input');
const renameError = document.getElementById('rename-error');
const renameConfirmBtn = document.getElementById('rename-confirm');
const renameCancelBtn = document.getElementById('rename-cancel');
const renameTitle = document.getElementById('rename-title');

function showRenameModal(title, currentName, onConfirm, opts = {}) {
    renameTitle.textContent = title;
    renameInput.value = currentName;
    renameInput.placeholder = opts.placeholder || 'New name';
    renameConfirmBtn.textContent = opts.buttonLabel || 'Rename';
    renameError.classList.add('hidden');
    renameModal.classList.remove('hidden');
    renameInput.focus();
    if (currentName) renameInput.select();

    const cleanup = () => {
        renameModal.classList.add('hidden');
        renameConfirmBtn.removeEventListener('click', handleConfirm);
        renameCancelBtn.removeEventListener('click', handleCancel);
        renameInput.removeEventListener('keydown', handleKey);
        renameModal.removeEventListener('click', handleOverlay);
    };

    const handleConfirm = () => {
        const newName = renameInput.value.trim();
        if (!newName || newName === currentName) { cleanup(); return; }
        const err = onConfirm(newName);
        if (err) {
            renameError.textContent = err;
            renameError.classList.remove('hidden');
        } else {
            cleanup();
        }
    };

    const handleCancel = () => cleanup();
    const handleKey = (e) => { if (e.key === 'Enter') handleConfirm(); else if (e.key === 'Escape') cleanup(); };
    const handleOverlay = (e) => { if (e.target === renameModal) cleanup(); };

    renameConfirmBtn.addEventListener('click', handleConfirm);
    renameCancelBtn.addEventListener('click', handleCancel);
    renameInput.addEventListener('keydown', handleKey);
    renameModal.addEventListener('click', handleOverlay);
}

const confirmModal = document.getElementById('confirm-modal');
const confirmTitle = document.getElementById('confirm-title');
const confirmMessage = document.getElementById('confirm-message');
const confirmOkBtn = document.getElementById('confirm-ok');
const confirmCancelBtn = document.getElementById('confirm-cancel');

function showConfirmModal(title, message, onConfirm, opts = {}) {
    confirmTitle.textContent = title;
    confirmMessage.textContent = message;
    confirmOkBtn.textContent = opts.buttonLabel || 'Delete';
    confirmOkBtn.className = 'btn ' + (opts.buttonClass || 'btn-danger');
    confirmModal.classList.remove('hidden');

    const cleanup = () => {
        confirmModal.classList.add('hidden');
        confirmOkBtn.removeEventListener('click', handleOk);
        confirmCancelBtn.removeEventListener('click', handleCancel);
        document.removeEventListener('keydown', handleKey);
        confirmModal.removeEventListener('click', handleOverlay);
    };

    const handleOk = () => { cleanup(); onConfirm(); };
    const handleCancel = () => cleanup();
    const handleKey = (e) => { if (e.key === 'Escape') cleanup(); };
    const handleOverlay = (e) => { if (e.target === confirmModal) cleanup(); };

    confirmOkBtn.addEventListener('click', handleOk);
    confirmCancelBtn.addEventListener('click', handleCancel);
    document.addEventListener('keydown', handleKey);
    confirmModal.addEventListener('click', handleOverlay);
}

function renameItem(item) {
    showRenameModal('Rename file', item.name, (newName) => {
        if (fileNameExistsInFolder(newName, item.folderId || null)) {
            return 'A file with that name already exists in this folder.';
        }
        item.name = newName;
        updateItemMetadata(item);
        renderGalleryItems();
        if (currentViewerItem === item) viewerTitle.textContent = newName;
        return null;
    });
}

async function updateItemMetadata(item) {
    const meta = {
        name: item.name,
        media_type: item.media_type,
        mime_type: item.mime_type,
        size: item.size,
        chunk_count: item.chunk_count_trusted || item.chunk_count,
    };
    if (item.folderId) meta.folderId = item.folderId;
    if (item.width) meta.width = item.width;
    if (item.height) meta.height = item.height;
    if (item.duration) meta.duration = item.duration;
    if (item.rotation) meta.rotation = item.rotation;

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

async function uploadFile(file, itemEl, targetFolderId) {
    if (targetFolderId === undefined) targetFolderId = currentFolderId;
    const uploadName = uniqueFileName(file.name, targetFolderId);

    setUploadStatus(itemEl, 'Reading...');
    let fileData = new Uint8Array(await file.arrayBuffer());

    const mediaType = file.type.startsWith('video/') ? 'video' : 'image';
    let fragmented = false;

    // Remux videos to fMP4 for streaming playback
    if (mediaType === 'video') {
        setUploadStatus(itemEl, 'Preparing for streaming...');
        const fmp4Data = await remuxToFMP4(fileData, file.name);
        if (fmp4Data) {
            fileData = fmp4Data;
            fragmented = true;
        } else {
            console.warn('Video will be uploaded without streaming support (ffmpeg remux failed)');
            setUploadStatus(itemEl, 'Uploading without streaming...');
        }
    }

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

    // Hash modification (skip for videos to preserve container integrity)
    const modifiedData = mediaType === 'video' ? fileData : modifyHash(fileData, file.type, hashNonce);

    // Encrypt thumbnail
    const encThumb = await encryptChunk(thumbData, thumbKey, 0);

    // Split into segments: fMP4 at moof boundaries, otherwise fixed chunks
    let segments;
    if (fragmented) {
        segments = splitFMP4Segments(modifiedData);
    } else {
        segments = [];
        for (let start = 0; start < modifiedData.length; start += CHUNK_SIZE) {
            segments.push(modifiedData.slice(start, Math.min(start + CHUNK_SIZE, modifiedData.length)));
        }
    }
    const chunkCount = segments.length;

    // Encrypt segments
    const encChunks = [];
    for (let i = 0; i < chunkCount; i++) {
        encChunks.push(await encryptChunk(segments[i], fileKey, i));
        setUploadProgress(itemEl, Math.round(((i + 1) / chunkCount) * 50));
    }

    // Encrypt keys with master key
    const encFileKey = await encryptFileKey(fileKey);
    const encThumbKey = await encryptFileKey(thumbKey);

    // Build and encrypt metadata blob
    const metaPlain = {
        name: uploadName,
        media_type: mediaType,
        mime_type: fragmented ? 'video/mp4' : (file.type || 'application/octet-stream'),
        size: file.size,
        chunk_count: chunkCount,
    };
    if (fragmented) metaPlain.fragmented = true;
    if (targetFolderId) metaPlain.folderId = targetFolderId;

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
