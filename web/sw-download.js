// Service worker for streaming downloads.
//
// Scope is narrowed to /_dl/ at registration time — the SW only intercepts
// requests to /_dl/<id> URLs used by this feature. It never sees login,
// API, static-asset, or any other origin traffic.
//
// Protocol:
//   1. The SPA opens a MessageChannel and posts {type: 'register-stream', id, ...}
//      to this SW, transferring port2.
//   2. This SW stores a ReadableStream keyed by id and acks 'registered' on
//      the port.
//   3. The SPA clicks an <a href="/_dl/<id>" download> link. The browser
//      fetches that URL; the SW's fetch handler responds with a streaming
//      Response backed by the ReadableStream. The browser shows a native
//      download UI with progress.
//   4. The SPA feeds decrypted chunks through the port via {type: 'chunk',
//      data: ArrayBuffer} messages (ArrayBuffers transferred, not copied).
//   5. {type: 'end'} closes the stream; {type: 'abort'} errors it.
//
// The SW holds no keys, no tokens, and no long-lived state beyond the set of
// in-flight streams. Decryption is done entirely in the SPA (or its web
// worker), and this SW only pipes already-plaintext bytes to the browser.

const streams = new Map(); // id -> { controller, port, filename, contentType, contentLength, stream }

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('message', (event) => {
    const data = event.data;
    if (!data || data.type !== 'register-stream') return;

    const { id, filename, contentType, contentLength } = data;
    const port = event.ports[0];
    if (!id || !port) return;

    const stream = new ReadableStream({
        start(controller) {
            streams.set(id, {
                controller,
                port,
                filename: filename || 'download',
                contentType: contentType || 'application/octet-stream',
                contentLength: typeof contentLength === 'number' ? contentLength : null,
                stream: null, // filled below
            });
            port.onmessage = (evt) => {
                const msg = evt.data;
                if (!msg) return;
                if (msg.type === 'chunk') {
                    try { controller.enqueue(new Uint8Array(msg.data)); } catch {}
                } else if (msg.type === 'end') {
                    try { controller.close(); } catch {}
                    streams.delete(id);
                } else if (msg.type === 'abort') {
                    try { controller.error(new Error('Download aborted')); } catch {}
                    streams.delete(id);
                }
            };
        },
        cancel() {
            try { port.postMessage({ type: 'cancel' }); } catch {}
            streams.delete(id);
        },
    });
    // Expose the ReadableStream to the fetch handler.
    const entry = streams.get(id);
    if (entry) entry.stream = stream;

    // Ack via the port so the SPA can safely navigate to /_dl/<id>.
    try { port.postMessage({ type: 'registered', id }); } catch {}
});

self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);
    if (!url.pathname.startsWith('/_dl/')) return;

    const id = url.pathname.slice('/_dl/'.length);
    if (!id) return;

    const entry = streams.get(id);
    if (!entry || !entry.stream) {
        event.respondWith(new Response(
            'Download session not registered or already consumed.',
            { status: 404, headers: { 'Content-Type': 'text/plain' } },
        ));
        return;
    }

    const safeName = entry.filename.replace(/["\r\n]/g, '');
    const headers = new Headers({
        'Content-Type': entry.contentType,
        'Content-Disposition': `attachment; filename="${safeName}"`,
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
    });
    if (entry.contentLength != null) {
        headers.set('Content-Length', String(entry.contentLength));
    }
    event.respondWith(new Response(entry.stream, { status: 200, headers }));
});
