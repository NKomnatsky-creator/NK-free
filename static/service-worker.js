const CACHE = 'passvault-v10';
const CDN_ASSETS = [
    'https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css',
    'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css',
    'https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js'
];

self.addEventListener('install', e => {
    e.waitUntil(
        caches.open(CACHE).then(c =>
            Promise.allSettled(CDN_ASSETS.map(a =>
                c.add(new Request(a, { mode: 'no-cors' }))
            ))
        ).then(() => self.skipWaiting())
    );
});

self.addEventListener('activate', e => {
    e.waitUntil(
        caches.keys().then(keys =>
            Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
        ).then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', e => {
    const url = e.request.url;
    if (url.includes('/api/') || url.endsWith('/manifest.json') || e.request.method !== 'GET') return;

    if (e.request.mode === 'navigate') {
        e.respondWith(
            fetch(e.request).catch(() =>
                caches.match('/login').then(r => r || caches.match('/dashboard')).then(r =>
                    r || new Response('Offline', { status: 503, headers: { 'Content-Type': 'text/plain' } })
                )
            )
        );
        return;
    }

    const isStatic = url.includes('/static/');
    const isCDN = CDN_ASSETS.some(a => url.startsWith(a.split('?')[0]));

    e.respondWith(
        caches.match(e.request, { ignoreSearch: !isStatic }).then(r => {
            if (r) return r;
            return fetch(e.request).then(resp => {
                if (!resp) return resp;
                const cacheable = (resp.status === 200) || (resp.type === 'opaque');
                if (cacheable && (isStatic || isCDN)) {
                    const copy = resp.clone();
                    caches.open(CACHE).then(c => c.put(e.request, copy)).catch(() => {});
                }
                return resp;
            }).catch(() => caches.match(e.request));
        })
    );
});