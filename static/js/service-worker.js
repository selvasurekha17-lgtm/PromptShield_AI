/**
 * PromptShield AI — Service Worker
 *
 * Strategy:
 * - Cache shell assets (HTML, CSS, JS, fonts) on install.
 * - Network-first for API calls (/api/*) — offline fallback returns error JSON.
 * - Cache-first for static assets (/static/*).
 * - Navigation requests (SPA) return cached index.html when offline.
 * - Share Target POST (/share) is passed through to Flask; SW does not intercept POST body.
 */

'use strict';

const CACHE_NAME = 'promptshield-v1';

// Shell assets to pre-cache on install
const SHELL_ASSETS = [
  '/',
  '/static/css/style.css',
  '/static/js/app.js',
  '/static/js/charts.js',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png',
];

// ─── Install ──────────────────────────────────────────────────────────────────
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(SHELL_ASSETS).catch((err) => {
        // Non-fatal: some assets may not be reachable during install
        console.warn('[SW] Pre-cache partial failure:', err);
      });
    }).then(() => self.skipWaiting())
  );
});

// ─── Activate ─────────────────────────────────────────────────────────────────
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys
          .filter((key) => key !== CACHE_NAME)
          .map((key) => caches.delete(key))
      );
    }).then(() => self.clients.claim())
  );
});

// ─── Fetch Strategy ───────────────────────────────────────────────────────────
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET requests (POST /share, POST /api/analyze, etc.) — let them pass through
  if (request.method !== 'GET') return;

  // Skip cross-origin requests (CDN fonts, Chart.js, Three.js)
  if (url.origin !== self.location.origin) return;

  // API calls: network-first, no caching
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(
      fetch(request).catch(() => {
        return new Response(
          JSON.stringify({ error: 'Offline — API unavailable', code: 'OFFLINE' }),
          { status: 503, headers: { 'Content-Type': 'application/json' } }
        );
      })
    );
    return;
  }

  // Static assets: cache-first
  if (url.pathname.startsWith('/static/')) {
    event.respondWith(
      caches.match(request).then((cached) => {
        return cached || fetch(request).then((response) => {
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(request, clone));
          }
          return response;
        });
      })
    );
    return;
  }

  // Navigation (SPA + share target GET): network-first, fall back to cached /
  event.respondWith(
    fetch(request).then((response) => {
      if (response.ok) {
        const clone = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(request, clone));
      }
      return response;
    }).catch(() => {
      return caches.match('/') || caches.match(request);
    })
  );
});
