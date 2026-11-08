const CACHE_NAME = 'cipher-v7';

const APP_SHELL = [
  './',
  './index.html',
  './crypto-v3.js',
  './crypto-v4.js',
  './recovery-phrase.js',
  './vendor/argon2.umd.min.js',
  './vendor/bip39-en.js',
  './manifest.json',
  './icon-192.png',
  './icon-512.png'
];

// 安裝：建立新版離線殼，並立即接手等待中的舊版。
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
  );
});

// 啟動：移除所有舊版 CIPHER 快取，接管已開啟的頁面。
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys
          .filter(key => key !== CACHE_NAME)
          .map(key => caches.delete(key))
      ))
      .then(() => self.clients.claim())
  );
});

async function networkFirst(request) {
  const cache = await caches.open(CACHE_NAME);

  try {
    const response = await fetch(request);
    if (response.ok && response.type === 'basic') {
      await cache.put(request, response.clone());
    }
    return response;
  } catch (error) {
    const cached = await cache.match(request);
    if (cached) return cached;
    if (request.mode === 'navigate') {
      return (await cache.match('./index.html')) || Response.error();
    }
    return Response.error();
  }
}

self.addEventListener('fetch', event => {
  const request = event.request;

  // 只處理同源 GET；避免攔截 API 寫入或其他網站資源。
  if (request.method !== 'GET' || !request.url.startsWith(self.location.origin)) return;

  // 先向網路確認最新版，離線時才退回快取。
  event.respondWith(networkFirst(request));
});
