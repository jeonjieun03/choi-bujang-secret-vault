// 11단계: 설치형 웹앱의 오프라인 안내용 서비스 워커입니다.
// - 미리 저장하는 것은 공개 파일(오프라인 안내 화면, 아이콘, manifest)뿐입니다.
// - 보호 요청(/api/...)과 배포 정보(/aleph.json)는 저장하지도, 가로채지도 않습니다. 항상 서버로 그대로 갑니다.
// - 화면 이동이 네트워크 오류로 실패할 때만 오프라인 안내 화면을 보여 줍니다.
// - 서비스 워커는 기기 승인·로그인을 판단하지 않습니다(설치 여부는 기기 확인이 아님).
const CACHE = 'vault-shell-v2';
const PUBLIC_FILES = ['/offline.html', '/icon-192.png', '/icon-512.png', '/manifest.webmanifest'];

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(PUBLIC_FILES)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', event => {
  event.waitUntil(caches.keys()
    .then(keys => Promise.all(keys.filter(key => key !== CACHE).map(key => caches.delete(key))))
    .then(() => self.clients.claim()));
});

self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/api/') || url.pathname === '/aleph.json') return; // 보호 요청·배포 정보는 손대지 않음
  if (request.mode === 'navigate') {
    // 화면은 항상 서버에서 새로 받고(브라우저 캐시도 쓰지 않음), 연결이 안 될 때만 오프라인 안내를 보여 줍니다.
    event.respondWith(fetch(request.url, { cache: 'no-store', credentials: 'same-origin' })
      .catch(() => caches.match('/offline.html')));
    return;
  }
  if (request.method === 'GET' && PUBLIC_FILES.includes(url.pathname)) {
    event.respondWith(caches.match(request).then(hit => hit ?? fetch(request)));
  }
});
