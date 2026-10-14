// 12단계: 요청 추적 기록. 응답이 끝날 때 함수 이름·요청 ID·메서드·상태 코드 한 줄만 서버 로그에 남깁니다.
// 요청 ID는 화면(작전실 실측 표)이 보낸 X-Request-Id(UUID)를 쓰고, 없으면 Vercel 의 x-vercel-id 를 씁니다.
// 사용자 ID·토큰·메모 본문·주소의 쿼리는 남기지 않습니다. 허용·거부 판단은 바꾸지 않습니다(관측만).
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const VERCEL_ID = /^[a-z0-9:_-]{1,128}$/iu;

export function requestIdOf(request) {
  const own = request?.headers?.['x-request-id'];
  if (typeof own === 'string' && UUID.test(own)) return own.toLowerCase();
  const vercel = request?.headers?.['x-vercel-id'];
  return typeof vercel === 'string' && VERCEL_ID.test(vercel) ? vercel : 'none';
}

export function traceRequest(name, request, response) {
  const id = requestIdOf(request);
  const method = /^[A-Z]{3,7}$/u.test(request?.method ?? '') ? request.method : 'GET';
  try {
    response.setHeader?.('X-Request-Id', id);
    // 응답을 내보내기 "직전"(end 호출 시점)에 남깁니다. 응답이 끝난 뒤에는 Vercel 이 함수를 멈출 수 있어
    // 그때 남긴 줄은 로그에 기록되지 않을 수 있습니다.
    const end = response.end;
    if (typeof end === 'function') {
      let logged = false;
      response.end = function tracedEnd(...args) {
        if (!logged) {
          logged = true;
          try { console.info(`trace: ${name} id=${id} method=${method} status=${response.statusCode}`); } catch { /* 무시 */ }
        }
        return end.apply(this, args);
      };
    }
  } catch { /* 기록 실패는 응답을 바꾸지 않습니다. */ }
  return id;
}
