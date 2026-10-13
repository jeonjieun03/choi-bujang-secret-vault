// 확인용 기록: 로그인 토큰을 401로 거절한 이유를 서버 기록에 한 줄 남깁니다.
// 토큰 원문·서명·사용자 ID는 남기지 않고, 공개 정보인 발급처(iss)와 받는 주소(aud)만 남깁니다.
export function logAuthReject(name, authorization) {
  if (!authorization) {
    console.info(`${name}: auth missing_token`);
    return;
  }
  let iss = '?';
  let aud = '?';
  try {
    const part = String(authorization).replace(/^Bearer\s+/u, '').split('.')[1] ?? '';
    const claims = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
    const clean = (v) => String(Array.isArray(v) ? v.join(',') : v ?? '?').replace(/[^A-Za-z0-9.:/_,-]/gu, '').slice(0, 120);
    iss = clean(claims.iss);
    aud = clean(claims.aud);
  } catch { /* 형식이 틀린 토큰 */ }
  console.info(`${name}: auth rejected iss=${iss} aud=${aud}`);
}
