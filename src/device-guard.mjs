// 11단계: 보호 요청마다 "서버가 승인한 기기"의 서명인지 확인합니다.
// 로그인 확인(verify-login) 뒤, 자료를 읽거나 쓰기 전에 부릅니다. 통과하지 못하면 자료 없이 거부합니다.
//
// 요청 머리:
//   X-Device-Session   기기 잠금 해제로 받은 세션 ID(UUID)
//   X-Device-Time      서명한 시각(밀리초). 서버 시각과 60초 넘게 차이 나면 거부
//   X-Device-Nonce     일회용 값. 같은 값을 다시 쓰면 거부(재사용 공격)
//   X-Device-Signature 메서드·경로·본문 해시·시각·일회용 값·세션 ID 를 이번 화면용 열쇠로 서명한 값
// 경로는 서버가 요청에서 직접 정한 "논리 경로"(예: /api/notes/<id>)로 다시 만들어 대조하므로,
// 서명 뒤 경로(다른 메모 ID 등)나 본문을 바꾸면 서명이 맞지 않아 거부됩니다.
import { bodyTextOf, canonicalRequest, verifyRequestSignature } from './device-auth.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const NONCE = /^[A-Za-z0-9_-]{16,64}$/u;
const MAX_SKEW_MS = 60_000;

const deny = (status, error, reason) => {
  console.info(`device: deny reason=${reason}`);
  return Object.freeze({ ok: false, status, error });
};

export async function requireApprovedDevice({ client, request, ownerId, path, now = Date.now() }) {
  const h = request.headers ?? {};
  const sessionId = h['x-device-session'];
  const time = h['x-device-time'];
  const nonce = h['x-device-nonce'];
  const signature = h['x-device-signature'];
  if (!sessionId && !time && !nonce && !signature) return deny(403, 'DEVICE_SIGNATURE_REQUIRED', 'unsigned');
  if (typeof sessionId !== 'string' || !UUID.test(sessionId) || typeof nonce !== 'string' || !NONCE.test(nonce)
      || typeof time !== 'string' || !/^\d{13}$/u.test(time) || typeof signature !== 'string') {
    return deny(403, 'DEVICE_SIGNATURE_INVALID', 'malformed');
  }
  if (Math.abs(now - Number(time)) > MAX_SKEW_MS) return deny(403, 'DEVICE_SIGNATURE_EXPIRED', 'stale_time');

  // 세션: 이 사용자 것이고 만료 전이어야 함
  const { data: session, error: sessionError } = await client.from('vault_device_sessions')
    .select('session_id, device_id, owner_id, session_jwk, expires_at')
    .eq('session_id', sessionId.toLowerCase()).eq('owner_id', ownerId).maybeSingle();
  if (sessionError) { console.error('device: 세션 조회 실패', sessionError.code ?? 'unknown'); return Object.freeze({ ok: false, status: 502, error: 'DEVICE_CHECK_UNAVAILABLE' }); }
  if (!session || Date.parse(session.expires_at) <= now) return deny(403, 'DEVICE_SESSION_REQUIRED', 'no_session');

  // 기기: 서버(DB)에서 승인된 기기여야 함(화면 버튼이나 설치 표시로는 바뀌지 않음)
  const { data: device, error: deviceError } = await client.from('vault_devices')
    .select('device_id, status').eq('device_id', session.device_id).eq('owner_id', ownerId).maybeSingle();
  if (deviceError) { console.error('device: 기기 조회 실패', deviceError.code ?? 'unknown'); return Object.freeze({ ok: false, status: 502, error: 'DEVICE_CHECK_UNAVAILABLE' }); }
  if (device?.status !== 'approved') return deny(403, 'DEVICE_NOT_APPROVED', 'not_approved');

  // 서명: 서버가 다시 만든 글(메서드·논리 경로·본문)과 맞아야 함
  const canonical = canonicalRequest({ method: request.method ?? 'GET', path, bodyText: bodyTextOf(request.body),
    time, nonce, sessionId: sessionId.toLowerCase() });
  if (!verifyRequestSignature(session.session_jwk, canonical, signature)) return deny(403, 'DEVICE_SIGNATURE_INVALID', 'bad_signature');

  // 재사용 방지: 같은 일회용 값은 한 번만
  const { error: nonceError } = await client.from('vault_request_nonces').insert({ nonce, session_id: session.session_id });
  if (nonceError?.code === '23505') return deny(403, 'DEVICE_SIGNATURE_REPLAYED', 'replayed');
  if (nonceError) { console.error('device: 일회용 값 저장 실패', nonceError.code ?? 'unknown'); return Object.freeze({ ok: false, status: 502, error: 'DEVICE_CHECK_UNAVAILABLE' }); }

  return Object.freeze({ ok: true, deviceId: session.device_id });
}
