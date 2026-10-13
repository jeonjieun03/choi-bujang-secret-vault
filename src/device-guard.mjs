// 11단계: 보호 요청(메모·공지·복원)은 "서버가 등록 기기로 확인하고 판정기가 허용한 뒤" 받은 기기 세션이 있어야 합니다.
// 로그인 확인(verify-login) 뒤, 자료를 읽거나 쓰기 전에 부릅니다. 세션이 없거나, 만료됐거나, 그 사이 기기 승인이
// 취소되면 자료 없이 403 으로 거부합니다. 세션 ID 는 화면 메모리에만 있고 브라우저 저장소에 넣지 않습니다.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

const deny = (status, error, reason) => {
  console.info(`device: deny reason=${reason}`);
  return Object.freeze({ ok: false, status, error });
};

export async function requireApprovedDevice({ client, request, ownerId, now = Date.now() }) {
  const sessionId = request.headers?.['x-device-session'];
  if (!sessionId) return deny(403, 'DEVICE_APPROVAL_REQUIRED', 'no_device_session');
  if (typeof sessionId !== 'string' || !UUID.test(sessionId)) return deny(403, 'DEVICE_APPROVAL_REQUIRED', 'malformed_session');

  const { data: session, error } = await client.from('vault_device_sessions')
    .select('session_id, device_id, expires_at').eq('session_id', sessionId.toLowerCase()).eq('owner_id', ownerId).maybeSingle();
  if (error) { console.error('device: 세션 조회 실패', error.code ?? 'unknown'); return Object.freeze({ ok: false, status: 502, error: 'DEVICE_CHECK_UNAVAILABLE' }); }
  if (!session || Date.parse(session.expires_at) <= now) return deny(403, 'DEVICE_APPROVAL_REQUIRED', 'no_session');

  // 세션을 받은 뒤 승인이 취소(revoked)됐을 수 있으므로 매번 서버 명단을 다시 봅니다.
  const { data: device, error: deviceError } = await client.from('vault_devices')
    .select('status').eq('device_id', session.device_id).eq('owner_id', ownerId).maybeSingle();
  if (deviceError) { console.error('device: 기기 조회 실패', deviceError.code ?? 'unknown'); return Object.freeze({ ok: false, status: 502, error: 'DEVICE_CHECK_UNAVAILABLE' }); }
  if (device?.status !== 'approved') return deny(403, 'DEVICE_NOT_APPROVED', 'not_approved');
  return Object.freeze({ ok: true, deviceId: session.device_id });
}
