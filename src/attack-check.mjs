// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step === 3) return runStep3Checks(config);
  if (config.step !== 1) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  const response = await fetch(new URL('/data.json', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let visible = false;
  if (response.ok) {
    try {
      const data = await response.json();
      visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
        && data.notes.length > 0;
    } catch {
      // A non-JSON response is a failed check, not a successful deployment.
    }
  }
  return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
    observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` }];
}

// 3단계 자기 점검: 로그인 없이(또는 엉터리 토큰으로) 실제 요청을 보내고 받은 상태 코드만 기록합니다.
// 토큰·메모 본문·이메일은 기록하지 않습니다. 요청을 보내지 못하면 미실행으로 남깁니다.
// 정상 A 로그인 흐름은 비밀번호가 필요해 이 점검에서 요청하지 않습니다(미실행으로 기록).
function appUrlFrom(config) {
  let app;
  try { app = new URL(config.publicAppUrl); } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  return app;
}

async function statusOf(app, path, init = {}) {
  try {
    const response = await fetch(new URL(path, app), {
      redirect: 'error', signal: AbortSignal.timeout(10000), cache: 'no-store', ...init,
    });
    return { status: response.status };
  } catch (error) {
    return { error: error?.name === 'TimeoutError' ? '시간 초과' : '네트워크 오류' };
  }
}

async function runStep3Checks(config) {
  const app = appUrlFrom(config);
  const probeId = '00000000-0000-4000-8000-000000000000';
  const json = { 'Content-Type': 'application/json' };
  const malformed = { Authorization: 'Bearer not.a.token' };
  const checks = [
    ['static_data_json_removed', '/data.json', {}, '정적 /data.json이 없거나 가상 메모 확인 표시가 없음(404)', s => s === 404],
    ['anonymous_note_list', '/api/notes', {}, '로그인 없는 목록 조회는 401로 거부', s => s === 401],
    ['malformed_token_note_list', '/api/notes', { headers: malformed }, '형식이 틀린 토큰의 목록 조회는 401로 거부', s => s === 401],
    ['anonymous_note_create', '/api/notes', { method: 'POST', headers: json,
      body: JSON.stringify({ title: '점검', body: '점검' }) }, '로그인 없는 메모 추가는 401로 거부', s => s === 401],
    ['anonymous_note_read_one', `/api/notes/${probeId}`, {}, '로그인 없는 한 건 조회는 401로 거부', s => s === 401],
    ['anonymous_note_update', `/api/notes/${probeId}`, { method: 'PUT', headers: json,
      body: JSON.stringify({ title: '점검', body: '점검' }) }, '로그인 없는 메모 수정은 401로 거부', s => s === 401],
    ['anonymous_note_delete', `/api/notes/${probeId}`, { method: 'DELETE' }, '로그인 없는 메모 삭제는 401로 거부', s => s === 401],
  ];
  const results = [];
  for (const [attackId, path, init, expected, ok] of checks) {
    const result = await statusOf(app, path, init);
    const observed = result.error
      ? `미실행: ${result.error}로 요청을 보내지 못함`
      : `HTTP ${result.status} 응답 (${ok(result.status) ? '예상과 같음' : '예상과 다름'})`;
    results.push({ attackId, expected, observed });
  }
  results.push({ attackId: 'a_login_note_crud', expected: '정상 A 로그인은 메모 목록·추가·수정·삭제 가능',
    observed: '미실행: 로그인 비밀번호가 필요해 자동 점검에서 요청하지 않음' });
  return results;
}
