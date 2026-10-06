// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step >= 3 && config.step <= 5) return runStep3Checks(config);
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

// 3·4단계 자기 점검: 로그인 없이(또는 엉터리 토큰으로) 실제 요청을 보내고 받은 상태 코드만 기록합니다.
// 응답에 Vercel 배포 표시(x-vercel-id)가 없으면 사이트가 아닌 중간 장비의 응답이므로 미실행으로 남깁니다.
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

async function statusOf(app, path, init = {}, origin = 'vercel') {
  try {
    const response = await fetch(new URL(path, app), {
      redirect: 'error', signal: AbortSignal.timeout(10000), cache: 'no-store', ...init,
    });
    // 응답이 정말 목적지에서 왔는지 확인합니다(중간 장비의 응답은 미실행으로 처리).
    const fromTarget = origin === 'vercel'
      ? Boolean(response.headers.get('x-vercel-id'))
      : [...response.headers.keys()].some(name => name.startsWith('sb-'));
    if (!fromTarget) return { error: '목적지에 닿지 못함(중간 장비 응답)' };
    return { status: response.status, response };
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
  if (config.step >= 5) {
    // 원본 자료 API를 공개(publishable) 키로 직접 요청: 권한이 없어 거부되어야 합니다.
    // 공개 키는 화면 코드에 원래 공개된 값이며, 결과에는 키를 기록하지 않습니다.
    let original = null;
    try { original = new URL(config.originalApiUrl); } catch { /* 아래에서 미실행 처리 */ }
    const page = await statusOf(app, '/');
    let html = '';
    if (page.response) { try { html = await page.response.text(); } catch { html = ''; } }
    const publishable = /sb_publishable_[A-Za-z0-9_-]{10,}/u.exec(html)?.[0] ?? null;
    let direct;
    if (!original || original.protocol !== 'https:' || original.search) {
      direct = '미실행: aleph.config.json의 originalApiUrl이 쿼리 없는 HTTPS 주소가 아님';
    } else if (!publishable) {
      direct = page.error ? `미실행: 화면을 읽지 못함(${page.error})` : '미실행: 화면에서 공개 키를 찾지 못함';
    } else {
      const result = await statusOf(original, original.pathname + '?select=*&limit=1',
        { headers: { apikey: publishable } }, 'supabase');
      direct = result.error ? `미실행: ${result.error}로 요청을 보내지 못함`
        : `HTTP ${result.status} 응답 (${result.status === 401 || result.status === 403 ? '예상과 같음' : '예상과 다름'})`;
    }
    results.push({ attackId: 'anon_key_original_api_read', expected: '공개 키로 원본 자료 API를 직접 조회하면 401 또는 403으로 거부', observed: direct });
    results.push({ attackId: 'static_server_key_scan', expected: '배포된 화면에 서버 전용 키(sb_secret_ 등)가 없음',
      observed: page.error ? `미실행: 화면을 읽지 못함(${page.error})`
        : (/sb_secret_|service_role/u.test(html) ? '화면에서 서버 전용 키 표시를 찾음 (예상과 다름)' : '화면에서 서버 전용 키 표시를 찾지 못함 (예상과 같음)') });
  }
  if (config.step >= 4) {
    results.push({ attackId: 'b_reads_a_note', expected: 'B 로그인으로 A 메모 ID를 조회하면 404로 거부',
      observed: '미실행: A·B 로그인 토큰이 필요해 자동 점검에서 요청하지 않음' });
    results.push({ attackId: 'b_updates_a_note', expected: 'B 로그인으로 A 메모를 수정하면 404로 거부',
      observed: '미실행: A·B 로그인 토큰이 필요해 자동 점검에서 요청하지 않음' });
    results.push({ attackId: 'b_deletes_a_note', expected: 'B 로그인으로 A 메모를 삭제하면 404로 거부',
      observed: '미실행: A·B 로그인 토큰이 필요해 자동 점검에서 요청하지 않음' });
    results.push({ attackId: 'owner_change_on_update', expected: '수정 본문으로 메모 주인을 바꾸면 403으로 거부',
      observed: '미실행: 로그인 토큰이 필요해 자동 점검에서 요청하지 않음' });
  }
  return results;
}
