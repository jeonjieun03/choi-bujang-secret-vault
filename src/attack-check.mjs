// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step >= 3 && config.step <= 11) return runStep3Checks(config);
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
  // 10단계: 점검 20개 이내를 지키려고 수정·삭제 비로그인 점검 대신 복원 경로 비로그인 점검을 넣습니다.
  if (config.step >= 10) {
    checks.splice(checks.findIndex(([id]) => id === 'anonymous_note_update'), 2,
      ['anonymous_note_restore', `/api/notes/${probeId}/restore`, { method: 'POST' }, '로그인 없는 메모 복원(POST /api/notes/:id/restore)은 401로 거부', s => s === 401]);
  }
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
  if (config.step >= 6) {
    // 6단계: 판정기 기기 등록 규칙. 판정기는 운영 엔진이 부르므로 여기서는 로컬 판정기를 가상 요청으로 직접 불러 봅니다.
    // 로컬 연습 결과이며 심판 판정이 아닙니다. 실제 미등록 기기 공격은 심판이 보냅니다.
    try {
      const { decide } = await import('./decider.mjs');
      const { fixtureRequests } = await import('../scripts/fixture-7.mjs');
      const { normal } = fixtureRequests();
      const ok = await decide(normal);
      const bad = await decide({ ...normal, requestId: crypto.randomUUID(), deviceRegistered: false });
      results.push({ attackId: 'local_registered_device_read', expected: '로컬 판정기: 등록 기기의 자료실 읽기는 allow',
        observed: `로컬 가상 요청 결과 ${ok.decision} · ${ok.reasonCode}` });
      results.push({ attackId: 'local_unregistered_device_read', expected: '로컬 판정기: 미등록 기기는 deny·device_not_registered',
        observed: `로컬 가상 요청 결과 ${bad.decision} · ${bad.reasonCode}` });
    } catch {
      results.push({ attackId: 'local_unregistered_device_read', expected: '로컬 판정기: 미등록 기기는 deny·device_not_registered',
        observed: '미실행: 로컬 판정기를 불러오지 못함' });
    }
    if (config.step >= 7) {
      try {
        const { decide } = await import('./decider.mjs');
        const { fixtureRequests } = await import('../scripts/fixture-7.mjs');
        const { suspicious } = fixtureRequests();
        const before = await decide(suspicious);
        const after = await decide({ ...suspicious, requestId: crypto.randomUUID(),
          stepUp: { verified: true, authAgeSeconds: 60 } });
        results.push({ attackId: 'local_composite_anomaly_step_up', expected: '로컬 판정기: 복합 이상 가상 사건은 step_up·step_up_required',
          observed: `로컬 가상 요청 결과 ${before.decision} · ${before.reasonCode}` });
        results.push({ attackId: 'local_step_up_verified_allow', expected: '로컬 판정기: 추가 확인을 마친 같은 사건은 allow',
          observed: `로컬 가상 요청 결과 ${after.decision} · ${after.reasonCode}` });
      } catch {
        results.push({ attackId: 'local_composite_anomaly_step_up', expected: '로컬 판정기: 복합 이상 가상 사건은 step_up·step_up_required',
          observed: '미실행: 로컬 판정기를 불러오지 못함' });
      }
      // 9단계부터는 점검 20개 이내를 지키려고 미실행 표시만 하던 이 항목을 뺍니다.
      if (config.step < 9) results.push({ attackId: 'relogin_block_then_allow', expected: '다시 로그인 전 자료 차단, 새 로그인 뒤 요청 허용',
        observed: '미실행: 재로그인 시각을 검증하는 제공 엔진이 이 환경에 없음' });
    }
    if (config.step >= 8) {
      try {
        const { decide } = await import('./decider.mjs');
        const { fixtureRequests } = await import('../scripts/fixture-7.mjs');
        const { normal } = fixtureRequests();
        const id = '11111111-2222-4333-8444-555555555555';
        const ask = (method, route, path, extra = {}) => decide({ ...normal, requestId: crypto.randomUUID(), method, route, path, ...extra });
        const own = await ask('PUT', 'PUT /notes/:id', '/notes/demo');
        const notice = await ask('PUT', 'PUT /notices/:id', `/notices/${id}`);
        const unknown = await ask('GET', 'GET /notes/:id', '/notes/export');
        results.push({ attackId: 'local_zone_own_note_update', expected: '로컬 판정기: 연습 주체의 자기 연습 메모(demo) 수정은 allow',
          observed: `로컬 가상 요청 결과 ${own.decision} · ${own.reasonCode}` });
        results.push({ attackId: 'local_zone_student_notice_update', expected: '로컬 판정기: 학생의 공지 수정은 deny·instructor_only',
          observed: `로컬 가상 요청 결과 ${notice.decision} · ${notice.reasonCode}` });
        results.push({ attackId: 'local_zone_function_path', expected: '로컬 판정기: :id 자리의 기능 경로(export)는 deny·route_not_allowed',
          observed: `로컬 가상 요청 결과 ${unknown.decision} · ${unknown.reasonCode}` });
      } catch {
        results.push({ attackId: 'local_zone_student_notice_update', expected: '로컬 판정기: 학생의 공지 수정은 deny·instructor_only',
          observed: '미실행: 로컬 판정기를 불러오지 못함' });
      }
      results.push({ attackId: 'cross_zone_api_requests', expected: '다른 구역 메모 조회·수정·목록과 학생의 공지 수정은 자료 API에서 404·403',
        observed: '미실행: A·B 로그인 토큰이 필요해 자동 점검에서 요청하지 않음' });
    }
    if (config.step >= 10) {
      // 10단계: 침해 전 정책 사본을 다시 읽어 검증(SHA-256·판정기 대조)하고 시험 정책과 비교한 로컬 결과입니다.
      try {
        const { loadVerifiedBackup, loadTestPolicy, diffPolicies } = await import('./policy-diff.mjs');
        const { fileURLToPath } = await import('node:url');
        const root = fileURLToPath(new URL('..', import.meta.url));
        const backup = await loadVerifiedBackup(root);
        const diff = diffPolicies(loadTestPolicy(`${root}policy/test-policy.json`), backup.snapshot);
        results.push({ attackId: 'local_policy_backup_verified', expected: '로컬: 정책 사본 SHA-256·판정기 대조 일치, 시험 정책과 차이 없음',
          observed: `로컬 정책 사본 ${backup.manifest.version} 검증 일치 · 시험 정책 차이 ${diff.changes.length}개` });
      } catch (error) {
        results.push({ attackId: 'local_policy_backup_verified', expected: '로컬: 정책 사본 SHA-256·판정기 대조 일치, 시험 정책과 차이 없음',
          observed: `로컬 정책 사본 검증 중단: ${String(error?.message ?? 'unknown').slice(0, 120)}` });
      }
    }
    if (config.step >= 9) {
      // 9단계: 로컬 탐지기에 가상 사건만 넣어 본 결과입니다. 실제 회수·경과 시간은 심판이 확인합니다.
      try {
        const { detect, revocationProposal } = await import('./detect.mjs');
        const start = Date.UTC(2026, 9, 1, 10, 0, 0);
        const reads = (count, { device, network, offset = 0 }) => Array.from({ length: count }, (_, i) => ({
          at: new Date(start + offset + i * 2000).toISOString(), method: 'GET',
          identity: { sub: 'learner_fixture' }, deviceId: device, network }));
        const normal = reads(30, { device: 'a'.repeat(16), network: 'usual' });
        const composite = [...normal, ...reads(150, { device: 'b'.repeat(16), network: 'new_network', offset: 1000 })];
        const kept = detect(normal);
        const revoke = revocationProposal(composite);
        results.push({ attackId: 'local_detect_normal_kept', expected: '로컬 탐지기: 평소 네트워크 정상 조회 30건은 observe(회수 제안 없음)',
          observed: `로컬 가상 사건 결과 ${kept.action}` });
        results.push({ attackId: 'local_detect_composite_revoke', expected: '로컬 탐지기: 새 네트워크+10분 안 다량 조회는 기기 한 개 대상 propose_revocation·burst_read',
          observed: `로컬 가상 사건 결과 ${revoke.action} · ${revoke.reasonCode ?? '-'} · 대상 기기 ${revoke.deviceId === 'b'.repeat(16) ? '새 네트워크 기기 1개' : '확인 필요'}` });
      } catch {
        results.push({ attackId: 'local_detect_composite_revoke', expected: '로컬 탐지기: 복합 의심 사건은 propose_revocation',
          observed: '미실행: 로컬 탐지기를 불러오지 못함' });
      }
    } else {
      results.push({ attackId: 'unregistered_device_relay', expected: '미등록 기기 인증서·인증서 없는 통로 요청은 거부',
        observed: '미실행: 운영 통로(mTLS) 요청은 심판이 보내며 자동 점검에서 요청하지 않음' });
    }
  }
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
  // 8단계부터는 cross_zone_api_requests 한 항목이 B의 A 메모 읽기·수정·삭제·주인 변경을 함께 다룹니다(점검 20개 이내).
  if (config.step >= 4 && config.step < 8) {
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
