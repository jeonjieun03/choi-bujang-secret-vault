// 이 파일은 학생이 같은 프로젝트에서 이어서 구현합니다.
// 제공 UI를 받은 것만으로 단계 완료를 인정하지 않습니다.
//
// 13단계: renderIdentity — 지금 로그인한 사용자·기기·세션을 상태에 맞게 보여 줍니다.
// - 표시는 매번 받은 값({ me, devices, sessions })만으로 새로 만듭니다. 이전 값을 저장해 두지 않으므로
//   다시 불러오면 새 값으로 바뀌고, 오류일 때 이전 사용자 이름이 남지 않습니다.
// - 글자는 document.createElement 와 textContent 로만 넣습니다(HTML 로 해석하는 방법은 쓰지 않음).
// - 보안 기준 미충족(noncompliant)·만료(expired)·철회됨(revoked)·확인 불가(unknown)는 정상처럼 보이지 않게 "주의" 표시를 붙이고,
//   한국어 뜻과 함께 서버가 보낸 원래 값을 괄호로 보여 줍니다. 사용자·기기·세션은 이름(label)과 ID를 함께 보여 줍니다.
// - 기기 보안 상태는 서버가 알려 준 보안 기준 충족 여부를 보여 줄 뿐이며, 악성코드 검사나 치료 기능이 아닙니다.

const DEVICE_STATUS = Object.freeze({
  compliant: { text: '보안 기준 충족', normal: true },
  noncompliant: { text: '보안 기준 미충족', normal: false },
  unknown: { text: '확인 불가', normal: false },
});
const SESSION_STATUS = Object.freeze({
  active: { text: '활성', normal: true },
  expired: { text: '만료', normal: false },
  revoked: { text: '철회됨', normal: false },
  unknown: { text: '확인 불가', normal: false },
});
const MODE_NOTICE = Object.freeze({
  connected: null,
  demo: '예제 자료: 실제 회사 시스템에 연결된 결과가 아닙니다.',
  disconnected: '연결 없음: 회사 시스템(서버)에 연결되어 있지 않습니다.',
  unknown: '확인 불가: 연결 상태를 확인할 수 없습니다.',
});

function node(tag, text, attrs = {}) {
  const el = document.createElement(tag);
  if (text != null) el.textContent = String(text);
  for (const [name, value] of Object.entries(attrs)) el.setAttribute(name, String(value));
  return el;
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

// 상태 코드 → { 글자, 정상 여부 }. 모르는 값은 확인 불가로 보고 정상으로 바꾸지 않습니다.
function statusOf(table, code) {
  const known = typeof code === 'string' && Object.hasOwn(table, code) ? table[code] : null;
  const raw = typeof code === 'string' && code ? code : '값 없음';
  return known ? { label: `${known.text} (${raw})`, normal: known.normal } : { label: `확인 불가 (${raw})`, normal: false };
}

// "이름: 상태" 한 줄. 정상이 아니면 주의 표시를 붙입니다.
function statusLine(name, status, kind) {
  const line = node('p', null, { 'data-identity-field': kind, 'data-attention': status.normal ? 'no' : 'yes' });
  line.append(node('strong', `${name}: `), node('span', status.label));
  if (!status.normal) line.append(node('span', ' ⚠ 주의: 정상 상태가 아닙니다', { role: 'note' }));
  return line;
}

// 연결 방식 안내(예제 자료·연결 없음·확인 불가). loading·error 에서도 함께 보여 줍니다.
function modeNotices(parts) {
  const modes = [...new Set(parts.map((part) => (isObject(part) ? part.mode : null)))];
  const notices = [];
  for (const mode of modes) {
    if (mode == null || mode === 'connected') continue;
    notices.push(Object.hasOwn(MODE_NOTICE, mode) ? MODE_NOTICE[mode] : MODE_NOTICE.unknown);
  }
  return [...new Set(notices)].map((text) => node('p', text, { 'data-identity-mode': 'notice', role: 'note' }));
}

function errorMessage(part) {
  const message = isObject(part) && isObject(part.error) && typeof part.error.message === 'string' && part.error.message
    ? part.error.message : '서버가 이유를 알려 주지 않았습니다.';
  const code = isObject(part) && isObject(part.error) && typeof part.error.code === 'string' && part.error.code
    ? ` (${part.error.code})` : '';
  return `${message}${code}`;
}

// 서버 응답을 받았지만 계약과 다르거나 결과를 검증할 수 없을 때는 "연결 실패"가 아니라 "확인 불가"로 구분합니다.
const UNVERIFIED_CODES = new Set(['CONTRACT_MISMATCH', 'ENGINE_RESULT_UNVERIFIED']);
function errorKind(part) {
  const code = isObject(part) && isObject(part.error) ? part.error.code : null;
  return UNVERIFIED_CODES.has(code) ? '확인 불가' : '연결 실패';
}

function idText(value) {
  return typeof value === 'string' && value ? value : null;
}

// 기기·세션 목록 칸(보조 정보). 목록 자체를 못 불러오면 그 사실을 보여 줍니다.
function listSection(title, part, table, kind, labelOf) {
  const section = node('div', null, { 'data-identity-list': kind });
  section.append(node('h4', title));
  if (!isObject(part) || part.status === 'loading') {
    section.append(node('p', `${title}을(를) 불러오는 중입니다.`));
    return section;
  }
  if (part.status === 'error') {
    section.append(node('p', `${errorKind(part)}: ${title}을(를) 불러올 수 없습니다. ${errorMessage(part)}`, { role: 'alert' }));
    return section;
  }
  if (part.status !== 'ok' || !Array.isArray(part.data)) {
    section.append(node('p', `확인 불가: ${title} 자료의 형식을 확인할 수 없습니다.`, { role: 'alert' }));
    return section;
  }
  if (part.data.length === 0) {
    section.append(node('p', `${title}이(가) 없습니다.`));
    return section;
  }
  const list = node('ul');
  for (const item of part.data) {
    const status = statusOf(table, isObject(item) ? item.status : null);
    const li = node('li', null, { 'data-attention': status.normal ? 'no' : 'yes' });
    li.append(node('span', `${labelOf(item)}: ${status.label}`));
    if (!status.normal) li.append(node('span', ' ⚠ 주의', { role: 'note' }));
    list.append(li);
  }
  section.append(list);
  return section;
}

function renderIdentity({ me, devices, sessions } = {}) {
  const box = node('section', null, { 'data-student-identity': 'v13', 'aria-live': 'polite' });
  box.append(node('h3', '로그인·기기·세션 상태'));
  const notices = modeNotices([me, devices, sessions]);

  // 1) 불러오는 중
  if (!isObject(me) || me.status === 'loading') {
    box.setAttribute('data-identity-state', 'loading');
    box.append(node('p', '불러오는 중: 로그인한 사용자·기기·세션 정보를 서버에서 받고 있습니다.'), ...notices);
    return box;
  }

  // 2) 실패: 연결 실패와 서버 메시지만 보여 주고, 사용자·기기·세션 값은 하나도 그리지 않습니다.
  if (me.status === 'error') {
    box.setAttribute('data-identity-state', 'error');
    box.append(
      node('p', `${errorKind(me)}: ${errorMessage(me)}`, { role: 'alert' }),
      node('p', '로그인한 사용자 정보를 불러올 수 없어 사용자·기기·세션을 표시하지 않습니다. 연결을 확인한 뒤 「다시 불러오기」를 눌러 주세요.'),
      ...notices,
    );
    return box;
  }

  // 3) 응답 형식이 맞지 않음: 정상으로 바꾸지 않고 확인 불가로 보여 줍니다.
  const data = me.status === 'ok' && isObject(me.data) ? me.data : null;
  const user = data && isObject(data.user) ? data.user : null;
  const device = data && isObject(data.device) ? data.device : null;
  const session = data && isObject(data.session) ? data.session : null;
  if (!user || typeof user.label !== 'string' || !user.label) {
    box.setAttribute('data-identity-state', 'unknown');
    box.append(node('p', '확인 불가: 서버 응답에서 로그인한 사용자를 확인할 수 없습니다.', { role: 'alert' }), ...notices);
    return box;
  }

  // 4) 정상 응답: 사용자 이름, 기기 이름과 상태, 세션 상태
  box.setAttribute('data-identity-state', 'ok');
  const deviceStatus = statusOf(DEVICE_STATUS, device ? device.status : null);
  const sessionStatus = statusOf(SESSION_STATUS, session ? session.status : null);
  const userLine = node('p', null, { 'data-identity-field': 'user' });
  userLine.append(node('strong', '사용자: '), node('span', `${user.label} (ID ${idText(user.id) || '확인 불가'})`));
  const deviceName = device && idText(device.label) ? device.label : '(이름 없음)';
  const deviceId = device && idText(device.id) ? device.id : '확인 불가';
  const sessionId = session && idText(session.id) ? session.id : '확인 불가';
  box.append(
    userLine,
    statusLine(`기기 ${deviceName} (ID ${deviceId})`, deviceStatus, 'device'),
    statusLine(`세션 (ID ${sessionId})`, sessionStatus, 'session'),
  );
  if (!deviceStatus.normal || !sessionStatus.normal) {
    box.append(node('p', '이 PC 또는 접속은 지금 정상 상태가 아닙니다. 점검·다시 로그인이 필요한지 확인해 주세요.', { role: 'alert' }));
  }
  box.append(
    node('p', '기기 보안 상태는 서버가 알려 준 보안 기준 충족 여부이며, 악성코드 검사나 치료 기능이 아닙니다.', { 'data-identity-field': 'scope' }),
    ...notices,
    listSection('내 기기 목록', devices, DEVICE_STATUS, 'devices', (item) => `${(isObject(item) && idText(item.label)) || '(이름 없음)'} (ID ${(isObject(item) && idText(item.id)) || '확인 불가'})`),
    listSection('내 세션 목록', sessions, SESSION_STATUS, 'sessions', (item) => `세션 (ID ${(isObject(item) && idText(item.id)) || '확인 불가'})`),
  );
  return box;
}

// ── 14단계: 업무 앱 접근 판정 ──────────────────────────────────────────
// 입력: renderDecision({ status, mode, data?, error?, appId }), data = { appId, decision, reason, checkedAt }
// - 요청 전(idle)·요청 중(loading)·판정 수신(ok)·요청 실패(error)를 먼저 나눕니다.
// - 판정은 한국어 뜻과 서버가 보낸 원래 값을 함께 적고, 목록에 없는 값은 "판정 확인 불가"로 처리합니다.
// - 요청 실패는 접근 거부 판정이 아니며, 판정 확인 불가와 요청 실패는 허용처럼 보이지 않게 합니다.
const DECISIONS = {
  allow: { text: '접근 허용', note: '정책상 이 앱 접근이 허용되었습니다. 실제 앱 접속 성공을 보장하지는 않습니다.', normal: true },
  deny: { text: '접근 거부', note: '정책상 이 앱 접근이 거부되었습니다.', normal: false },
  challenge: { text: '추가 인증 또는 확인 필요', note: '접근하려면 추가 인증 또는 확인이 필요합니다. 이 화면이 추가 인증을 대신 수행하지 않습니다.', normal: false },
  unknown: { text: '판정 확인 불가', note: '서버 판정을 확인할 수 없습니다. 접근이 허용되지 않은 것으로 보고, 허용으로 간주하지 마세요.', normal: false },
};
const DECISION_SCOPE = '이 결과는 선택한 업무 앱 한 개에 대한 접근 판정이며, 전체 업무 앱 권한 목록이 아닙니다.';

function formatCheckedAt(value) {
  if (typeof value !== 'string' || !value) return '확인 불가 (판정 시각 없음)';
  const time = new Date(value);
  if (Number.isNaN(time.getTime())) return `확인 불가 (${value})`;
  return `${time.toLocaleString('ko-KR')} (${value})`;
}

function renderDecision({ status, mode, data, error, appId } = {}) {
  const box = node('section', null, { 'data-student-decision': 'v14', 'aria-live': 'polite' });
  box.append(node('h3', '업무 앱 접근 판정'));
  const notices = modeNotices([{ mode }]);
  const appText = typeof appId === 'string' && appId ? `앱 ID ${appId}` : '선택한 앱 없음';

  // 1) 요청 전
  if (status === 'idle') {
    box.setAttribute('data-decision-state', 'idle');
    box.append(node('p', '요청 전: 업무 앱을 골라 「접속 요청」을 눌러 주세요. 아직 접근 판정이 없습니다.'), ...notices);
    return box;
  }

  // 2) 요청 중
  if (status === 'loading') {
    box.setAttribute('data-decision-state', 'loading');
    box.append(node('p', `판정 확인 중: ${appText}의 접근 판정을 서버에 요청하고 있습니다.`), ...notices);
    return box;
  }

  // 3) 요청 실패: 판정이 아니므로 거부·허용 어느 쪽으로도 보이지 않게 합니다.
  if (status === 'error') {
    box.setAttribute('data-decision-state', 'error');
    box.setAttribute('data-decision', 'request-failed');
    box.append(node('p', `요청 실패: ${errorMessage({ error })}`, { role: 'alert' }));
    if (errorKind({ error }) === '확인 불가') {
      box.append(node('p', '확인 불가: 서버 응답을 검증할 수 없어 판정 결과를 확인할 수 없습니다.'));
    }
    box.append(
      node('p', `${appText}: 요청이 실패해 판정을 받지 못했습니다. 이것은 접근 거부 판정이 아니며, 접근 허용도 아닙니다. 「접속 요청」을 다시 눌러 확인해 주세요.`),
      ...notices,
    );
    return box;
  }

  // 4) 판정 수신
  if (status !== 'ok' || !isObject(data)) {
    box.setAttribute('data-decision-state', 'unknown');
    box.setAttribute('data-decision', 'unknown');
    box.append(node('p', `판정 확인 불가 (unknown): ${appText}의 판정 자료를 확인할 수 없습니다. 접근이 허용되지 않은 것으로 보세요.`, { role: 'alert' }), ...notices);
    return box;
  }
  const raw = typeof data.decision === 'string' && data.decision ? data.decision : 'unknown';
  const known = Object.hasOwn(DECISIONS, raw);
  const sameApp = !(typeof appId === 'string' && appId && data.appId !== appId);
  const info = known && sameApp ? DECISIONS[raw] : DECISIONS.unknown;
  const shownCode = (known && sameApp) || raw === 'unknown' ? raw : `unknown, 서버 값 ${raw}`;
  box.setAttribute('data-decision-state', 'ok');
  box.setAttribute('data-decision', known && sameApp ? raw : 'unknown');

  const result = node('p', null, { 'data-decision-field': 'decision', 'data-attention': info.normal ? 'no' : 'yes' });
  result.append(node('strong', '판정: '), node('span', `${info.text} (${shownCode})`));
  if (!info.normal) result.append(node('span', ' ⚠ 주의', { role: 'note' }));
  box.append(
    node('p', `대상: 앱 ID ${typeof data.appId === 'string' && data.appId ? data.appId : '확인 불가'}`, { 'data-decision-field': 'app' }),
    result,
    node('p', info.note, info.normal ? {} : { role: 'alert' }),
  );
  if (!sameApp) box.append(node('p', '확인 불가: 선택한 앱과 판정 결과의 앱 ID가 다릅니다.', { role: 'alert' }));
  box.append(
    node('p', `판정 이유: ${typeof data.reason === 'string' && data.reason ? data.reason : '확인 불가 (서버가 이유를 보내지 않음)'}`, { 'data-decision-field': 'reason' }),
    node('p', `판정 시각: ${formatCheckedAt(data.checkedAt)}`, { 'data-decision-field': 'checkedAt' }),
    node('p', DECISION_SCOPE),
    ...notices,
  );
  return box;
}

export function createStudentView() {
  return {
    renderIdentity,
    renderDecision,
    renderEvents() { return '학생 구현 대기: 본인 접속·XDR 기록을 연결하세요.'; },
    renderStatus() { return '학생 구현 대기: 기기·세션·알림과 연결 점검 상태를 구분하세요.'; },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
