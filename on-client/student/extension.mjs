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

// ── 15단계: 내 접속 기록과 저장된 XDR 경보 ──────────────────────────────
// 입력: renderEvents({ status, mode, data?, error? }), data = 기록 배열
// - 받은 배열을 복사해 at 기준 최신순으로 정렬합니다. 원본 배열과 서버 자료는 바꾸지 않습니다.
// - 「기록 종류」「업무 앱」「접속 상태」 필터는 서버에 다시 묻지 않고 받은 배열 안에서만 거릅니다(전체 = all).
// - 「<event.id> 상세」 버튼으로 근거(evidence)·규칙(rules)·세 상태(access·session·device)를 따로 보여 줍니다.
// - renderEvents가 새로 불릴 때마다(다시 불러오기 포함) 필터와 상세 선택을 처음 상태로 되돌리고 새로 그립니다.
// - 실제 조치 버튼은 만들지 않습니다.
const EVENT_KINDS = { access: '접속 기록', xdr: 'XDR 경보' };
const ACCESS_STATE = { allowed: { text: '허용됨', normal: true }, denied: { text: '거부됨', normal: false }, unknown: { text: '확인 불가', normal: false } };
const EVENT_SCOPE = '조회 범위: 앱 서버가 내 SDP 감사 기록에서 확인한 본인의 최근 기록(최대 40건)과 서버에 이미 저장된 XDR 경보입니다. 모든 직원의 전체 이력이나 실시간 전체 위협 탐지가 아니며, 화면을 열 때 새로 탐지하지 않습니다.';

function eventStateText(table, code) {
  if (typeof code === 'string' && Object.hasOwn(table, code)) return { label: `${table[code].text}(${code})`, normal: table[code].normal };
  return { label: `확인 불가(${typeof code === 'string' && code ? code : 'unknown'})`, normal: false };
}

function eventKindText(kind) {
  return typeof kind === 'string' && Object.hasOwn(EVENT_KINDS, kind) ? `${EVENT_KINDS[kind]}(${kind})` : `확인 불가(${typeof kind === 'string' && kind ? kind : 'unknown'})`;
}

function eventAppText(appId) {
  return typeof appId === 'string' && appId ? appId : '앱 확인 불가(appId 없음)';
}

function eventTime(at) {
  const ms = typeof at === 'string' ? Date.parse(at) : NaN;
  if (Number.isNaN(ms)) return `시각 확인 불가(${typeof at === 'string' && at ? at : '값 없음'})`;
  return `${new Date(ms).toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' })} 한국 시각 (${at})`;
}

function eventTimeValue(event) {
  const ms = isObject(event) && typeof event.at === 'string' ? Date.parse(event.at) : NaN;
  return Number.isNaN(ms) ? -Infinity : ms;
}

// 근거·규칙 목록: id와 text를 함께 적고, 배열이 아니면 확인 불가로 보여 줍니다.
function idTextList(title, items, field) {
  const wrap = node('div', null, { 'data-event-detail-field': field });
  wrap.append(node('h5', title));
  if (!Array.isArray(items)) {
    wrap.append(node('p', `확인 불가: ${title} 자료가 없습니다.`));
    return wrap;
  }
  if (items.length === 0) {
    wrap.append(node('p', `${title}: 없음`));
    return wrap;
  }
  const list = node('ul');
  for (const item of items) {
    const id = isObject(item) && typeof item.id === 'string' && item.id ? item.id : 'ID 확인 불가';
    const text = isObject(item) && typeof item.text === 'string' ? item.text : '내용 확인 불가';
    list.append(node('li', `${id}: ${text}`));
  }
  wrap.append(list);
  return wrap;
}

function eventDetail(event) {
  const id = String(event.id);
  const detail = node('section', null, { 'data-student-event-detail': id, 'aria-label': `${id} 상세 정보` });
  detail.append(node('h4', `기록 상세: ${id}`));
  detail.append(
    node('p', `사건 ID: ${id}`),
    node('p', `종류: ${eventKindText(event.kind)}`),
    node('p', `시각: ${eventTime(event.at)}`),
    node('p', `앱: ${eventAppText(event.appId)}`),
    node('p', `요약: ${typeof event.summary === 'string' ? event.summary : '확인 불가'}`),
    idTextList('근거(evidence)', event.evidence, 'evidence'),
    idTextList('규칙(rules)', event.rules, 'rules'),
  );
  const state = isObject(event.state) ? event.state : {};
  const stateBox = node('div', null, { 'data-event-detail-field': 'state' });
  stateBox.append(node('h5', '상태(state)'));
  const rows = [
    ['접속 상태(access)', eventStateText(ACCESS_STATE, state.access), 'access'],
    ['세션 상태(session)', eventStateText(SESSION_STATUS, state.session), 'session'],
    ['기기 상태(device)', eventStateText(DEVICE_STATUS, state.device), 'device'],
  ];
  const list = node('ul');
  for (const [name, info, key] of rows) {
    const li = node('li', `${name}: ${info.label}`, { 'data-event-state': key, 'data-attention': info.normal ? 'no' : 'yes' });
    if (!info.normal) li.append(node('span', ' ⚠ 주의', { role: 'note' }));
    list.append(li);
  }
  stateBox.append(list);
  detail.append(stateBox);
  // 16단계: 연결되지 않은 조치는 「<action> 미지원」 비활성 버튼과 안내만 보여 줍니다.
  // 클릭 처리기를 달지 않으므로 어떤 조치 요청도 보내지 않습니다. 목록이 비어 있으면 버튼을 만들지 않습니다.
  const actions = Array.isArray(event.supportedActions)
    ? event.supportedActions.filter((action) => typeof action === 'string' && action) : [];
  if (actions.length === 0) {
    detail.append(node('p', '조치: 이 기록에 연결된 조치가 없습니다.'));
  } else {
    const actionBox = node('div', null, { 'data-event-detail-field': 'unsupported-actions' });
    actionBox.append(node('h5', '조치(아직 지원하지 않음)'));
    for (const action of actions) {
      actionBox.append(node('button', `${action} 미지원`, { type: 'button', disabled: '', 'aria-disabled': 'true', 'data-unsupported-action': action }));
    }
    actionBox.append(node('p', '아직 지원하지 않는 조치입니다. 조치 실행 연결은 준비 중이며, 이 버튼은 어떤 요청도 보내지 않습니다. 조치가 실행되거나 완료된 것이 아닙니다.', { role: 'note' }));
    detail.append(actionBox);
  }
  return detail;
}

function filterSelect(id, labelText, values, labelOf) {
  const wrap = node('div', null, { 'data-event-filter': id });
  const selectId = `student-event-filter-${id}`;
  const label = node('label', labelText, { for: selectId });
  const select = node('select', null, { id: selectId, name: id, 'aria-label': labelText });
  select.append(node('option', '전체', { value: 'all' }));
  for (const value of values) select.append(node('option', labelOf(value), { value }));
  select.value = 'all';
  wrap.append(label, select);
  return { wrap, select };
}

function renderEvents({ status, mode, error, data } = {}) {
  const box = node('section', null, { 'data-student-events': 'v15', 'aria-live': 'polite' });
  box.append(node('h3', '내 접속 기록과 XDR 경보'));
  const notices = modeNotices([{ mode }]);

  if (status === 'loading' || status == null) {
    box.setAttribute('data-events-state', 'loading');
    box.append(node('p', '불러오는 중: 내 보안 기록을 서버에서 받고 있습니다.'), ...notices);
    return box;
  }

  // 조회 실패: 빈 목록과 다르게 보여 주고, 이전 목록은 그리지 않습니다.
  if (status === 'error') {
    const kind = errorKind({ error });
    box.setAttribute('data-events-state', kind === '확인 불가' ? 'unverified' : 'error');
    box.append(
      node('p', `${kind === '확인 불가' ? '확인 불가 · ' : ''}기록을 불러오지 못했습니다: ${errorMessage({ error })}`, { role: 'alert' }),
      node('p', '조회에 실패해 이전 목록과 상세는 현재 결과가 아니므로 표시하지 않습니다. 기록이 없다는 뜻이 아닙니다. 「다시 불러오기」로 다시 확인해 주세요.'),
      ...notices,
    );
    return box;
  }

  if (status !== 'ok' || !Array.isArray(data)) {
    box.setAttribute('data-events-state', 'unverified');
    box.append(node('p', '확인 불가: 기록 자료의 형식을 확인할 수 없어 목록을 표시하지 않습니다.', { role: 'alert' }), ...notices);
    return box;
  }

  if (data.length === 0) {
    box.setAttribute('data-events-state', 'empty');
    box.append(node('p', '표시할 기록이 없습니다. 조회는 성공했으며, 본인의 최근 기록이 0건입니다.'), node('p', EVENT_SCOPE), ...notices);
    return box;
  }

  // 받은 배열을 복사해 최신순으로 정렬(원본은 그대로)
  box.setAttribute('data-events-state', 'ok');
  const events = data.filter(isObject).slice().sort((a, b) => eventTimeValue(b) - eventTimeValue(a));
  const unique = (pick) => [...new Set(events.map(pick).filter((v) => typeof v === 'string' && v))];
  const kindFilter = filterSelect('kind', '기록 종류', unique((e) => e.kind), eventKindText);
  const appFilter = filterSelect('app', '업무 앱', unique((e) => e.appId), (v) => v);
  const accessFilter = filterSelect('access', '접속 상태', unique((e) => (isObject(e.state) ? e.state.access : null)), (v) => eventStateText(ACCESS_STATE, v).label);
  const filters = node('div', null, { 'data-event-filters': 'v15' });
  filters.append(kindFilter.wrap, appFilter.wrap, accessFilter.wrap);

  const count = node('p', null, { 'data-event-count': '' });
  const listHolder = node('div');
  const detailHolder = node('div');
  let selectedId = null;

  function visibleEvents() {
    return events.filter((e) =>
      (kindFilter.select.value === 'all' || e.kind === kindFilter.select.value)
      && (appFilter.select.value === 'all' || e.appId === appFilter.select.value)
      && (accessFilter.select.value === 'all' || (isObject(e.state) && e.state.access === accessFilter.select.value)));
  }

  function draw() {
    const shown = visibleEvents();
    count.textContent = `표시 중 ${shown.length}건 / 받은 기록 ${events.length}건 (최신순)`;
    if (!shown.some((e) => String(e.id) === selectedId)) selectedId = null;
    listHolder.replaceChildren();
    detailHolder.replaceChildren();
    if (shown.length === 0) {
      listHolder.append(node('p', '선택한 필터 조건에 맞는 기록이 없습니다. 필터를 「전체」로 바꾸면 받은 기록을 모두 볼 수 있습니다.'));
      return;
    }
    const list = node('ul');
    for (const event of shown) {
      const id = String(event.id);
      const li = node('li', null, { 'data-student-event-id': id });
      li.append(
        node('p', `사건 ID ${id} · ${eventTime(event.at)}`),
        node('p', `종류: ${eventKindText(event.kind)} · 앱: ${eventAppText(event.appId)}`),
        node('p', `요약: ${typeof event.summary === 'string' ? event.summary : '확인 불가'}`),
      );
      const button = node('button', `${id} 상세`, { type: 'button', 'aria-label': `${id} 상세`, 'aria-expanded': selectedId === id ? 'true' : 'false' });
      button.addEventListener('click', () => {
        selectedId = selectedId === id ? null : id;
        draw();
      });
      li.append(button);
      list.append(li);
    }
    listHolder.append(list);
    const selected = shown.find((e) => String(e.id) === selectedId);
    if (selected) detailHolder.append(eventDetail(selected));
  }

  for (const f of [kindFilter, appFilter, accessFilter]) f.select.addEventListener('change', draw);
  draw();
  box.append(node('p', EVENT_SCOPE), ...notices, filters, count, listHolder, detailHolder);
  return box;
}

// ── 16단계: 알림·기기·세션·도움정보(진단)·오류·빈 화면 ─────────────────────
// 입력: renderStatus({ devices, sessions, notifications, diagnostics, mode })
// - 기기·세션·도움정보 각각 불러오는 중 / 정상 / 실패 / 빈 목록을 서로 다른 문장으로 보여 줍니다.
// - 다시 시도는 사용자가 위쪽 「다시 불러오기」 버튼을 직접 누를 때만 일어납니다. 학생 코드는 자동으로 다시 요청하지 않습니다.
// - 도움정보(진단)는 제공 화면이 조회해 넘겨 준 값만 씁니다. 학생 코드는 진단 주소를 직접 호출하지 않습니다.
// - 도움정보는 requestId·component·version·checkedAt·engine.mode·engine.code 만 골라 보여 주고 복사합니다.
//   API 키·인증 토큰·비밀번호 같은 다른 값은 화면과 복사 내용에 넣지 않습니다. 복사는 「도움정보 복사」를 누를 때만 합니다.
const TIMEOUT_CODES = new Set(['TIMEOUT', 'REQUEST_TIMEOUT', 'ENGINE_TIMEOUT']);
const RESOURCE_NAMES = { me: '로그인 정보', apps: '업무 앱', events: '보안 기록', devices: '등록 기기', sessions: '세션', access: '접속 판정', diagnostics: '도움정보', vulnerabilities: '취약점 조회' };
const RETRY_GUIDE = '다시 시도는 위쪽 「다시 불러오기」 버튼을 직접 누르세요. 자동으로 다시 요청하지 않습니다.';
const SAFE_CODE = /^[A-Za-z0-9._:-]{1,64}$/;

function safeCode(code) {
  return typeof code === 'string' && SAFE_CODE.test(code) ? code : '확인 불가';
}

// 실패 문장: 무엇을 불러오지 못했는지, 시간 초과인지, 서버 message, 다시 시도 방법
// what 은 목적격 조사까지 붙인 말입니다(예: '등록 기기 목록을').
function failureLines(what, part) {
  const code = isObject(part) && isObject(part.error) ? part.error.code : null;
  const head = TIMEOUT_CODES.has(code)
    ? `시간 초과: ${what} 정해진 시간 안에 불러오지 못했습니다.`
    : `${errorKind(part) === '확인 불가' ? '확인 불가' : '불러오기 실패'}: ${what} 불러오지 못했습니다.`;
  return [
    node('p', `${head} ${errorMessage(part)}`, { role: 'alert' }),
    node('p', RETRY_GUIDE),
  ];
}

function statusListBlock(field, title, what, part, emptyText, itemText) {
  const block = node('div', null, { 'data-status-field': field });
  block.append(node('h4', title));
  if (!isObject(part) || part.status === 'loading' || part.status === 'idle') {
    block.setAttribute('data-status-state', 'loading');
    block.append(node('p', `불러오는 중: ${what} 서버에서 받고 있습니다.`));
    return block;
  }
  if (part.status === 'error') {
    block.setAttribute('data-status-state', 'error');
    block.append(...failureLines(what, part));
    return block;
  }
  if (part.status !== 'ok' || !Array.isArray(part.data)) {
    block.setAttribute('data-status-state', 'unverified');
    block.append(node('p', `확인 불가: ${title} 자료의 형식을 확인할 수 없습니다.`, { role: 'alert' }), node('p', RETRY_GUIDE));
    return block;
  }
  if (part.data.length === 0) {
    block.setAttribute('data-status-state', 'empty');
    block.append(node('p', emptyText));
    return block;
  }
  block.setAttribute('data-status-state', 'ok');
  const list = node('ul');
  for (const item of part.data) {
    const { text, normal } = itemText(item);
    const li = node('li', text, { 'data-attention': normal ? 'no' : 'yes' });
    if (!normal) li.append(node('span', ' ⚠ 주의', { role: 'note' }));
    list.append(li);
  }
  block.append(list);
  return block;
}

function notificationBlock(notifications) {
  const block = node('div', null, { 'data-status-field': 'notifications' });
  block.append(node('h4', '알림'));
  if (!Array.isArray(notifications)) {
    block.append(node('p', '확인 불가: 알림 목록을 확인할 수 없습니다.', { role: 'alert' }));
    return block;
  }
  if (notifications.length === 0) {
    block.append(node('p', '주의할 알림이 없습니다.'));
    return block;
  }
  const list = node('ul');
  for (const item of notifications) {
    const resource = isObject(item) && typeof item.resource === 'string' ? item.resource : '';
    const resourceText = resource ? `${Object.hasOwn(RESOURCE_NAMES, resource) ? RESOURCE_NAMES[resource] : '확인 불가'}(${safeCode(resource)})` : '확인 불가';
    const message = isObject(item) && typeof item.message === 'string' && item.message ? item.message : '내용 확인 불가';
    list.append(node('li', `자료: ${resourceText} · 코드: ${safeCode(isObject(item) ? item.code : null)} · ${message}`, { 'data-notification-resource': resource || 'unknown' }));
  }
  block.append(list);
  return block;
}

// 진단 결과에서 허용된 여섯 값만 새 객체로 골라냅니다(다른 필드는 복사·표시하지 않음).
function pickDiagnostics(data) {
  const text = (value) => (typeof value === 'string' && value ? value : '확인 불가');
  const engine = isObject(data.engine) ? data.engine : {};
  return {
    requestId: text(data.requestId),
    component: text(data.component),
    version: text(data.version),
    checkedAt: text(data.checkedAt),
    'engine.mode': text(engine.mode),
    'engine.code': text(engine.code),
  };
}

function diagnosticsBlock(diagnostics) {
  const block = node('div', null, { 'data-status-field': 'diagnostics' });
  block.append(node('h4', '도움정보(진단)'));
  block.append(node('p', '도움정보는 문제를 문의할 때 도움 요청에 쓰도록 복사하는 정보입니다. 요청 ID·구성 요소·버전·확인 시각·엔진 상태만 담고, API 키·인증 토큰·비밀번호는 담지 않습니다.'));
  const copyButton = node('button', '도움정보 복사', { type: 'button' });
  const copyStatus = node('p', null, { 'data-diagnostics-copy': 'status', 'aria-live': 'polite' });
  let safe = null;

  if (!isObject(diagnostics) || diagnostics.status === 'idle') {
    block.append(node('p', '아직 도움정보를 불러오지 않았습니다. 필요하면 화면의 「도움정보 불러오기」 버튼을 직접 누르세요.'));
  } else if (diagnostics.status === 'loading') {
    block.append(node('p', '불러오는 중: 도움정보를 서버에서 받고 있습니다.'));
  } else if (diagnostics.status === 'error') {
    block.append(...failureLines('도움정보를', diagnostics).slice(0, 1), node('p', '다시 시도는 「도움정보 불러오기」 버튼을 직접 누르세요. 자동으로 다시 요청하지 않습니다.'));
  } else if (diagnostics.status !== 'ok' || !isObject(diagnostics.data)) {
    block.append(node('p', '확인 불가: 도움정보 형식을 확인할 수 없습니다.', { role: 'alert' }));
  } else {
    safe = pickDiagnostics(diagnostics.data);
    block.append(node('p', `아래 값은 ${safe.checkedAt} 에 불러온 도움정보입니다. 최신 값이 필요하면 「도움정보 불러오기」를 직접 다시 누르세요.`));
    const list = node('dl');
    for (const [key, value] of Object.entries(safe)) list.append(node('dt', key), node('dd', value));
    block.append(list);
  }

  if (!safe) {
    copyButton.setAttribute('disabled', '');
    copyStatus.textContent = '복사할 도움정보가 아직 없습니다.';
  }
  copyButton.addEventListener('click', async () => {
    if (!safe) return;
    const text = Object.entries(safe).map(([key, value]) => `${key}: ${value}`).join('\n');
    try {
      if (!navigator.clipboard || typeof navigator.clipboard.writeText !== 'function') throw new Error('no clipboard');
      await navigator.clipboard.writeText(text);
      copyStatus.textContent = '도움정보(위 여섯 항목)를 클립보드에 복사했습니다. 붙여 넣기 전에 내용을 한 번 더 확인하세요.';
    } catch {
      copyStatus.textContent = '복사하지 못했습니다. 브라우저가 클립보드 사용을 허용하지 않았을 수 있습니다. 위 항목을 직접 선택해 복사하세요.';
    }
  });
  block.append(copyButton, copyStatus);
  return block;
}

function renderStatus({ devices, sessions, notifications, diagnostics, mode } = {}) {
  const box = node('section', null, { 'data-student-status': 'v16', 'aria-live': 'polite' });
  box.append(node('h3', '알림·기기·세션·도움정보'));
  box.append(...modeNotices([{ mode }]));
  box.append(
    notificationBlock(notifications),
    statusListBlock('devices', '등록 기기', '등록 기기 목록을', devices, '등록된 기기가 없습니다.', (item) => {
      const status = statusOf(DEVICE_STATUS, isObject(item) ? item.status : null);
      const label = isObject(item) && idText(item.label) ? item.label : (isObject(item) && idText(item.id)) || '(이름 없음)';
      return { text: `${label}: ${status.label}`, normal: status.normal };
    }),
    statusListBlock('sessions', '현재 세션', '현재 세션 정보를', sessions, '현재 연결 없음: 확인된 세션이 없습니다.', (item) => {
      const status = statusOf(SESSION_STATUS, isObject(item) ? item.status : null);
      return { text: `세션 ${(isObject(item) && idText(item.id)) || '(ID 확인 불가)'}: ${status.label}`, normal: status.normal };
    }),
    node('p', '세션은 지금 검증된 연결 하나만 표시합니다. 지난 세션 전체 목록이 아닙니다.'),
    diagnosticsBlock(diagnostics),
  );
  return box;
}

export function createStudentView() {
  return {
    renderIdentity,
    renderDecision,
    renderEvents,
    renderStatus,
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
