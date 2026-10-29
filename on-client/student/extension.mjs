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

// ── 17단계: 앱 내부 AI 연결 점검 ─────────────────────────────────────────
// 입력: renderAiConnection({ status, mode, data?, error?, checkedAt, explanationAccepted })
// - 연결 점검(모델 목록 응답)과 실제 사건 설명 실행을 구분합니다. 점검 성공을 사건 설명 성공으로 쓰지 않습니다.
// - 오류는 제공 화면이 걸러 준 안전한 error.code·message만 보여 주고, code로 원인을 나눠 안내합니다.
// - 매번 입력으로 새로 그리므로 다시 점검해 성공하면 이전 오류가, idle이 오면 이전 점검 결과가 사라집니다.
// - 자동으로 다시 점검하지 않습니다. 다시 점검은 사용자가 「AI 연결 점검」(또는 「현재 API 연결 점검」)을 직접 누르는 것입니다.
const AI_ERROR_GROUPS = [
  { codes: ['ON_AI_PROVISIONING_PENDING', 'AI_REQUEST_UNVERIFIED', 'ON_AI_AUTHORIZATION_CHANGED', 'SUBJECT_SCOPE_UNVERIFIED'],
    title: '권한 준비 중 또는 확인 불가', guide: '학생 잘못이 아닙니다. 담당자에게 계정 연결과 앱 이용 권한 확인을 요청하세요.' },
  { codes: ['WB_CLCO_AUTH_REQUIRED'],
    title: '인증 실패', guide: '보호 현황의 계정 연결 확인과 AI 연결을 다시 확인하고, 계속되면 담당자에게 확인하세요. Workbench 열쇠나 AI 회사 열쇠를 복사해 붙이지 마세요.' },
  { codes: ['WB_CLCO_ACCESS_BLOCKED'],
    title: '접근 제한', guide: '계정 연결을 다시 확인하고, 담당자에게 앱 이용 권한을 확인하세요.' },
  { codes: ['WB_CLCO_COHORT_BUDGET_EXHAUSTED', 'WB_CLCO_LIMIT_REACHED'],
    title: '반 사용량·이용 한도 도달', guide: '담당자에게 사용량과 이용 한도를 확인하세요.' },
  { codes: ['WB_CLCO_SESSION_CLOSED'],
    title: '이용 시간 아님', guide: 'AI 이용 시간을 확인한 뒤 직접 다시 점검하세요.' },
  { codes: ['WB_CLCO_RATE_LIMITED'],
    title: '요청 제한', guide: '잠시 뒤 「AI 연결 점검」(또는 「현재 API 연결 점검」)을 직접 다시 누르세요.' },
  { codes: ['WB_CLCO_TIMEOUT', 'REQUEST_TIMEOUT', 'ENGINE_TIMEOUT', 'TIMEOUT'],
    title: '시간 초과', guide: '잠시 뒤 「AI 연결 점검」(또는 「현재 API 연결 점검」)을 직접 다시 누르세요.' },
  { codes: ['NETWORK_ERROR'],
    title: '네트워크 오류', guide: '앱 서버 연결을 확인하고 잠시 뒤 직접 다시 점검하세요.' },
  { codes: ['CANCELLED', 'WB_CLCO_CANCELLED', 'REQUEST_CANCELLED'],
    title: '취소됨', guide: '점검을 취소했습니다. 이전 결과는 현재 결과가 아닙니다. 필요하면 직접 다시 점검하세요.' },
  { codes: ['ON_AI_MODEL_LIST_EMPTY', 'MODEL_NOT_CONFIGURED'],
    title: '쓸 수 있는 모델 없음', guide: '담당자에게 이 앱 권한의 모델 허용 설정을 확인해 달라고 요청하세요.' },
  { codes: ['ON_AI_INVALID_INPUT'],
    title: '근거 부족', guide: '설명에 필요한 사건 근거·규칙을 확인할 수 없어 AI 설명을 만들지 않았습니다. 기존 기록을 확인하세요.' },
  { codes: ['ON_AI_INVALID_OUTPUT'],
    title: '근거 불일치 또는 응답 형식 확인 불가', guide: '인용한 근거 ID가 이 기록과 맞지 않거나, 지원하지 않는 조치·이미 실행했다는 답 등 쓸 수 없는 응답이라 결과로 쓰지 않습니다. 필요하면 직접 다시 요청하세요.' },
];
const AI_SCOPE_NOTE = '연결 점검은 앱 서버를 통해 AI 모델 응답만 확인합니다. 사건 설명은 보안 기록에서 따로 요청하고 확인합니다.';

function aiErrorGroup(code) {
  return AI_ERROR_GROUPS.find((group) => group.codes.includes(code))
    || { title: '확인 불가', guide: 'AI 연결 상태를 확인할 수 없습니다. 담당자에게 계정 연결과 앱 권한 확인을 요청하세요.' };
}

function aiErrorLines(prefix, error) {
  const code = isObject(error) ? safeCode(error.code) : '확인 불가';
  const message = isObject(error) && typeof error.message === 'string' && error.message ? error.message : '서버가 이유를 알려 주지 않았습니다.';
  const group = aiErrorGroup(isObject(error) ? error.code : null);
  return [
    node('p', `${prefix}: ${group.title}`, { role: 'alert', 'data-ai-error-group': group.title }),
    node('p', `코드: ${code} · ${message}`),
    node('p', `안내: ${group.guide}`),
  ];
}

function renderAiConnection({ status, mode, data, error, checkedAt, explanationAccepted } = {}) {
  const box = node('section', null, { 'data-student-ai-connection': 'v17', 'aria-live': 'polite' });
  box.append(node('h3', '앱 AI 연결 점검'));
  const notices = modeNotices([{ mode }]);

  if (status === 'loading') {
    box.setAttribute('data-ai-state', 'loading');
    box.append(node('p', 'AI 연결 점검 중: 앱 서버를 통해 AI 모델 응답을 확인하고 있습니다. 「AI 연결 점검 취소」를 누르면 늦게 온 응답은 쓰지 않습니다.'), node('p', AI_SCOPE_NOTE), ...notices);
    return box;
  }

  if (status === 'error') {
    box.setAttribute('data-ai-state', 'error');
    box.append(...aiErrorLines('AI 연결 점검 실패', error), node('p', '자동으로 다시 점검하지 않습니다. 다시 점검은 「AI 연결 점검」(또는 「현재 API 연결 점검」)을 직접 누르세요.'), node('p', AI_SCOPE_NOTE), ...notices);
    return box;
  }

  if (status === 'ok' && isObject(data) && data.transportChecked === true && (data.audienceAuthorization === 'test' || data.audienceAuthorization === 'verified')) {
    box.setAttribute('data-ai-state', 'ok');
    box.setAttribute('data-ai-authorization', data.audienceAuthorization);
    const isTest = data.audienceAuthorization === 'test';
    const list = node('dl');
    list.append(
      node('dt', '점검 종류'), node('dd', isTest ? '시험 연결 점검(test) · 실제 앱 권한 확인이 아님' : '앱 권한 확인 후 점검(verified) · 점검 시각 기준'),
      node('dt', '응답 모델 수'), node('dd', Number.isInteger(data.modelCount) ? String(data.modelCount) : '확인 불가'),
      node('dt', '점검 시각'), node('dd', typeof checkedAt === 'string' && checkedAt ? checkedAt : '확인 불가'),
    );
    const help = isObject(data.help) ? data.help : null;
    if (help) {
      list.append(
        node('dt', '도움 코드'), node('dd', safeCode(help.code)),
        node('dt', '앱 권한 발급 상태'), node('dd', help.provisioning === 'verified' ? '확인됨(verified)' : help.provisioning === 'pending' ? '준비 중(pending)' : `확인 불가(${safeCode(help.provisioning)})`),
      );
    }
    box.append(
      node('p', isTest ? 'AI 연결 점검 결과: 시험 연결(test)의 모델 응답만 확인했습니다.' : 'AI 연결 점검 결과: 앱 권한 확인 후 모델 응답을 확인했습니다(verified).'),
      list,
      node('p', explanationAccepted === true
        ? '사건 설명 결과는 보안 기록의 AI 설명 칸에서 확인하세요.'
        : '이 점검은 연결만 확인했으며, 사건 설명은 아직 실행하지 않았습니다. 모델 목록 응답은 사건 설명 결과가 아닙니다.', { role: 'note' }),
      node('p', '다시 점검은 「AI 연결 점검」(또는 「현재 API 연결 점검」)을 직접 누르세요. 자동으로 다시 점검하지 않습니다.'),
      ...notices,
    );
    return box;
  }

  if (status === 'ok') {
    box.setAttribute('data-ai-state', 'unverified');
    box.append(node('p', '확인 불가: AI 연결 점검 응답 형식을 확인할 수 없어 연결 완료로 보지 않습니다.', { role: 'alert' }), node('p', AI_SCOPE_NOTE), ...notices);
    return box;
  }

  // idle(또는 계정 연결을 다시 해 초기화된 경우): 이전 점검 결과를 그리지 않습니다.
  box.setAttribute('data-ai-state', 'idle');
  box.append(
    node('p', 'AI 연결 점검 전: 아직 점검 결과가 없습니다. 계정 연결 확인과 AI 연결을 마친 뒤 「AI 연결 점검」(또는 「현재 API 연결 점검」)을 직접 누르세요.'),
    node('p', AI_SCOPE_NOTE),
    ...notices,
  );
  return box;
}

// ── 18단계: 근거에 연결된 AI 사건 설명 ───────────────────────────────────
// 입력: renderExplanation({ event, explanation, checkedAt })
//   event: 보안 기록에서 고른 기록(15단계 모양) 또는 null
//   explanation: { status, mode, data?, error? }, data = { summary, evidenceIds, proposals, requiresHumanConfirmation, executed }
// - 실패(error)는 event가 없어도 먼저 안전한 code·message와 실패 이유(근거 부족 등)를 보여 줍니다.
// - 성공한 설명에만 바깥 요소에 data-student-explanation-event(event.id)를 붙입니다.
// - evidenceIds는 지금 고른 event.evidence의 id와 하나씩 대조합니다. 하나라도 없으면 근거 불일치로 설명을 쓰지 않고,
//   없는 근거를 만들어 채우지 않습니다. executed가 true인 설명(이미 실행했다는 답)도 쓰지 않습니다.
// - 매번 입력으로 새로 그리므로 다른 기록 선택·다시 불러오기·실패 때 이전 설명과 성공 표식이 남지 않습니다.
// - 실행 버튼은 만들지 않습니다. AI 설명은 참고 정보이며 설명·제안만으로 보안 조치가 실행되지 않습니다.
const EXPLANATION_SCOPE = 'AI 설명은 참고 정보입니다. 사실 판단은 근거 글과 연동 시스템이 알려 준 상태로 하며, 설명·제안만으로 보안 조치가 실행되지 않습니다.';

function explanationFailure(box, title, lines, notices) {
  box.append(node('p', title, { role: 'alert' }), ...lines, node('p', '기록은 그대로입니다. AI 연결이나 응답 문제는 과제 실패가 아니며, 업무 앱 판정과 보안 기록은 계속 쓸 수 있습니다.'), node('p', EXPLANATION_SCOPE), ...notices);
  return box;
}

function renderExplanation({ event, explanation, checkedAt } = {}) {
  const box = node('section', null, { 'aria-live': 'polite' });
  box.append(node('h3', 'AI 사건 설명'));
  const eventId = isObject(event) && typeof event.id === 'string' && event.id ? event.id : null;
  const part = isObject(explanation) ? explanation : {};
  const notices = modeNotices([{ mode: part.mode }]);

  // 1) 실패: event가 없어도 먼저 보여 줍니다. 성공 표식은 붙이지 않습니다.
  if (part.status === 'error') {
    box.setAttribute('data-explanation-state', 'error');
    const lines = aiErrorLines('AI 설명 실패', part.error).slice(1);
    if (eventId) lines.unshift(node('p', `대상 사건 ID: ${eventId}`));
    return explanationFailure(box, `AI 설명 실패: ${aiErrorGroup(isObject(part.error) ? part.error.code : null).title}`, lines, notices);
  }

  // 2) 고른 기록 없음
  if (!eventId) {
    box.setAttribute('data-explanation-state', 'no-event');
    box.append(node('p', '보안 기록에서 기록을 먼저 고르세요. 기록의 「AI 설명 요청」을 누르면 이곳에 설명이 표시됩니다.'), ...notices);
    return box;
  }

  // 3) 요청 중
  if (part.status === 'loading') {
    box.setAttribute('data-explanation-state', 'loading');
    box.append(node('p', `AI 설명 요청 중: 사건 ${eventId}`), ...notices);
    return box;
  }

  // 4) 아직 요청 전
  if (part.status !== 'ok') {
    box.setAttribute('data-explanation-state', 'idle');
    box.append(node('p', `사건 ${eventId}: 아직 AI 설명을 요청하지 않았습니다.`), ...notices);
    return box;
  }

  // 5) 성공 응답 검증: 형식·실행 여부·근거 ID 대조
  const data = isObject(part.data) ? part.data : null;
  if (!data || typeof data.summary !== 'string' || !data.summary || !Array.isArray(data.evidenceIds) || !Array.isArray(data.proposals)) {
    box.setAttribute('data-explanation-state', 'unverified');
    return explanationFailure(box, `확인 불가: 사건 ${eventId}의 AI 설명 형식을 확인할 수 없어 쓰지 않습니다.`, [], notices);
  }
  if (data.executed !== false || data.requiresHumanConfirmation !== true) {
    box.setAttribute('data-explanation-state', 'rejected-executed');
    return explanationFailure(box, `쓸 수 없는 설명: 사건 ${eventId}에 대해 AI가 이미 실행했다고 답했거나 사람 확인 조건이 없습니다.`, [node('p', '보안 조치는 설명만으로 실행되지 않습니다. 이 설명은 표시하지 않습니다.')], notices);
  }
  const evidence = Array.isArray(event.evidence) ? event.evidence.filter(isObject) : [];
  const evidenceById = new Map(evidence.map((item) => [item.id, item]));
  const missing = data.evidenceIds.filter((id) => !evidenceById.has(id));
  if (data.evidenceIds.length === 0 || missing.length > 0) {
    box.setAttribute('data-explanation-state', 'evidence-mismatch');
    const reason = data.evidenceIds.length === 0
      ? '근거 부족: AI 설명이 인용한 근거 ID가 없습니다.'
      : `근거 불일치: 인용한 근거 ID(${missing.map((id) => String(id)).join(', ')})가 고른 사건 ${eventId}의 근거에 없습니다.`;
    return explanationFailure(box, `AI 설명을 쓸 수 없습니다(사건 ${eventId}).`, [node('p', `${reason} 근거가 맞지 않으므로 내용을 표시하지 않고, 없는 근거를 만들어 채우지 않습니다.`)], notices);
  }

  // 6) 성공한 설명에만 성공 표식
  box.setAttribute('data-explanation-state', 'ok');
  box.setAttribute('data-student-explanation-event', eventId);
  box.append(
    node('p', `사건 ID: ${eventId}`),
    node('h4', 'AI 설명(참고용)'),
    node('p', data.summary),
    node('p', `설명 시각: ${typeof checkedAt === 'string' && checkedAt ? checkedAt : '확인 불가'}`),
  );

  // 인용한 근거: 근거 ID — 근거 글
  const evidenceBox = node('div', null, { 'data-explanation-field': 'evidence' });
  evidenceBox.append(node('h5', '인용한 근거'));
  const evidenceList = node('ul');
  for (const id of data.evidenceIds) {
    const item = evidenceById.get(id);
    evidenceList.append(node('li', `${id} — ${typeof item.text === 'string' ? item.text : '근거 글 확인 불가'}`, { 'data-evidence-id': String(id) }));
  }
  evidenceBox.append(evidenceList);

  // 규칙: 규칙 ID — 규칙 글
  const rulesBox = node('div', null, { 'data-explanation-field': 'rules' });
  rulesBox.append(node('h5', '관련 규칙'));
  const rules = Array.isArray(event.rules) ? event.rules.filter(isObject) : [];
  if (rules.length === 0) {
    rulesBox.append(node('p', '규칙: 없음'));
  } else {
    const ruleList = node('ul');
    for (const rule of rules) ruleList.append(node('li', `${typeof rule.id === 'string' && rule.id ? rule.id : 'ID 확인 불가'} — ${typeof rule.text === 'string' ? rule.text : '규칙 글 확인 불가'}`));
    rulesBox.append(ruleList);
  }

  // 확인 불가 상태: 접속·세션·기기별로 unknown(또는 값 없음)만 나열
  const unknownBox = node('div', null, { 'data-explanation-field': 'unknown-state' });
  unknownBox.append(node('h5', '확인 불가 상태'));
  const state = isObject(event.state) ? event.state : {};
  const unknownRows = [['접속', state.access], ['세션', state.session], ['기기', state.device]]
    .filter(([, value]) => value === 'unknown' || typeof value !== 'string' || !value)
    .map(([name, value]) => `${name}: 확인 불가(${typeof value === 'string' && value ? value : 'unknown'})`);
  if (unknownRows.length === 0) {
    unknownBox.append(node('p', '없음'));
  } else {
    const unknownList = node('ul');
    for (const row of unknownRows) unknownList.append(node('li', row, { 'data-attention': 'yes' }));
    unknownBox.append(unknownList, node('p', '확인할 수 없는 상태는 정상이나 안전으로 보지 않습니다.', { role: 'note' }));
  }

  // 제안: 이유와 미실행 상태. 실행 버튼은 만들지 않습니다.
  const proposalBox = node('div', null, { 'data-explanation-field': 'proposals' });
  proposalBox.append(node('h5', 'AI 제안 조치'));
  const supported = Array.isArray(event.supportedActions) ? event.supportedActions : [];
  if (data.proposals.length === 0) {
    proposalBox.append(node('p', supported.length === 0
      ? '연동 시스템이 지원하는 조치가 없어 제안이 없습니다(정상).'
      : 'AI가 제안한 조치가 없습니다.'));
  } else {
    const proposalList = node('ul');
    for (const proposal of data.proposals) {
      const action = isObject(proposal) ? safeCode(proposal.action) : '확인 불가';
      const reason = isObject(proposal) && typeof proposal.reason === 'string' && proposal.reason ? proposal.reason : '이유 확인 불가';
      const refs = isObject(proposal) && Array.isArray(proposal.evidenceIds) ? proposal.evidenceIds.map((id) => String(id)).join(', ') : '없음';
      proposalList.append(node('li', `${action}: ${reason} (근거 ${refs}) · 사람 확인이 필요하며 실행되지 않았습니다.`, { 'data-proposal-action': action }));
    }
    proposalBox.append(proposalList);
  }

  box.append(evidenceBox, rulesBox, unknownBox, proposalBox, node('p', EXPLANATION_SCOPE, { role: 'note' }), ...notices);
  return box;
}

// ── 19단계: 보안 조치 요청 상태와 실제 결과 구분 ─────────────────────────
// 입력: renderAction({ status, event, actionId, target, receipt, observation, message, confirmationExpiresAt?, error? })
// - 제안(AI)·사람 확인·서버 전달·접수(ACK)·효과 관측을 서로 다른 문장으로 보여 줍니다.
// - succeeded 이면서 observation.effectApplied === true 일 때만 "효과 확인"으로 표시하고, 그 밖에는 결과 불명입니다.
// - 접수 영수증의 사건·조치가 지금 사건·조치와 다르면 현재 요청의 결과로 쓰지 않습니다(확인 불가).
// - 학생 코드는 버튼·조치 요청(POST)·확인 티켓을 만들거나 저장하지 않습니다. 조작은 제공 화면 버튼으로만 합니다.
// - 매번 입력으로 새로 그리므로 새 값이 오면 이전 대상·요청·결과 표시가 남지 않습니다.
const ACTION_STATUS = {
  idle: { text: '아직 미실행(idle)', detail: '조치 제안은 아직 실행되지 않았습니다. AI 제안만으로는 아무 조치도 실행되지 않습니다.' },
  loading: { text: '확인 중(loading) · 완료 아님', detail: '조치를 준비하거나 연동 시스템 결과를 조회하고 있습니다. 아직 결과가 아닙니다.' },
  prepared: { text: '준비됨 · 미실행(prepared)', detail: '조치를 준비만 했고 실행하지 않았습니다. 사건·조치·실제 대상과 확인 기한을 사람이 확인한 뒤 제공 화면의 「대상과 조치를 확인했으며 집행합니다」를 눌러야 서버에 전달됩니다.' },
  executing: { text: '서버에 전달 중(executing) · 완료 아님', detail: '사람 확인 뒤 서버에 전달하고 있습니다. 결과는 아직 없습니다.' },
  pending: { text: '서버 접수·처리 중(pending) · 완료 아님', detail: '서버가 요청을 받았다는 접수 응답(ACK)일 뿐, 조치 효과가 확인된 것이 아닙니다. 결과는 제공 화면의 「원천 결과만 재조회」로 직접 확인하세요.' },
  succeeded: { text: '효과 확인(succeeded)', detail: '연동 시스템이 조치 효과를 관측했습니다.' },
  denied: { text: '거절(denied)', detail: '연동 시스템이 이 조치를 거절했습니다. 조치는 적용되지 않았습니다.' },
  failed: { text: '실패(failed)', detail: '연동 시스템에서 조치 처리가 실패했습니다.' },
  unknown: { text: '결과 불명(unknown)', detail: '성공으로도, 효과 없음으로도 판단하지 마세요. 다시 집행하지 말고 제공 화면의 「원천 결과만 재조회」로 결과만 직접 확인하세요.' },
  expired: { text: '확인 기한 지남(expired)', detail: '사람 확인 기한이 지나 집행할 수 없습니다. 현재 사건에서 조치를 다시 준비하세요.' },
  error: { text: '요청 처리 안 됨(error)', detail: '요청이 처리되지 않았습니다. 이 상태는 효과 확인이 아닙니다. 서버에 이미 전달된 뒤 생긴 오류라면 다시 집행하지 말고 결과만 재조회하세요.' },
};
const ACTION_SCOPE = '보안 조치를 실제로 처리하는 연동 시스템 연결은 아직 준비되지 않았습니다. 지금 기록은 지원 조치가 없어(supportedActions 빈 배열) 조치 준비 버튼이 나오지 않는 것이 정상입니다. 「조치 화면 취소」는 이미 서버에 전달된 조치 효과를 되돌리지 않습니다.';

function renderAction({ status, event, actionId, target, receipt, observation, message, confirmationExpiresAt, error } = {}) {
  const box = node('section', null, { 'aria-live': 'polite' });
  box.append(node('h3', '보안 조치 요청 상태'));
  const code = typeof status === 'string' && Object.hasOwn(ACTION_STATUS, status) ? status : null;
  const eventId = isObject(event) && typeof event.id === 'string' && event.id ? event.id : null;
  const rec = isObject(receipt) ? receipt : null;
  const obs = isObject(observation) ? observation : null;

  // 지금 사건·조치와 영수증이 같은 의도인지 확인합니다.
  const bindingBroken = Boolean(rec && ((rec.eventId != null && rec.eventId !== eventId) || (rec.actionId != null && rec.actionId !== actionId)));
  // 효과 확인은 succeeded + effectApplied === true + 의도 일치일 때만
  const effectConfirmed = code === 'succeeded' && obs !== null && obs.effectApplied === true && !bindingBroken;
  const shown = !code ? null : (code === 'succeeded' && !effectConfirmed ? 'unknown' : code);

  box.setAttribute('data-action-state', shown || 'unverified');
  if (!shown) {
    box.append(node('p', `확인 불가: 조치 상태 값(${safeCode(status)})을 알 수 없습니다. 성공으로 보지 마세요.`, { role: 'alert' }));
  } else {
    const info = ACTION_STATUS[shown];
    box.append(node('p', `상태: ${info.text}`, { 'data-action-field': 'status', role: shown === 'succeeded' ? 'status' : 'note' }), node('p', info.detail));
    if (code === 'succeeded' && !effectConfirmed) {
      box.append(node('p', bindingBroken
        ? '서버가 succeeded를 보냈지만 영수증의 사건·조치가 지금 사건과 달라 현재 요청의 결과로 볼 수 없습니다(결과 불명).'
        : '서버가 succeeded를 보냈지만 효과 관측(effectApplied: true)이 없어 효과 확인으로 보지 않습니다(결과 불명).', { role: 'alert' }));
    }
  }
  if (bindingBroken) box.append(node('p', '확인 불가: 접수 영수증의 사건 ID 또는 조치 ID가 지금 표시 중인 사건·조치와 다릅니다. 이전 요청의 결과를 현재 결과로 쓰지 않습니다.', { role: 'alert' }));

  // 현재 의도: 사건·근거·조치·실제 대상·요청 정보 (받은 것만 표시)
  const facts = node('dl', null, { 'data-action-field': 'intent' });
  const add = (label, value) => { if (value != null && value !== '') facts.append(node('dt', label), node('dd', String(value))); };
  add('사건 ID', eventId);
  if (eventId && Array.isArray(event.evidence)) {
    const ids = event.evidence.filter(isObject).map((item) => item.id).filter((id) => typeof id === 'string' && id);
    add('근거 ID', ids.length ? ids.join(', ') : '없음');
  }
  add('조치(actionId)', typeof actionId === 'string' ? actionId : null);
  if (isObject(target)) {
    add('실제 대상(target.id)', target.id);
    add('대상 세대(target.generation)', target.generation);
  }
  if (shown === 'prepared' || (confirmationExpiresAt && shown !== 'idle')) add('사람 확인 기한', typeof confirmationExpiresAt === 'string' && confirmationExpiresAt ? confirmationExpiresAt : '확인 불가');
  if (rec) {
    add('요청 ID(requestId)', rec.requestId);
    add('영수증 ID(receiptId)', rec.receiptId);
    add('버전(version)', rec.version);
    if (typeof rec.status === 'string') add('영수증 상태', rec.status);
  }
  if (obs) {
    add('관측 시각(observedAt)', obs.observedAt || '확인 불가');
    add('effectApplied', obs.effectApplied === true ? 'true' : obs.effectApplied === false ? 'false' : '확인 불가');
  }
  if (facts.childElementCount > 0) box.append(facts);

  // 효과 확인일 때 필요한 값 묶음
  if (effectConfirmed) {
    box.append(node('p', `효과 확인(succeeded) · 관측 시각 ${obs.observedAt || '확인 불가'} · effectApplied: true · receiptId ${rec && rec.receiptId ? rec.receiptId : '확인 불가'}`, { 'data-action-field': 'observed' }));
  }

  // 중복 방지: 같은 요청의 재전송·이전 조회 안내
  if (rec && rec.replayed === true) box.append(node('p', '같은 요청 ID로 이미 접수된 요청의 응답입니다(replayed). 새로 집행된 것이 아니며, 같은 조치를 다시 전달하지 않았습니다.'));
  if (rec && rec.superseded === true) box.append(node('p', '이전 조회 결과는 최신 결과를 대신하지 않습니다(superseded).'));

  // 거절·실패·오류의 안전한 사유
  if ((shown === 'denied' || shown === 'failed') && typeof message === 'string' && message) box.append(node('p', `사유: ${message}`));
  if (isObject(error)) box.append(node('p', `코드: ${safeCode(error.code)} · ${typeof error.message === 'string' && error.message ? error.message : '서버가 이유를 알려 주지 않았습니다.'}`, { role: 'alert' }));
  else if (shown === 'error') box.append(node('p', '코드: 확인 불가 · 서버가 이유를 알려 주지 않았습니다.', { role: 'alert' }));

  box.append(node('p', '조작은 제공 화면의 「대상과 조치를 확인했으며 집행합니다」「원천 결과만 재조회」「조치 화면 취소」 버튼으로만 합니다. 이 칸에는 실행 버튼이 없습니다.'), node('p', ACTION_SCOPE, { role: 'note' }));

  // 현재 사건·요청으로 그린 경우에만 표식을 붙입니다.
  if (eventId && !bindingBroken) {
    box.setAttribute('data-student-action-event', eventId);
    if (rec && typeof rec.requestId === 'string' && rec.requestId) box.setAttribute('data-student-action-request', rec.requestId);
  }
  return box;
}

// ── 20단계: 설치 패키지 버전과 알려진 취약점(OSV) 조회 결과 ─────────────────
// 입력: renderVulnerabilities({ status, mode, data?, error? })
// - idle(조회 전)·loading(조회 중)·error(조회 실패)·ok를 나누고, 조회 중·실패 때는 이전 표를 그리지 않습니다.
// - 매번 입력으로 새로 그리므로 다시 조회하면 새 lockfileHash·새 표로 바뀌고, 늦은 응답은 제공 화면이 버립니다.
// - 버전은 package-lock.json과 설치된 메타데이터를 대조한 정확한 설치 버전만 씁니다(^1.2.0 같은 범위는 쓰지 않음).
// - 조회 실패·미조회는 "취약점 없음"이 아닙니다. 일부 조회에서 이미 받은 취약점 ID는 지우지 않습니다.
// - 학생 코드는 조회 요청을 직접 보내지 않습니다. 조회·취소·다시 조회는 제공 화면 버튼으로 합니다.
const SCAN_STATUS_TEXT = {
  complete: '모두 조회(complete)',
  partial: '일부 조회 실패(partial)',
  not_checked: '아직 조회 안 함(not_checked)',
  not_configured: '조회 준비 미완료(not_configured)',
  unverifiable: 'lock 파일 확인 불가(unverifiable)',
};
const SCAN_STATUS_DETAIL = {
  complete: '조회 대상 패키지를 모두 OSV에 조회했습니다. 결과가 없다는 것은 조회 범위에서 알려진 항목이 없다는 뜻이며, 안전을 보장하지 않습니다.',
  partial: '일부 패키지는 조회하지 못했습니다. 조회하지 못한 패키지는 "취약점 없음"이 아니며, 이미 받은 취약점 ID는 그대로 표시합니다.',
  not_checked: '승인된 공개 조회 대상 패키지가 없어 OSV에 조회하지 않았습니다(미조회). 취약점 없음이 아닙니다. 조회 대상은 담당자가 정합니다.',
  not_configured: '조회 대상 프로젝트 설정이 준비되지 않아 조회하지 않았습니다(미조회). 취약점 없음이 아닙니다. 설정은 담당자가 준비합니다.',
  unverifiable: 'package-lock.json을 확인할 수 없어 조회 결과를 만들 수 없습니다. 취약점 없음이 아닙니다.',
};
const PACKAGE_STATUS_TEXT = {
  known_vulnerabilities: '알려진 항목 있음(known_vulnerabilities)',
  none_found: '알려진 항목 없음(none_found) · 조회 시점·조회 범위 기준',
  unverifiable: '조회 확인 불가(unverifiable)',
};
const VULN_SCOPE = 'OSV는 공개된 알려진 취약점 데이터베이스입니다. 조회 결과가 없다는 사실만으로 해당 패키지나 앱 전체가 안전하다고 보장할 수 없습니다.';
const EXACT_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

function renderVulnerabilities({ status, mode, data, error } = {}) {
  const box = node('section', null, { 'data-student-vulnerabilities': 'v20', 'aria-live': 'polite' });
  box.append(node('h3', '설치 패키지와 알려진 취약점(OSV)'));
  const notices = modeNotices([{ mode }]);

  if (status === 'loading') {
    box.setAttribute('data-vuln-state', 'loading');
    box.append(node('p', '조회 중: 설치된 패키지 버전을 OSV 정보와 대조하고 있습니다. 이전 결과는 현재 결과가 아니므로 표시하지 않습니다. 「패키지 조회 취소」를 누르면 늦게 온 응답은 쓰지 않습니다.'), ...notices);
    return box;
  }
  if (status === 'error') {
    box.setAttribute('data-vuln-state', 'error');
    const code = isObject(error) ? safeCode(error.code) : '확인 불가';
    const message = isObject(error) && typeof error.message === 'string' && error.message ? error.message : '패키지 조회를 확인할 수 없습니다.';
    const kind = TIMEOUT_CODES.has(isObject(error) ? error.code : null) ? '조회 시간 초과' : (isObject(error) && ['CANCELLED', 'REQUEST_CANCELLED'].includes(error.code)) ? '조회 취소' : '조회 실패';
    box.append(
      node('p', `${kind}: ${message} (${code})`, { role: 'alert' }),
      node('p', '조회 실패는 "취약점 없음"이 아닙니다. 이전 표는 현재 결과가 아니므로 표시하지 않습니다. 다시 조회는 「설치 패키지 조회」를 직접 누르세요. 자동으로 다시 조회하지 않습니다.'),
      ...notices,
    );
    return box;
  }
  if (status !== 'ok') {
    box.setAttribute('data-vuln-state', 'idle');
    box.append(node('p', '조회 전: 아직 설치 패키지를 조회하지 않았습니다. 보호 현황의 「설치 패키지 조회」를 직접 누르세요.'), node('p', VULN_SCOPE), ...notices);
    return box;
  }

  const scan = isObject(data) ? data : null;
  const scanStatus = scan && typeof scan.status === 'string' && Object.hasOwn(SCAN_STATUS_TEXT, scan.status) ? scan.status : null;
  if (!scanStatus) {
    box.setAttribute('data-vuln-state', 'unverified');
    box.append(node('p', '확인 불가: 조회 결과 형식을 확인할 수 없어 표시하지 않습니다. 취약점 없음이 아닙니다.', { role: 'alert' }), ...notices);
    return box;
  }
  box.setAttribute('data-vuln-state', 'ok');
  box.setAttribute('data-vuln-scan-status', scanStatus);

  // 전체 결과
  const summary = node('dl', null, { 'data-vuln-field': 'scan' });
  const add = (label, value) => { if (value != null && value !== '') summary.append(node('dt', label), node('dd', String(value))); };
  add('전체 조회 상태', SCAN_STATUS_TEXT[scanStatus]);
  add('사유 코드', typeof scan.code === 'string' ? safeCode(scan.code) : null);
  add('lockfileVersion', Number.isInteger(scan.lockfileVersion) ? scan.lockfileVersion : null);
  add('lockfileHash', typeof scan.lockfileHash === 'string' ? scan.lockfileHash : null);
  add('확인 시각(checkedAt)', typeof scan.checkedAt === 'string' ? scan.checkedAt : null);
  if (isObject(scan.excluded) && Number.isInteger(scan.excluded.count)) add('조회 제외 패키지 수', `${scan.excluded.count}개 (승인되지 않았거나 공개 조회 대상이 아님 · 취약점 없음이 아님)`);
  box.append(node('p', `전체 결과: ${SCAN_STATUS_TEXT[scanStatus]}`, scanStatus === 'complete' ? {} : { role: 'note' }), node('p', SCAN_STATUS_DETAIL[scanStatus]), summary);

  // 패키지 표
  const packages = Array.isArray(scan.packages) ? scan.packages.filter(isObject) : [];
  if (packages.length === 0) {
    box.append(node('p', scanStatus === 'complete' || scanStatus === 'partial'
      ? '조회한 패키지 행이 없습니다.'
      : '조회하지 않아 패키지 행이 없습니다. 패키지가 없다는 뜻도, 취약점이 없다는 뜻도 아닙니다.'));
  } else {
    const table = node('table');
    const head = node('tr');
    for (const title of ['패키지(name)', '설치 버전(version)', '조회 결과(status)', '알려진 취약점(id · modified)', '출처(source)', '확인 시각(checkedAt)']) head.append(node('th', title, { scope: 'col' }));
    table.append(head);
    for (const pkg of packages) {
      const name = typeof pkg.name === 'string' ? pkg.name : '확인 불가';
      const version = typeof pkg.version === 'string' && EXACT_VERSION.test(pkg.version) ? pkg.version : null;
      const vulns = Array.isArray(pkg.vulnerabilities) ? pkg.vulnerabilities.filter(isObject) : [];
      const row = node('tr', null, { 'data-student-package-name': name, 'data-student-package-version': version || 'unverifiable' });
      let statusText = typeof pkg.status === 'string' && Object.hasOwn(PACKAGE_STATUS_TEXT, pkg.status) ? PACKAGE_STATUS_TEXT[pkg.status] : `확인 불가(${safeCode(pkg.status)})`;
      if (pkg.status === 'unverifiable' && vulns.length > 0) statusText = '일부 확인·전체 조회 확인 불가(unverifiable) · 받은 취약점 ID는 그대로 표시';
      if (!version) statusText = `설치 버전 확인 불가 · ${statusText}`;
      const vulnCell = node('td');
      if (vulns.length === 0) {
        vulnCell.textContent = pkg.status === 'none_found' ? '없음(조회 범위에서 알려진 항목 없음)' : '없음(확인된 항목 없음 · 취약점 없음이 아님)';
      } else {
        const list = node('ul');
        for (const v of vulns) list.append(node('li', `${typeof v.id === 'string' ? v.id : 'ID 확인 불가'} · 수정 시각 ${typeof v.modified === 'string' ? v.modified : '확인 불가'}`, { 'data-vuln-id': typeof v.id === 'string' ? v.id : '' }));
        vulnCell.append(list);
      }
      row.append(
        node('td', name),
        node('td', version || `확인 불가(${typeof pkg.version === 'string' ? pkg.version : '값 없음'}) · 범위 표기는 설치 버전으로 쓰지 않음`),
        node('td', statusText, { 'data-attention': pkg.status === 'none_found' && version ? 'no' : 'yes' }),
        vulnCell,
        node('td', typeof pkg.source === 'string' ? pkg.source : '확인 불가'),
        node('td', typeof pkg.checkedAt === 'string' ? pkg.checkedAt : '확인 불가'),
      );
      table.append(row);
    }
    box.append(table);
  }
  box.append(node('p', '버전은 package-lock.json과 설치된 패키지 정보를 대조한 정확한 설치 버전입니다. 다시 조회는 「설치 패키지 조회」를 직접 누르세요.'), node('p', VULN_SCOPE, { role: 'note' }), ...notices);
  return box;
}

// ── 총공세 2일차: 내 PC 관제 대시보드 (renderStatus 맨 위) ─────────────────────
// - 값은 제공 기능 「내 PC 상태」와 같은 경로(/api/pc/status)를 학생 API(api.get)로 받아 씁니다. 학생 코드가 CPU·메모리·디스크를 다시 재지 않습니다.
//   (제공: src/pc-status.mjs 가 일반 권한으로 측정, public/pc-status-view.mjs 가 제공 카드 표시 / 학생: 아래 카드 4개와 지난 조회 대비 변화)
// - 사용자가 「내 PC 실측 조회」를 누를 때만 한 번 읽습니다. 자동 조회·타이머는 없습니다.
// - 읽지 못한 값은 0이나 예시 값으로 채우지 않고 「확인 불가」와 이유를 보여 주며, 지난 값을 현재 값처럼 쓰지 않습니다.
// - 이 칸의 값은 모두 이 PC 실측입니다. 예시 값은 표시하지 않습니다.
const PC_PATH = '/api/pc/status';
const PC_STALE_MS = 60000;
const PC_REASONS = {
  permission_denied: '읽기 권한 없음(permission_denied) · 관리자 권한으로 바꾸지 말고 담당자에게 확인',
  unsupported: '이 운영체제에서는 조회하지 않음(unsupported)',
  timeout: '조회 시간 초과(timeout)',
  cancelled: '조회 취소(cancelled)',
  query_failed: '조회 실패(query_failed)',
  invalid_response: '응답 형식 확인 불가(invalid_response)',
  invalid_sample: '측정 표본 확인 불가(invalid_sample)',
};
const PC_LIMITS = { cpuPercent: 85, memoryPercent: 90, diskFreePercent: 10 };
const gb = (bytes) => bytes / 1024 ** 3;
const gbText = (bytes) => `${gb(bytes).toFixed(1)} GB`;
const isNum = (n) => typeof n === 'number' && Number.isFinite(n) && n >= 0;
const signed = (n, digits, unit) => {
  const v = Number(n.toFixed(digits));
  if (v === 0) return `＝ 변화 없음`;
  return `${v > 0 ? '▲ +' : '▼ −'}${Math.abs(v).toFixed(digits)}${unit}`;
};
const pcTime = (ms) => new Date(ms).toLocaleString('ko-KR');

function readPcMetric(key, metric) {
  if (!isObject(metric) || metric.state !== 'ok') {
    const reason = isObject(metric) && typeof metric.reason === 'string' ? metric.reason : null;
    return { ok: false, reason: reason && Object.hasOwn(PC_REASONS, reason) ? PC_REASONS[reason] : '이번 조회에서 값을 받지 못함' };
  }
  if (key === 'cpu' && isNum(metric.usagePercent) && metric.usagePercent <= 100) return { ok: true, cpu: metric.usagePercent, sampleMs: metric.sampleMs };
  if (key === 'memory' && isNum(metric.usedBytes) && isNum(metric.totalBytes) && metric.totalBytes > 0 && metric.usedBytes <= metric.totalBytes) return { ok: true, used: metric.usedBytes, total: metric.totalBytes };
  if (key === 'disk' && isNum(metric.freeBytes) && isNum(metric.totalBytes) && metric.totalBytes > 0 && metric.freeBytes <= metric.totalBytes) return { ok: true, free: metric.freeBytes, total: metric.totalBytes };
  if (key === 'firewall' && Array.isArray(metric.profiles) && metric.profiles.length === 3
    && ['Domain', 'Private', 'Public'].every((name) => metric.profiles.some((pr) => isObject(pr) && pr.name === name && typeof pr.enabled === 'boolean'))) {
    return { ok: true, profiles: ['Domain', 'Private', 'Public'].map((name) => ({ name, enabled: metric.profiles.find((pr) => pr.name === name).enabled })) };
  }
  return { ok: false, reason: '응답의 값이나 단위를 확인할 수 없음' };
}

// 응답 한 건을 검사해 { measuredAt(ms), metrics:{cpu,memory,disk,firewall} } 로 바꿉니다. 맞지 않으면 null.
function parsePcResult(result) {
  if (!isObject(result) || result.ok !== true || !isObject(result.data)) return null;
  const d = result.data;
  if (d.schema !== 'aleph.on.pc-status.v1' || d.source !== 'local-pc' || typeof d.measuredAt !== 'string' || !isObject(d.metrics)) return null;
  const measuredAt = Date.parse(d.measuredAt);
  if (!Number.isFinite(measuredAt)) return null;
  const metrics = {};
  for (const key of ['cpu', 'memory', 'disk', 'firewall']) metrics[key] = readPcMetric(key, d.metrics[key]);
  return { measuredAt, metrics };
}

function pcCard(key, title, current, previous, stale) {
  const card = node('article', null, { class: 'card', 'data-student-pc-metric': key });
  const m = current ? current.metrics[key] : null;
  const p = previous && previous.metrics[key] && previous.metrics[key].ok ? previous.metrics[key] : null;
  let value = '확인 불가', state = 'unknown', stateText = '확인 불가', delta = '', range = '', note = '';
  if (m && m.ok) {
    if (key === 'cpu') {
      value = `${m.cpu.toFixed(1)} %`; range = `${isNum(m.sampleMs) ? `${m.sampleMs / 1000}초` : '짧은'} 구간 실측값`;
      state = m.cpu >= PC_LIMITS.cpuPercent ? 'warn' : 'ok';
      delta = p ? `${signed(m.cpu - p.cpu, 1, '%p')} (지난 ${p.cpu.toFixed(1)} %)` : '비교할 지난 값 없음';
    } else if (key === 'memory') {
      const pct = (100 * m.used) / m.total;
      value = `${gbText(m.used)} / ${gbText(m.total)}`; range = `사용 중 / 전체 · ${pct.toFixed(1)} % 사용`;
      state = pct >= PC_LIMITS.memoryPercent ? 'warn' : 'ok';
      delta = p ? `${signed(gb(m.used) - gb(p.used), 1, ' GB')} (지난 ${gbText(p.used)})` : '비교할 지난 값 없음';
    } else if (key === 'disk') {
      const pct = (100 * m.free) / m.total;
      value = `${gbText(m.free)} 남음`; range = `앱이 있는 디스크 · 전체 ${gbText(m.total)} 중 ${pct.toFixed(1)} %`;
      state = pct < PC_LIMITS.diskFreePercent ? 'warn' : 'ok';
      delta = p ? `${signed(gb(m.free) - gb(p.free), 1, ' GB')} (지난 ${gbText(p.free)})` : '비교할 지난 값 없음';
    } else if (key === 'firewall') {
      const off = m.profiles.filter((pr) => !pr.enabled).map((pr) => pr.name);
      value = m.profiles.map((pr) => `${pr.name} ${pr.enabled ? '켜짐' : '꺼짐'}`).join(' · ');
      range = 'Windows 방화벽 설정을 읽기만 함 · 켜짐은 보호 전체의 안전 판정이 아님';
      state = off.length ? 'warn' : 'ok';
      note = off.length ? `꺼진 프로필: ${off.join(', ')}` : '';
      if (p) {
        const changed = m.profiles.filter((pr) => p.profiles.find((q) => q.name === pr.name).enabled !== pr.enabled);
        delta = changed.length ? `바뀜: ${changed.map((pr) => `${pr.name} ${pr.enabled ? '꺼짐→켜짐' : '켜짐→꺼짐'}`).join(', ')}` : '＝ 지난 조회와 같음';
      } else delta = '비교할 지난 값 없음';
    }
    stateText = state === 'warn' ? '주의' : '정상(기준 이내)';
    if (stale) { state = 'stale'; stateText = '오래됨'; }
  } else if (m) {
    note = `이유: ${m.reason}`;
    delta = p ? '지난 값은 현재 상태로 쓰지 않음' : '';
  } else {
    note = current === null ? '아직 조회하지 않았습니다.' : '';
    if (current === null) { state = 'idle'; stateText = '조회 전'; }
  }
  card.setAttribute('data-pc-state', state);
  const chip = node('span', ` ${stateText}`, { class: `tag ${state === 'ok' ? 'state-ok' : state === 'warn' ? 'decision-challenge' : 'state-empty'}` });
  const head = node('h4', title); head.append(chip);
  card.append(head, node('p', value, { 'data-pc-field': 'value' }));
  if (delta) card.append(node('p', delta, { class: 'muted', 'data-pc-field': 'delta' }));
  if (range) card.append(node('p', range, { class: 'muted' }));
  if (note) card.append(node('p', note, { class: 'muted', 'data-pc-field': 'note' }));
  if (current && current.measuredAt) {
    card.append(node('p', m && m.ok
      ? `잰 시각: ${pcTime(current.measuredAt)} · 출처: 이 PC(local-pc) 실측`
      : `조회 시각: ${pcTime(current.measuredAt)} · 이 항목은 이번에 값을 받지 못함`, { class: 'muted' }));
  }
  return card;
}

function renderPcDashboard(pc, onRequest) {
  const box = node('section', null, { 'data-student-pc-dashboard': 'final-day2', 'aria-live': 'polite' });
  box.append(node('h3', '내 PC 관제 대시보드'));
  box.append(node('p', '제공 「내 PC 상태」와 같은 값(/api/pc/status)을 받아 이번 값과 지난 조회 값을 비교합니다. 관리자 권한을 쓰지 않고, 이 칸의 값은 모두 이 PC 실측입니다(예시 값 없음).', { class: 'muted' }));
  const bar = node('div', null, { class: 'row' });
  const button = node('button', pc.phase === 'loading' ? '읽는 중…' : '내 PC 실측 조회', { type: 'button', class: 'btn' });
  if (pc.phase === 'loading') button.setAttribute('disabled', '');
  button.addEventListener('click', onRequest);
  bar.append(button);
  const stale = pc.current ? Date.now() - pc.current.measuredAt > PC_STALE_MS : false;
  let line;
  if (pc.phase === 'loading') line = '이 PC에서 읽는 중입니다.';
  else if (pc.phase === 'error') line = `이번 조회 실패: ${pc.error} · 지난 값은 현재 상태로 쓰지 않습니다. 버튼을 직접 다시 누르세요.`;
  else if (!pc.current) line = '아직 조회하지 않았습니다. 「내 PC 실측 조회」를 누르면 한 번 읽습니다. 자동으로 읽지 않습니다.';
  else {
    line = `이번 실측 ${pcTime(pc.current.measuredAt)}`;
    line += pc.previous ? ` · 지난 실측 ${pcTime(pc.previous.measuredAt)} (${Math.round((pc.current.measuredAt - pc.previous.measuredAt) / 1000)}초 전)` : ' · 지난 실측 없음(첫 조회)';
    if (stale) line += ` · 실측 후 ${Math.round((Date.now() - pc.current.measuredAt) / 1000)}초 지나 「오래됨」으로 표시합니다. 다시 조회하세요.`;
  }
  bar.append(node('span', line, { class: 'muted', role: 'status' }));
  box.append(bar);
  const shown = pc.phase === 'error' ? { measuredAt: null, metrics: {} } : pc.current;
  const grid = node('div', null, { class: 'grid-2' });
  for (const [key, title] of [['cpu', 'CPU 사용률'], ['memory', '메모리 사용량'], ['disk', '디스크 남은 공간'], ['firewall', 'Windows 방화벽']]) {
    const metricSource = shown && pc.phase === 'error' ? { measuredAt: null, metrics: { [key]: { ok: false, reason: pc.error } } } : shown;
    grid.append(pcCard(key, title, metricSource, pc.previous, stale));
  }
  box.append(grid);
  box.append(node('p', `▲▼ = 지난 조회 대비 변화 · 주의 기준: CPU ${PC_LIMITS.cpuPercent}% 이상, 메모리 ${PC_LIMITS.memoryPercent}% 이상, 디스크 남은 공간 ${PC_LIMITS.diskFreePercent}% 미만, 꺼진 방화벽 프로필 · 확인 불가 = 이번에 읽지 못함(0이나 예시 값으로 채우지 않음) · 「주의」는 문제 확인이 필요하다는 뜻이며 악성코드·침해 판정이 아닙니다.`, { class: 'muted' }));
  return box;
}

export function createStudentView({ api, onChange } = {}) {
  // 내 PC 대시보드 상태(화면을 다시 그려도 유지). 확인 티켓·비밀값은 없습니다.
  const pc = { phase: 'idle', current: null, previous: null, error: null };
  const rerender = () => { if (typeof onChange === 'function') onChange(); };
  async function requestPc() {
    if (pc.phase === 'loading') return;
    if (!api || typeof api.get !== 'function') { pc.phase = 'error'; pc.error = '학생 API를 사용할 수 없음'; rerender(); return; }
    pc.phase = 'loading'; rerender();
    let result;
    try { result = await api.get(PC_PATH); } catch { result = null; }
    const parsed = parsePcResult(result);
    if (parsed) {
      if (pc.current) pc.previous = pc.current;
      pc.current = parsed; pc.phase = 'ok'; pc.error = null;
    } else {
      const code = isObject(result) && isObject(result.error) ? safeCode(result.error.code) : '응답 형식 확인 불가';
      pc.phase = 'error'; pc.error = code === 'NOT_ALLOWED' ? '이 시작 틀에서는 학생 API로 PC 값을 받을 수 없음(NOT_ALLOWED)' : `조회 실패(${code})`;
      if (pc.current) pc.previous = pc.current;
      pc.current = null;
    }
    rerender();
  }
  function renderStatusWithPc(input) {
    const box = renderStatus(input);
    box.insertBefore(renderPcDashboard(pc, requestPc), box.children[1] || null);
    return box;
  }
  return {
    renderIdentity,
    renderDecision,
    renderEvents,
    renderStatus: renderStatusWithPc,
    renderVulnerabilities,
    renderAiConnection,
    renderExplanation,
    renderAction,
  };
}
