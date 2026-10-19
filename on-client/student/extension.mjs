// 이 파일은 학생이 같은 프로젝트에서 이어서 구현합니다.
// 제공 UI를 받은 것만으로 단계 완료를 인정하지 않습니다.
//
// 13단계: renderIdentity — 지금 로그인한 사용자·기기·세션을 상태에 맞게 보여 줍니다.
// - 표시는 매번 받은 값({ me, devices, sessions })만으로 새로 만듭니다. 이전 값을 저장해 두지 않으므로
//   다시 불러오면 새 값으로 바뀌고, 오류일 때 이전 사용자 이름이 남지 않습니다.
// - 글자는 document.createElement 와 textContent 로만 넣습니다(innerHTML 등은 쓰지 않음).
// - 점검 필요(noncompliant)·만료(expired)·취소(revoked)·확인 불가(unknown)는 정상처럼 보이지 않게 "주의" 표시를 붙이고,
//   한국어 뜻과 함께 서버가 보낸 원래 값을 괄호로 보여 줍니다.

const DEVICE_STATUS = Object.freeze({
  compliant: { text: '정상', normal: true },
  noncompliant: { text: '점검 필요', normal: false },
  unknown: { text: '확인 불가', normal: false },
});
const SESSION_STATUS = Object.freeze({
  active: { text: '사용 중', normal: true },
  expired: { text: '만료', normal: false },
  revoked: { text: '취소', normal: false },
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

// 기기·세션 목록 칸(보조 정보). 목록 자체를 못 불러오면 그 사실을 보여 줍니다.
function listSection(title, part, table, kind, labelOf) {
  const section = node('div', null, { 'data-identity-list': kind });
  section.append(node('h4', title));
  if (!isObject(part) || part.status === 'loading') {
    section.append(node('p', `${title}을(를) 불러오는 중입니다.`));
    return section;
  }
  if (part.status === 'error') {
    section.append(node('p', `연결 실패: ${title}을(를) 불러올 수 없습니다. ${errorMessage(part)}`, { role: 'alert' }));
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
      node('p', `연결 실패: ${errorMessage(me)}`, { role: 'alert' }),
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
  userLine.append(node('strong', '사용자: '), node('span', user.label));
  box.append(
    userLine,
    statusLine(`기기 ${device && typeof device.label === 'string' && device.label ? device.label : '(이름 없음)'}`, deviceStatus, 'device'),
    statusLine('세션', sessionStatus, 'session'),
  );
  if (!deviceStatus.normal || !sessionStatus.normal) {
    box.append(node('p', '이 PC 또는 접속은 지금 정상 상태가 아닙니다. 점검·다시 로그인이 필요한지 확인해 주세요.', { role: 'alert' }));
  }
  box.append(
    ...notices,
    listSection('내 기기 목록', devices, DEVICE_STATUS, 'devices', (item) => (isObject(item) && item.label) || (isObject(item) && item.id) || '(이름 없음)'),
    listSection('내 세션 목록', sessions, SESSION_STATUS, 'sessions', (item) => (isObject(item) && item.id) || '(ID 없음)'),
  );
  return box;
}

export function createStudentView() {
  return {
    renderIdentity,
    renderDecision() { return '학생 구현 대기: 서버의 판정과 이유를 연결하세요.'; },
    renderEvents() { return '학생 구현 대기: 본인 접속·XDR 기록을 연결하세요.'; },
    renderStatus() { return '학생 구현 대기: 기기·세션·알림과 연결 점검 상태를 구분하세요.'; },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
