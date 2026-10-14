// persistence 판단 모듈: 서비스·예약 작업·시작 폴더·파일 무결성 경보 하나를 받아 block / alert / record 를 돌려줍니다.
// 이 파일은 혼자 계산합니다. 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 네트워크에 묻지 않습니다.
// 패턴은 xdr/persistence/patterns.json 의 내용을 그대로 옮겨 적은 상수입니다.
// 경보의 기법 표시(T1543·T1053)만으로는 판단하지 않습니다. 정상 이벤트에도 같은 표시가 붙을 수 있어
// 설명(새로 생김·바뀜·서명 여부·평소 목록 여부)과 실행 파일 위치(임시 폴더인지)를 함께 봅니다.
export const PATTERNS = Object.freeze([
  Object.freeze({
    name: "unsigned-new-service",
    title: "서명 없는 새 서비스 등록·서비스 실행 파일 변경",
    mitre: "T1543.003",
    condition: Object.freeze({
      summary: "서명이 없는 서비스가 새로 등록되거나 기존 서비스의 실행 파일이 바뀌고, 그 실행 파일이 임시 폴더(Temp·AppData)에 있거나 평소 목록에 없다",
      strong: "서명 없음이 확인되고 새 등록·실행 파일 변경·다시 켜도 남는 등록 중 하나가 있다(임시 폴더 실행 파일, 평소 목록에 없음, 원격 주소에서 연속 등록이면 더 뚜렷하다)",
      weak: "서명을 아직 모르거나, 서비스 설명만 바뀌었거나, 임시 폴더에 실행 파일만 생기고 서비스 등록은 없다",
      fields: Object.freeze(["rule.description","rule.mitre","rule.level","data.path","data.count","data.srcip"]),
    }),
    evidence: "MITRE ATT&CK T1543.003(Windows Service): 공격자는 다시 켜도 악성 프로그램이 실행되도록 서비스를 새로 만들거나 기존 서비스의 실행 파일을 바꿔 자리를 지킨다. https://attack.mitre.org/techniques/T1543/003/",
  }),
  Object.freeze({
    name: "unfamiliar-scheduled-task",
    title: "낯선 예약 작업",
    mitre: "T1053.005",
    condition: Object.freeze({
      summary: "처음 보는 예약 작업이 생기고, 작업 이름이 임의 문자열이거나 임시 폴더의 프로그램을 실행하거나 수업 시간 밖에 실행된다",
      strong: "처음 보는(평소 목록에 없는) 예약 작업이 임시 폴더 프로그램을 실행하거나, 임의 문자열 이름·수업 시간 밖 실행이 함께 있다",
      weak: "예약 작업이 하나 생겼지만 수업 중에 만들어졌거나, 이름이 수업 과제와 비슷하거나, 서명만 확인되지 않았다(기존·평소 시각의 예약 작업은 정상)",
      fields: Object.freeze(["rule.description","rule.mitre","rule.level","data.path","data.srcuser"]),
    }),
    evidence: "MITRE ATT&CK T1053.005(Scheduled Task): 공격자는 예약 작업을 만들어 악성 프로그램을 정해진 시각이나 시스템 시작 때 다시 실행되게 해 자리를 지킨다. https://attack.mitre.org/techniques/T1053/005/",
  }),
  Object.freeze({
    name: "startup-folder-change",
    title: "시작 폴더에 평소 목록에 없는 프로그램 추가",
    mitre: "T1543 (경보 표시), T1547.001 (MITRE 분류)",
    condition: Object.freeze({
      summary: "로그인할 때 자동으로 실행되는 시작 폴더(시작 프로그램)에 평소 목록에 없는 프로그램이 추가된다",
      strong: "시작 폴더에 평소 목록에 없는 프로그램이 추가됐거나, 시작 프로그램과 예약 작업이 같은 임시 파일을 함께 가리킨다",
      weak: "시작 폴더 변경이 1건이고 이어서 실행된 기록이 없거나, 수업 도구 이름이 하나 있고 서명만 아직 모른다(목록을 읽기만 한 것은 정상)",
      fields: Object.freeze(["rule.description","rule.mitre","rule.level","data.path"]),
    }),
    evidence: "이 경보 묶음은 시작 폴더 추가를 T1543(다시 켜도 남는 실행 등록)으로 표시했고, MITRE ATT&CK에서 시작 폴더 자동 실행은 T1547.001(Registry Run Keys / Startup Folder)로 분류된다. https://attack.mitre.org/techniques/T1547/001/",
  }),
]);

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const MAX_TEXT = 2000;

// 실행 파일이 사용자 임시 폴더에 있음(경로 또는 설명)
const TEMP_PATH = /\\(?:temp|tmp)\\|\\appdata\\local\\temp\\/iu;
const TEMP_TEXT = /임시\s*(폴더|파일)/u;
// 경로가 시작 폴더
const STARTUP_PATH = /\\start\s*menu\\programs\\startup\\|\\startup\\/iu;
// 무엇을 가리키는 말인지
const SERVICE = /서비스/u;
const TASK = /예약\s*(작업)?/u;
const STARTUP = /시작\s*(폴더|프로그램|항목)/u;
// 뚜렷한 신호
const UNSIGNED = /서명\s*(이|은)?\s*없|서명\s*없는/u;
const UNFAMILIAR = /처음\s*보는|평소\s*목록에\s*없|임의\s*문자열|수업\s*시간\s*밖/u;
const REGISTERED = /새\s*서비스|서비스\s*등록|등록(됐|되었|했)|실행\s*파일이\s*바뀌|다시\s*켜도\s*남/u;
const ADDED_OR_POINTS = /추가(됐|되었|했)|가리킵|실행합니다/u;
const REPEATED = /연속|(\d+)\s*건입니다/u;
// 변화가 아닌 평소 상태(정상)
const BENIGN = /서명된\s*채로|평소\s*(시각|저장소)|읽기만|기존\s*(예약\s*작업|수업\s*도구\s*서비스)|로그인했|로그아웃했|화면이\s*열렸|업데이트가\s*.*끝났/u;
// 무언가 생기거나 바뀐 기록(애매한 시도 포함)
const CHANGED = /새|처음|추가|등록|바뀌|생겼|만들었|변경|다시\s*시작|가리킵|하나\s*있|비슷/u;

const clamp = (n) => Math.min(0.99, Math.max(0, Math.round(n * 100) / 100));
const str = (value) => (typeof value === 'string' ? value.slice(0, MAX_TEXT) : '');

function toCount(value) {
  const n = typeof value === 'number' ? value : Number.parseInt(String(value ?? ''), 10);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

function signalsOf(alert) {
  const data = alert && typeof alert.data === 'object' && alert.data ? alert.data : {};
  const rule = alert && typeof alert.rule === 'object' && alert.rule ? alert.rule : {};
  const text = str(rule.description);
  const path = str(data.path);
  const mitre = Array.isArray(rule.mitre) ? rule.mitre.map(String) : [];
  const repeatedText = REPEATED.exec(text);
  const count = Math.max(toCount(data.count), repeatedText?.[1] ? Number(repeatedText[1]) : 0);
  return {
    text, level: Number.isFinite(rule.level) ? rule.level : 0,
    tagged: mitre.some(t => /^T1543|^T1053|^T1547/u.test(t)),
    temp: TEMP_PATH.test(path) || TEMP_TEXT.test(text),
    startupPath: STARTUP_PATH.test(path),
    service: SERVICE.test(text), task: TASK.test(text) || mitre.includes('T1053'),
    startup: STARTUP.test(text) || STARTUP_PATH.test(path),
    unsigned: UNSIGNED.test(text), unfamiliar: UNFAMILIAR.test(text), registered: REGISTERED.test(text),
    addedOrPoints: ADDED_OR_POINTS.test(text), repeated: /연속/u.test(text) || count >= 2, count,
    benign: BENIGN.test(text), changed: CHANGED.test(text) || TEMP_PATH.test(path),
  };
}

function toAction(confidence) {
  if (confidence >= BLOCK_AT) return 'block';
  if (confidence >= ALERT_AT) return 'alert';
  return 'record';
}

export function decide(alert) {
  const s = signalsOf(alert);
  if (s.benign && !s.unsigned && !s.unfamiliar) {
    return { action: 'record', confidence: s.tagged ? 0.15 : 0.05, reason: '평소 상태 기록(새로 생기거나 바뀐 자동 실행 등록 없음)' };
  }

  const names = [];
  let confidence = 0;
  // 1) 서명 없는 새 서비스·실행 파일 변경, 또는 평소 목록에 없는 서비스가 임시 폴더 파일로 다시 켜도 남게 등록
  if (s.service && s.registered && (s.unsigned || (s.unfamiliar && s.temp))) {
    names.push('unsigned-new-service');
    confidence = Math.max(confidence, 0.88 + (s.temp ? 0.03 : 0) + (s.repeated ? 0.03 : 0) + (s.level >= 12 ? 0.02 : 0));
  }
  // 2) 처음 보는·임의 이름 예약 작업이 임시 폴더 프로그램을 실행하거나 수업 시간 밖에 실행
  if (s.task && s.unfamiliar && (s.temp || /수업\s*시간\s*밖/u.test(s.text))) {
    names.push('unfamiliar-scheduled-task');
    confidence = Math.max(confidence, 0.87 + (s.temp ? 0.03 : 0) + (s.level >= 12 ? 0.02 : 0));
  }
  // 3) 시작 폴더에 평소 목록에 없는 프로그램 추가, 또는 시작 프로그램과 예약 작업이 같은 임시 파일을 가리킴
  if (s.startup && s.addedOrPoints && (s.unfamiliar || s.temp)) {
    names.push('startup-folder-change');
    if (s.task && TASK.test(s.text) && !names.includes('unfamiliar-scheduled-task')) names.push('unfamiliar-scheduled-task');
    confidence = Math.max(confidence, 0.87 + (s.temp ? 0.02 : 0) + (names.length > 1 ? 0.02 : 0));
  }
  if (names.length) {
    confidence = clamp(confidence);
    return { action: toAction(confidence), confidence,
      reason: `${names.join(' + ')}: 평소 목록에 없는 자동 실행 등록${s.unsigned ? '·서명 없음' : ''}${s.temp ? '·임시 폴더 실행 파일' : ''}${s.repeated && s.count ? `·${s.count}건` : ''}` };
  }

  // 4) 서비스·예약 작업·시작 항목·임시 폴더 실행 파일이 생기거나 바뀌었지만 뚜렷하지 않음 → 알림만
  if (s.changed && (s.service || s.task || s.startup || s.temp)) {
    if (s.service || (s.temp && !s.task && !s.startup)) names.push('unsigned-new-service');
    if (s.task && !s.startup) names.push('unfamiliar-scheduled-task');
    if (s.startup) names.push('startup-folder-change');
    confidence = 0.55 + (s.tagged ? 0.05 : 0) + (s.temp ? 0.05 : 0) + (s.level >= 7 ? 0.05 : 0);
    confidence = clamp(Math.min(confidence, 0.8));
    return { action: toAction(confidence), confidence, reason: `${names.join(' + ')} 의심: 생기거나 바뀌었지만 서명 없음·평소 목록 밖이 확인되지 않음` };
  }

  // 5) 어떤 패턴과도 맞지 않음 → 기록만
  return { action: 'record', confidence: s.tagged ? 0.15 : 0.05, reason: '자동 실행 등록 패턴과 맞는 신호 없음' };
}
