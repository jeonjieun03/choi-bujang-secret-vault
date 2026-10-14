// privilege 판단 모듈: 계정·그룹 변경 경보와 관리자 권한 사용 경보 하나를 받아 block / alert / record 를 돌려줍니다.
// 이 파일은 혼자 계산합니다. 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 네트워크에 묻지 않습니다.
// 패턴은 xdr/privilege/patterns.json 의 내용을 그대로 옮겨 적은 상수입니다.
// 기법 표시(T1068·T1078)만으로 막지 않고, 설명(관리자 그룹 추가·관리자 명령·시각·주소)과 그룹 이름·반복 횟수를 함께 봅니다.
export const PATTERNS = Object.freeze([
  Object.freeze({
    name: "admin-group-addition",
    title: "평범한 계정의 관리자 그룹 추가",
    mitre: "T1078 (경보 표시), T1098.007 (MITRE 분류)",
    condition: Object.freeze({
      summary: "평범한 계정이 관리자 그룹(administrators)에 추가된다",
      strong: "원격·처음 보는 주소에서 추가되거나, 추가 직후 관리자 명령이 이어지거나, 같은 주소에서 여러 계정이 한꺼번에 추가되거나, 빠졌던 계정이 곧바로 다시 들어온다",
      weak: "관리자 그룹이 아닌 과제·수업 그룹에 추가되거나, 새 로컬 그룹이 생겼거나, 그룹 설명만 바뀌었다(그룹 소속을 읽기만 한 것은 정상)",
      fields: Object.freeze(["data.group","data.count","data.srcip","data.srcuser","rule.description","rule.level"]),
    }),
    evidence: "이 경보 묶음은 관리자 그룹 추가를 T1078(도용한 정상 계정의 권한 높이기)로 표시했고, MITRE ATT&CK에서 계정을 관리자 같은 권한 그룹에 넣는 행위는 T1098.007(Additional Local or Domain Groups)로 분류된다. https://attack.mitre.org/techniques/T1098/007/",
  }),
  Object.freeze({
    name: "unfamiliar-admin-command",
    title: "처음 보는 관리자 명령",
    mitre: "T1068",
    condition: Object.freeze({
      summary: "평범한 계정이나 방금 권한이 높아진 세션이 관리자 명령을 실행한다",
      strong: "방금 관리자가 된 계정이 곧바로 관리자 명령을 실행하거나, 세션이 갑자기 관리자 권한으로 바뀌거나, 다른 계정의 권한으로 관리자 명령을 실행하거나, 처음 보는 주소에서 관리자 명령을 실행한다",
      weak: "평소 주소에서 관리자 명령이 한 번 실행됐거나, 권한 상승 창이 뜨고 취소됐거나, 관리자 명령이 실패로 끝났거나, 권한 상승 뒤 이어진 명령이 없다",
      fields: Object.freeze(["rule.description","rule.mitre","rule.level","data.srcip","data.srcuser"]),
    }),
    evidence: "MITRE ATT&CK T1068: 공격자는 소프트웨어 취약점을 악용해 평범한 계정의 권한을 관리자 수준으로 높인 뒤 관리자 명령을 실행하며, 평범한 세션이 갑자기 관리자 권한으로 명령을 실행하는 것이 그 흔적이다. https://attack.mitre.org/techniques/T1068/",
  }),
  Object.freeze({
    name: "off-hours-privilege-use",
    title: "업무 시간 밖 권한 사용",
    mitre: "T1078",
    condition: Object.freeze({
      summary: "수업·업무 시간 밖이거나 업무처럼 보이지 않는 시각에 관리자 권한이 쓰인다(관리자 그룹 추가·관리자 명령 포함)",
      strong: "업무 시간 밖에 관리자 권한 사용이 있고, 처음 보는 주소이거나 관리자 그룹 추가·명령 실행이 함께 있다",
      weak: "수업 시간 중의 권한 상승 1건처럼 시각은 평소 범위이고 이어진 관리자 활동이 없다",
      fields: Object.freeze(["rule.description","rule.level","data.srcip","data.srcuser"]),
    }),
    evidence: "MITRE ATT&CK T1078: 공격자가 도용한 정상 계정은 평소와 다른 시각이나 처음 보는 곳에서 쓰이는 경우가 많아, 업무 시간 밖의 권한 사용은 도용된 계정을 찾는 단서가 된다. https://attack.mitre.org/techniques/T1078/",
  }),
]);

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const MAX_TEXT = 2000;

// 관리자 그룹 추가(관리자 그룹이 아니라고 밝힌 경우는 제외)
const ADMIN_GROUP_NAME = /^(administrators|admins?|domain admins|관리자)$/iu;
const ADMIN_GROUP_TEXT = /관리자\s*그룹에\s*(추가|들어)|관리자\s*그룹\s*추가|다시\s*관리자로\s*들어/u;
const NOT_ADMIN_GROUP = /관리자\s*그룹은\s*아닙/u;
// 관리자 그룹 추가를 뚜렷하게 만드는 것
const GROUP_STRONG = /원격\s*주소|처음\s*보는|곧바로|명령\s*실행|계정\s*\d+\s*개|빠진\s*계정이.*다시/u;
// 관리자 명령·권한 사용
const ADMIN_USE = /관리자\s*명령을\s*실행|권한\s*명령을\s*실행|관리자\s*권한으로\s*바뀌|명령\s*실행이\s*같이/u;
const ADMIN_USE_STRONG = /방금\s*관리자가\s*된|처음\s*보는|처음\s*봅|다른\s*계정의\s*권한|관리자\s*권한으로\s*바뀌|곧바로/u;
// 업무 시간 밖
const OFF_HOURS = /(수업|업무)\s*시간\s*밖|업무처럼\s*보이지\s*않는\s*시각|새벽|심야/u;
// 권한·그룹과 관련은 있지만 뚜렷하지 않음(애매한 시도)
const WEAK_HINT = /권한\s*상승|관리자\s*명령|그룹에\s*추가|그룹이\s*하나\s*만들|그룹\s*설명|계정\s*종류/u;
// 평소 활동(정상)
const BENIGN = /로그인했|로그아웃했|읽기만|세션\s*정보를\s*조회|자료실을\s*열었|평소\s*예약\s*작업을\s*확인|비밀번호를\s*변경/u;

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
  const group = str(data.group).trim();
  const mitre = Array.isArray(rule.mitre) ? rule.mitre.map(String) : [];
  const accounts = /계정\s*(\d+)\s*개/u.exec(text);
  const count = Math.max(toCount(data.count), accounts ? Number(accounts[1]) : 0);
  const adminGroup = !NOT_ADMIN_GROUP.test(text) && (ADMIN_GROUP_NAME.test(group) || ADMIN_GROUP_TEXT.test(text));
  return {
    text, level: Number.isFinite(rule.level) ? rule.level : 0, count,
    tagged: mitre.some(t => /^T1068|^T1078|^T1098/u.test(t)),
    adminGroup,
    groupStrong: adminGroup && (GROUP_STRONG.test(text) || count >= 2),
    adminUse: ADMIN_USE.test(text),
    adminUseStrong: ADMIN_USE.test(text) && ADMIN_USE_STRONG.test(text),
    offHours: OFF_HOURS.test(text) && (ADMIN_USE.test(text) || adminGroup || /관리자|권한/u.test(text)),
    weak: WEAK_HINT.test(text) || (group && !adminGroup),
    benign: BENIGN.test(text),
  };
}

function toAction(confidence) {
  if (confidence >= BLOCK_AT) return 'block';
  if (confidence >= ALERT_AT) return 'alert';
  return 'record';
}

export function decide(alert) {
  const s = signalsOf(alert);
  const names = [];
  if (s.groupStrong) names.push('admin-group-addition');
  if (s.adminUseStrong) names.push('unfamiliar-admin-command');
  if (s.offHours) names.push('off-hours-privilege-use');

  // 1) 뚜렷한 권한 가로채기: 관리자 그룹 추가(원격·연속·재가입·명령 동반), 처음 보는 관리자 명령, 업무 시간 밖 권한 사용
  if (names.length) {
    let confidence = 0.87 + 0.03 * (names.length - 1);
    if (s.adminGroup && s.adminUse) confidence += 0.02;
    if (s.count >= 2) confidence += 0.02;
    if (s.level >= 12) confidence += 0.02;
    confidence = clamp(confidence);
    const extra = s.count >= 2 ? ` · ${s.count}건` : '';
    return { action: toAction(confidence), confidence, reason: `${names.join(' + ')} (T1068·T1078): 평소와 다른 권한 상승${extra}` };
  }

  // 2) 관리자 그룹 추가만 있고 뚜렷한 동반 신호가 없음 → 알림
  if (s.adminGroup) {
    return { action: 'alert', confidence: 0.75, reason: 'admin-group-addition 의심 (T1078): 관리자 그룹 추가, 동반 신호 없음' };
  }

  // 3) 평소 활동(로그인·로그아웃·읽기만·비밀번호 변경 등) → 기록만
  if (s.benign && !s.adminUse && !s.weak) {
    return { action: 'record', confidence: s.tagged ? 0.2 : 0.05, reason: '평소 계정 활동(권한 상승 없음)' };
  }

  // 4) 권한·그룹과 관련은 있지만 뚜렷하지 않음 → 알림만
  if (s.weak || s.adminUse || s.tagged) {
    const name = s.adminUse || /권한\s*상승|관리자\s*명령/u.test(s.text) ? 'unfamiliar-admin-command' : 'admin-group-addition';
    const confidence = clamp(Math.min(0.55 + (s.tagged ? 0.05 : 0) + (s.level >= 7 ? 0.05 : 0) + (s.adminUse ? 0.05 : 0), 0.8));
    return { action: toAction(confidence), confidence, reason: `${name} 의심 (T1068·T1078): 권한·그룹 변화가 있지만 뚜렷하지 않음` };
  }

  // 5) 어떤 패턴과도 맞지 않음 → 기록만
  return { action: 'record', confidence: 0.05, reason: '권한 상승 패턴과 맞는 신호 없음' };
}
