// brute-force 판단 모듈: Wazuh 경보 하나를 받아 block / alert / record 를 돌려줍니다.
// 이 파일은 혼자 계산합니다. 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 네트워크에 묻지 않습니다.
// 패턴은 xdr/brute-force/patterns.json 의 내용을 그대로 옮겨 적은 상수입니다.

export const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'same-source-failure-burst',
    title: '같은 주소의 짧은 시간 로그인 실패 연속',
    mitre: 'T1110.001',
    condition: Object.freeze({
      summary: '같은 출발 주소에서 몇 분 안에 로그인 실패가 연달아 쌓이고 그 사이 성공이 없다',
      strong: '실패 20건 이상이 5분 이내에 쌓이고 성공이 없다',
      weak: '실패 5건 이상이 쌓였지만 건수가 적거나 중간에 성공이 섞여 있다',
    }),
    evidence: 'MITRE ATT&CK T1110.001(Password Guessing): 공격자가 한 계정에 비밀번호를 반복해 넣어 맞히려 하며, 짧은 시간의 로그인 실패 급증이 대표 탐지 신호다. https://attack.mitre.org/techniques/T1110/001/',
  }),
  Object.freeze({
    name: 'password-spraying',
    title: '여러 계정에 같은 비밀번호 대입',
    mitre: 'T1110.003',
    condition: Object.freeze({
      summary: '같은 출발 주소가 서로 다른 여러 계정에 같은 비밀번호로 로그인 실패를 낸다',
      strong: '서로 다른 계정 5개 이상에 같은 비밀번호 실패가 이어진다',
      weak: '같은 주소에서 계정 2~4개에 실패가 나뉘어 있다',
    }),
    evidence: 'MITRE ATT&CK T1110.003(Password Spraying): 계정 잠금을 피하려고 자주 쓰는 비밀번호 하나를 여러 계정에 대입하며, 한 출발지의 여러 계정 로그인 실패가 탐지 신호다. https://attack.mitre.org/techniques/T1110/003/',
  }),
]);

// 패턴 조건에 쓰는 기준값
const STRONG_FAILURES = 20;   // 확실한 실패 연속
const WEAK_FAILURES = 3;      // 의심을 시작하는 실패 건수
const SHORT_WINDOW_MIN = 5;   // "짧은 시간"
const STRONG_ACCOUNTS = 5;    // 확실한 스프레이 계정 수
const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;

const KOREAN_COUNTS = { 한: 1, 두: 2, 세: 3, 네: 4, 다섯: 5, 여섯: 6, 일곱: 7, 여덟: 8, 아홉: 9, 열: 10 };

const clamp = (n) => Math.min(1, Math.max(0, Math.round(n * 100) / 100));

function toCount(value) {
  const n = typeof value === 'number' ? value : Number.parseInt(String(value ?? ''), 10);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

// 경보에서 판단에 필요한 신호만 뽑습니다(원본은 바꾸지 않음).
function signalsOf(alert) {
  const data = alert && typeof alert.data === 'object' && alert.data ? alert.data : {};
  const rule = alert && typeof alert.rule === 'object' && alert.rule ? alert.rule : {};
  const text = typeof rule.description === 'string' ? rule.description : '';
  const level = Number.isFinite(rule.level) ? rule.level : 0;
  const mitre = Array.isArray(rule.mitre) ? rule.mitre.map(String) : [];

  // 실패 건수: data.count 우선, 없으면 설명의 "실패 N건"
  let failures = toCount(data.count);
  const fromText = /실패[^0-9.]{0,6}(\d+)\s*건/u.exec(text);
  if (failures === null && fromText) failures = Number(fromText[1]);
  if (failures === null && /실패/u.test(text)) failures = 1;
  if (failures === null) failures = 0;

  // 시간 창(분)
  const win = /(\d+)\s*분/u.exec(text);
  const windowMin = win ? Number(win[1]) : null;

  // 성공 여부
  const noSuccess = /성공(은|이)?\s*없/u.test(text);
  const successAfter = !noSuccess && /성공/u.test(text);

  // 서로 다른 계정 수
  let accounts = 0;
  if (typeof data.accounts === 'string') {
    accounts = new Set(data.accounts.split(/[,\s]+/u).filter(Boolean)).size;
  } else if (Array.isArray(data.accounts)) {
    accounts = new Set(data.accounts.map(String)).size;
  }
  const numAcc = /계정\s*(\d+)\s*개/u.exec(text);
  if (numAcc) accounts = Math.max(accounts, Number(numAcc[1]));
  const wordAcc = /(한|두|세|네|다섯|여섯|일곱|여덟|아홉|열)\s*계정/u.exec(text);
  if (wordAcc) accounts = Math.max(accounts, KOREAN_COUNTS[wordAcc[1]]);
  const manyAccounts = /여러\s*계정|계정\s*이름을\s*바꿔/u.test(text);
  const samePassword = /같은\s*비밀번호/u.test(text);

  return { text, level, mitre, failures, windowMin, noSuccess, successAfter, accounts, manyAccounts, samePassword };
}

// 패턴 1: 같은 주소의 짧은 시간 실패 연속
function scoreBurst(s) {
  if (s.failures < WEAK_FAILURES) {
    return { score: s.failures > 0 ? 0.2 : 0, note: s.failures > 0 ? `실패 ${s.failures}건(기준 미만)` : '' };
  }
  let score;
  if (s.failures >= STRONG_FAILURES) {
    score = 0.85;
    if (s.windowMin !== null && s.windowMin <= SHORT_WINDOW_MIN) score += 0.05;
    if (s.noSuccess) score += 0.04;
    if (s.level >= 10) score += 0.03;
    if (s.successAfter) score = 0.7; // 끝내 성공했다면 사람 실수일 수도 있어 알림까지만
  } else {
    // 3~19건: 애매한 구간(알림)
    score = 0.5 + Math.min(0.25, (s.failures - WEAK_FAILURES) * 0.02);
    if (s.level >= 10) score += 0.05;
    if (s.successAfter) score -= 0.02;
    score = Math.min(score, 0.8);
  }
  const parts = [`실패 ${s.failures}건`];
  if (s.windowMin !== null) parts.push(`${s.windowMin}분`);
  if (s.noSuccess) parts.push('성공 없음');
  if (s.successAfter) parts.push('뒤에 성공');
  return { score, note: parts.join(', ') };
}

// 패턴 2: 여러 계정에 같은 비밀번호
function scoreSpray(s) {
  const accounts = s.accounts || (s.manyAccounts ? STRONG_ACCOUNTS : 0);
  if (accounts < 2 || (s.failures === 0 && !s.samePassword)) return { score: 0, note: '' };
  let score;
  if (accounts >= STRONG_ACCOUNTS && (s.samePassword || s.failures >= accounts || s.level >= 10)) {
    score = 0.88 + (s.samePassword ? 0.05 : 0) + (s.level >= 10 ? 0.03 : 0);
  } else if (accounts >= STRONG_ACCOUNTS) {
    score = 0.75;
  } else {
    score = 0.55 + (s.samePassword ? 0.1 : 0);
  }
  return { score, note: `계정 ${accounts}개${s.samePassword ? ', 같은 비밀번호' : ''}` };
}

export function decide(alert) {
  const s = signalsOf(alert);
  const results = [
    { pattern: PATTERNS[0], ...scoreBurst(s) },
    { pattern: PATTERNS[1], ...scoreSpray(s) },
  ].sort((a, b) => b.score - a.score);
  const best = results[0];
  const confidence = clamp(best.score);
  const action = confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record';

  if (action === 'record' && confidence < 0.2) {
    return { action, confidence, reason: '해당 패턴 없음: 로그인 실패 연속·여러 계정 대입 신호가 없음' };
  }
  const reason = `${best.pattern.name} (${best.pattern.mitre}): ${best.note || '신호 약함'}`;
  return { action, confidence, reason };
}
