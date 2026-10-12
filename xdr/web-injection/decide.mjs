// web-injection 판단 모듈: 웹 접근 경보 하나를 받아 block / alert / record 를 돌려줍니다.
// 이 파일은 혼자 계산합니다. 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 네트워크에 묻지 않습니다.
// 패턴은 xdr/web-injection/patterns.json 의 내용을 그대로 옮겨 적은 상수입니다.

export const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'sql-injection',
    title: '요청 인자 안의 SQL 구문',
    mitre: 'T1190',
    cwe: 'CWE-89',
    condition: Object.freeze({
      summary: '주소창·입력 칸의 요청 인자에 SQL 구문(따옴표로 끊고 OR·UNION·SELECT 등을 이어 붙임)이 들어 있다',
      strong: '같은 출발 주소에서 SQL 구문 표기가 5번 이상 반복된다',
      weak: 'SQL 구문처럼 보이는 표기가 1번 있고 반복되지 않는다(수업명 select·SQL 같은 평범한 단어는 제외)',
    }),
    evidence: 'MITRE ATT&CK T1190: 공격자는 외부에 공개된 웹 앱의 약점을 악용해 침입하며 SQL 주입이 대표 예이고(CWE-89), 무브잇 사건(CVE-2023-34362)도 이 형태였다. https://attack.mitre.org/techniques/T1190/',
  }),
  Object.freeze({
    name: 'script-injection',
    title: '요청 인자 안의 스크립트 태그',
    mitre: 'T1190',
    cwe: 'CWE-79',
    condition: Object.freeze({
      summary: '요청 인자에 스크립트 태그나 스크립트 실행 표식이 들어 있다',
      strong: '같은 출발 주소에서 스크립트 삽입 표식이 5번 이상 반복된다',
      weak: "스크립트 표식처럼 보이는 표기가 1번 있고 반복되지 않는다(수업 단어 '스크립트'는 제외)",
    }),
    evidence: 'MITRE ATT&CK T1190: 공개 웹 앱의 입력 처리 약점을 노린 요청이며, 요청 인자에 스크립트를 끼워 넣는 형태는 CWE-79(교차 사이트 스크립팅)로 분류된다. https://attack.mitre.org/techniques/T1190/',
  }),
  Object.freeze({
    name: 'path-traversal',
    title: '경로 거슬러 올라가기(../) 반복',
    mitre: 'T1190',
    cwe: 'CWE-22',
    condition: Object.freeze({
      summary: '파일 경로 인자에 상위 폴더로 거슬러 올라가는 표기(../)가 여러 단계 반복된다',
      strong: '같은 출발 주소에서 경로 이탈 표기가 5번 이상 반복된다',
      weak: '경로 인자에 이탈처럼 보이는 표기가 1번 있고 반복되지 않는다',
    }),
    evidence: 'MITRE ATT&CK T1190: 공개 웹 앱의 파일 경로 처리 약점을 노려 허용 밖 파일을 읽으려는 형태이며, ../ 반복은 CWE-22(경로 조작)의 대표 신호다. https://attack.mitre.org/techniques/T1190/',
  }),
  Object.freeze({
    name: 'command-injection',
    title: '요청 인자 안의 명령 구분자',
    mitre: 'T1190',
    cwe: 'CWE-78',
    condition: Object.freeze({
      summary: '요청 인자에 운영체제 명령을 이어 붙이는 구분자(; | && 등) 표기가 들어 있다',
      strong: '같은 출발 주소에서 명령 구분자 표기가 5번 이상 반복된다',
      weak: '구분 문자가 1번 있고 반복되지 않는다(이름 검색의 평범한 구분 문자는 제외)',
    }),
    evidence: 'MITRE ATT&CK T1190: 공개 웹 앱 입력을 통해 서버 명령을 실행시키려는 형태이며, 요청 인자의 명령 구분자 삽입은 CWE-78(OS 명령 주입)로 분류된다. https://attack.mitre.org/techniques/T1190/',
  }),
]);

const STRONG_REPEAT = 5;     // "반복"으로 보는 횟수
const NOTABLE_LEVEL = 5;     // 이 수준 이상은 살펴볼 만한 웹 경보
const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;

// 패턴별로 "확실한 주입 표식"을 찾는 규칙: 경보 설명(한국어)과 요청 주소(url)를 함께 봅니다.
const MARKERS = Object.freeze({
  'sql-injection': {
    text: /SQL\s*(구문|표식|표기)|데이터베이스\s*조회를\s*이어/iu,
    url: /doc-sql|union(\s|%20|\+)+select|('|%27)(\s|%20|\+)*(or|and)(\s|%20|\+)|\bor(\s|%20|\+)+1=1|;--|'--/iu,
  },
  'script-injection': {
    text: /스크립트\s*(삽입|표식|표기)/u,
    url: /doc-script|<\s*script|%3c\s*script|javascript:|onerror\s*=/iu,
  },
  'path-traversal': {
    text: /경로를?\s*(여러\s*단계\s*)?(거슬러|이탈)|경로\s*이탈/u,
    url: /doc-up-repeat|(\.\.|%2e%2e)(\/|%2f|\\)/iu,
  },
  'command-injection': {
    text: /명령\s*구분자/u,
    url: /doc-cmd|;\s*(cat|ls|id|whoami|wget|curl)\b|&&|\|\||`|\$\(/iu,
  },
});

// "~는 아닙니다", "수업명" 처럼 평범한 단어임을 밝힌 설명
const BENIGN_HINT = /아닙니다|수업\s*(명|단어|공지)|공격\s*표기는\s*없/u;
// 한 번뿐인 의심 표기(애매한 시도)
const WEAK_HINT = /따옴표|select|SQL|스크립트|up\s*이|구분\s*문자|주입처럼|이상한\s*검색|평소보다\s*깁/iu;

const clamp = (n) => Math.min(1, Math.max(0, Math.round(n * 100) / 100));

function toCount(value) {
  const n = typeof value === 'number' ? value : Number.parseInt(String(value ?? ''), 10);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

function signalsOf(alert) {
  const data = alert && typeof alert.data === 'object' && alert.data ? alert.data : {};
  const rule = alert && typeof alert.rule === 'object' && alert.rule ? alert.rule : {};
  const text = typeof rule.description === 'string' ? rule.description : '';
  const url = typeof data.url === 'string' ? data.url : '';
  const level = Number.isFinite(rule.level) ? rule.level : 0;

  // 반복 횟수: data.count 우선, 없으면 설명의 "N번"
  let count = toCount(data.count);
  const fromText = /(\d+)\s*번/u.exec(text);
  if (count === null && fromText) count = Number(fromText[1]);
  if (count === null) count = 0;
  const notRepeated = /반복(은|되지)\s*(없|않)/u.test(text);

  const benign = BENIGN_HINT.test(text);
  const matched = [];
  for (const pattern of PATTERNS) {
    const m = MARKERS[pattern.name];
    if (m.text.test(text) || m.url.test(url)) matched.push(pattern);
  }
  return { text, url, level, count, notRepeated, benign, matched, weakHint: WEAK_HINT.test(text) || WEAK_HINT.test(url) };
}

export function decide(alert) {
  const s = signalsOf(alert);
  const names = s.matched.map(p => p.name);

  // 1) 확실한 주입 표식이 있고 반복된다 → 차단 후보
  if (s.matched.length && !s.benign && !s.notRepeated && s.count >= STRONG_REPEAT) {
    let score = 0.86;
    if (s.level >= 10) score += 0.05;
    if (s.count >= 10) score += 0.03;
    if (s.matched.length > 1) score += 0.02;
    return {
      action: 'block',
      confidence: clamp(score),
      reason: `${names.join(' + ')} (T1190): 같은 주소에서 ${s.count}번 반복`,
    };
  }

  // 2) 표식은 있지만 반복이 적다 → 알림
  if (s.matched.length && !s.benign && s.count >= 2) {
    return {
      action: 'alert',
      confidence: clamp(0.6 + Math.min(0.2, s.count * 0.03)),
      reason: `${names.join(' + ')} (T1190): ${s.count}번, 반복 기준 미만`,
    };
  }

  // 3) 한 번뿐인 의심 표기, 또는 살펴볼 만한 수준의 경보 → 애매한 시도로 알림
  if (s.level >= NOTABLE_LEVEL && (s.matched.length || s.weakHint || s.benign)) {
    const nearest = names[0]
      ?? (/sql|select|따옴표/iu.test(s.text + s.url) ? 'sql-injection'
        : /스크립트|script/iu.test(s.text + s.url) ? 'script-injection'
          : /경로|path|up/iu.test(s.text + s.url) ? 'path-traversal'
            : /구분/u.test(s.text) ? 'command-injection'
              // 특정 표식이 없으면 요청 종류로 가장 가까운 패턴을 고릅니다(파일 경로 → 경로 이탈, 그 밖의 조회 인자 → SQL)
              : /\/files/u.test(s.url) ? 'path-traversal' : 'sql-injection');
    return {
      action: 'alert',
      confidence: clamp(0.5 + (s.level >= 7 ? 0.05 : 0) + (s.matched.length && !s.benign ? 0.05 : 0)),
      reason: `${nearest} 의심 (T1190): 표기 ${Math.max(1, s.count)}번, 반복 없음`,
    };
  }

  // 4) 주입 신호 없음 → 기록만
  return {
    action: 'record',
    confidence: clamp(s.level >= NOTABLE_LEVEL ? 0.3 : 0.05),
    reason: '해당 패턴 없음: 요청 인자에 주입 표기가 없음',
  };
}
