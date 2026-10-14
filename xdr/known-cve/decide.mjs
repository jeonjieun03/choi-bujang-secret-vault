// known-cve 판단 모듈: Wazuh 경보 하나를 받아 block / alert / record 를 돌려줍니다.
// 이 파일은 혼자 계산합니다. 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 네트워크에 묻지 않습니다.
// 패턴은 xdr/known-cve/patterns.json 의 내용을 그대로 옮겨 적은 상수입니다.
export const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'jndi-lookup-header',
    title: '요청 머리글 안의 원격 조회 구문',
    mitre: 'T1190',
    cve: 'CVE-2021-44228',
    condition: Object.freeze({
      summary: "요청 머리글(User-Agent 등)에 '${jndi:' 로 시작해 원격 조회 방식(ldap·ldaps·rmi·dns)과 '://' 가 이어지는 완전한 조회 구문이 들어 있다",
      strong: '머리글에 완전한 조회 구문이 있다(한 번이어도 해당). 같은 출발 주소의 반복(count)이나 주소 인자에도 함께 있으면 더 뚜렷하다',
      weak: "머리글에 중괄호나 조회 구문 조각만 있고 '${jndi:' 와 원격 조회 방식이 함께 있지 않다",
      fields: Object.freeze(['data.useragent', 'data.srcip', 'data.count', 'rule.level', 'rule.description']),
    }),
    evidence: 'CVE-2021-44228: Log4j2가 로그에 남기는 값 속 JNDI 조회 구문을 그대로 실행해 공격자가 지정한 LDAP 등 원격 서버에서 코드를 불러오게 되며, 로그에 남는 요청 머리글이 대표 통로다. https://nvd.nist.gov/vuln/detail/CVE-2021-44228',
  }),
  Object.freeze({
    name: 'jndi-lookup-param',
    title: '요청 주소 인자 안의 원격 조회 구문',
    mitre: 'T1190',
    cve: 'CVE-2021-44228',
    condition: Object.freeze({
      summary: "요청 주소의 인자(검색어·next·probe 등 '?' 뒤 값)에 '${jndi:' 와 원격 조회 방식·'://' 가 이어지는 완전한 조회 구문이 들어 있다",
      strong: '주소 인자에 완전한 조회 구문이 있다(한 번이어도 해당). 같은 출발 주소에서 반복(count)되면 더 뚜렷하다',
      weak: "주소 인자에 'CVE-2021-44228' 이름, 'jndi' 단어, 잘린 조회 조각만 있고 완전한 조회 구문은 없다(취약점 검색·수업 노트 같은 평범한 요청 포함)",
      fields: Object.freeze(['data.url', 'data.srcip', 'data.count', 'rule.level', 'rule.description']),
    }),
    evidence: 'MITRE ATT&CK T1190: 공격자는 외부에 공개된 웹 앱의 알려진 취약점을 악용해 침입하며, 사용자 입력(주소 인자)이 로그에 남는 앱에 CVE-2021-44228 조회 구문을 넣는 것이 이 기법의 사례다. https://attack.mitre.org/techniques/T1190/',
  }),
  Object.freeze({
    name: 'cve-scanner-trace',
    title: '알려진 취약점 점검 도구의 흔적',
    mitre: 'T1190',
    cve: 'CVE-2021-44228',
    condition: Object.freeze({
      summary: "알려진 취약점 점검 도구의 흔적(점검용 인자 이름 probe, 경보 설명의 '알려진 취약점 점검 흔적')이 같은 요청에 있다",
      strong: '점검 흔적과 완전한 원격 조회 구문이 같은 요청에 함께 있다',
      weak: '점검 도구와 비슷한 이름·취약점 목록 열람만 있고 조회 구문은 없다(수업용 점검 프로그램·문서 열람 포함)',
      fields: Object.freeze(['data.url', 'data.useragent', 'rule.description', 'rule.level']),
    }),
    evidence: 'MITRE ATT&CK T1190: 공개 앱 악용은 알려진 취약점(CVE-2021-44228 등)을 자동으로 두드리는 점검 요청으로 이어지는 경우가 많아, 점검 흔적이 조회 구문과 함께 있으면 같은 악용 시도로 본다. https://attack.mitre.org/techniques/T1190/',
  }),
]);

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const MAX_TEXT = 4000;

// 완전한 원격 조회 구문: ${jndi:<조회 방식>://
const FULL_LOOKUP = /\$\{jndi:(?:ldaps?|rmi|dns|iiop|corba|nds|nis|https?):\/\//u;
// 숨긴 표기 풀기: ${lower:j} ${upper:j} ${::-j} ${env:X:-j} 처럼 한 글자를 돌려주는 안쪽 조회를 그 글자로 바꿉니다.
const INNER_CHAR = /\$\{(?:lower|upper|::|env:[^:}]*:|sys:[^:}]*:|date)?:?-?([a-z0-9:/.])\}/giu;
// 애매한 조각: 조회 구문 흔적·CVE 이름·라이브러리 이름 등(완전한 구문은 아님)
const PARTIAL_DATA = /\$\{|jndi|cve-2021-44228|log4j|log-library|lookup/iu;
// 경보 설명에서 읽는 신호
const TEXT_STRONG = /CVE-2021-44228\s*(형태|표기)|원격\s*조회\s*구문이\s*(있|들어|함께)|조회\s*구문이\s*(머리글|주소)/u;
const TEXT_NEGATED = /(조회|악용)\s*구문은\s*없|완전한\s*구문은\s*아닙|글자만\s*있|단어가\s*한\s*번/u;
const TEXT_WEAK = /CVE-2021-44228|jndi|조회\s*(구문|형태)|중괄호|점검\s*도구|취약점\s*(목록|이름)|라이브러리\s*이름/iu;
const TEXT_SCANNER = /알려진\s*취약점\s*점검\s*흔적|취약점\s*점검\s*도구\s*흔적/u;
const SCANNER_PARAM = /[?&]probe=/iu;

const clamp = (n) => Math.min(0.99, Math.max(0, Math.round(n * 100) / 100));
const str = (value) => (typeof value === 'string' ? value.slice(0, MAX_TEXT) : '');

// 주소 인코딩(%24%7B 등)을 한 번 풀고, 숨긴 한 글자 조회를 펼친 뒤 소문자로 봅니다.
function normalize(value) {
  let text = str(value);
  for (let round = 0; round < 2; round += 1) {
    try { text = decodeURIComponent(text.replace(/\+/gu, ' ')); } catch { break; }
  }
  for (let round = 0; round < 5; round += 1) {
    const next = text.replace(INNER_CHAR, '$1');
    if (next === text) break;
    text = next;
  }
  return text.toLowerCase().replace(/\s+/gu, '');
}

function toCount(value) {
  const n = typeof value === 'number' ? value : Number.parseInt(String(value ?? ''), 10);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

function signalsOf(alert) {
  const data = alert && typeof alert.data === 'object' && alert.data ? alert.data : {};
  const rule = alert && typeof alert.rule === 'object' && alert.rule ? alert.rule : {};
  const text = str(rule.description);
  const header = normalize(data.useragent);
  const rawUrl = str(data.url);
  const query = normalize(rawUrl.includes('?') ? rawUrl.slice(rawUrl.indexOf('?')) : '');
  const path = normalize(rawUrl.includes('?') ? rawUrl.slice(0, rawUrl.indexOf('?')) : rawUrl);
  const level = Number.isFinite(rule.level) ? rule.level : 0;
  const mitre = Array.isArray(rule.mitre) ? rule.mitre.map(String) : [];
  const fromText = /(\d+)\s*번/u.exec(text);
  const count = Math.max(toCount(data.count), fromText ? Number(fromText[1]) : 0);
  return {
    text, level, count, tagged: mitre.includes('T1190'),
    headerLookup: FULL_LOOKUP.test(header),
    paramLookup: FULL_LOOKUP.test(query),
    scanner: SCANNER_PARAM.test(rawUrl) || TEXT_SCANNER.test(text),
    partial: PARTIAL_DATA.test(header) || PARTIAL_DATA.test(query) || PARTIAL_DATA.test(path),
    textStrong: TEXT_STRONG.test(text) && !TEXT_NEGATED.test(text),
    textNegated: TEXT_NEGATED.test(text),
    textWeak: TEXT_WEAK.test(text),
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
  let confidence;

  if (s.headerLookup || s.paramLookup) {
    // 1) 머리글·주소 인자에 완전한 원격 조회 구문 → 뚜렷한 악용 형태
    if (s.headerLookup) names.push('jndi-lookup-header');
    if (s.paramLookup) names.push('jndi-lookup-param');
    confidence = s.headerLookup ? 0.9 : 0.88;
    if (s.headerLookup && s.paramLookup) confidence += 0.03;
    if (s.scanner) { names.push('cve-scanner-trace'); confidence += 0.04; }
    if (s.count >= 2) confidence += 0.02;
    if (s.count >= 5) confidence += 0.02;
    if (s.level >= 12) confidence += 0.02;
  } else if (s.textStrong && s.level >= 10) {
    // 2) 요청 칸은 없지만 경보 설명이 완전한 조회 구문이 있다고 밝히고 수준이 높음 → 차단 후보
    names.push(/주소|인자/u.test(s.text) ? 'jndi-lookup-param' : 'jndi-lookup-header');
    if (s.scanner) names.push('cve-scanner-trace');
    confidence = 0.86 + (s.scanner ? 0.03 : 0) + (s.count >= 2 ? 0.02 : 0);
  } else if (s.partial || s.textWeak || s.textNegated || (s.scanner && s.tagged)) {
    // 3) 조각·이름·비슷한 도구만 있음 → 막지 않고 알림
    if (s.scanner || /점검\s*도구|취약점\s*목록/u.test(s.text)) names.push('cve-scanner-trace');
    if (/머리글|중괄호/u.test(s.text) && !names.length) names.push('jndi-lookup-header');
    if (!names.length) names.push('jndi-lookup-param');
    confidence = 0.55;
    if (s.tagged) confidence += 0.05;
    if (s.partial) confidence += 0.05;
    if (s.count >= 2) confidence += 0.05;
    confidence = Math.min(confidence, 0.8);
  } else {
    // 4) 어떤 패턴과도 맞지 않는 평범한 요청 → 기록만
    confidence = s.tagged ? 0.2 : 0.05;
    return { action: 'record', confidence: clamp(confidence), reason: '알려진 악용 패턴과 맞는 신호 없음' };
  }

  confidence = clamp(confidence);
  const action = toAction(confidence);
  const how = action === 'block' ? '완전한 원격 조회 구문'
    : '완전한 조회 구문 없이 이름·조각만 있음';
  const repeat = s.count >= 2 ? `, ${s.count}번` : '';
  return { action, confidence, reason: `${names.join(' + ')} (CVE-2021-44228·T1190): ${how}${repeat}` };
}
