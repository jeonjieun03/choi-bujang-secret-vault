// exfiltration 판단 모듈: 외부 전송 경보 하나를 받아 block / alert / record 를 돌려줍니다.
// 이 파일은 혼자 계산합니다. 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 네트워크에 묻지 않습니다.
// 패턴은 xdr/exfiltration/patterns.json 의 내용을 그대로 옮겨 적은 상수입니다.
// 기법 표시(T1041·T1048)만으로 막지 않고, 전송량·파일 수·반복 횟수와 설명(처음 보는 목적지·업무 시간 밖·압축·명령 통로)을 함께 봅니다.
export const PATTERNS = Object.freeze([
  Object.freeze({
    name: "new-destination-bulk-transfer",
    title: "처음 보는 목적지로 대용량 전송",
    mitre: "T1048",
    condition: Object.freeze({
      summary: "처음 보는(평소 목록에 없는) 바깥 목적지로 큰 전송량이나 많은 파일이 나가거나, 평소에 쓰지 않던 포트로 자료가 연속 전송된다",
      strong: "처음 보는 목적지·외부 주소로 대용량(약 50MB 이상) 또는 많은 파일(약 50건 이상)이 나가거나, 같은 목적지로 대용량 전송이 반복되거나, 자료실 전체가 외부로 복사된다",
      weak: "처음 보는 주소로 작은 파일만 나갔거나, 전송이 실패했거나, 전송량이 평소보다 한 번 높지만 목적지는 평소 주소다",
      fields: Object.freeze(["data.dstip","data.bytes","data.files","data.count","rule.description","rule.level"]),
    }),
    evidence: "MITRE ATT&CK T1048: 공격자는 평소 쓰는 통로가 아닌 다른 프로토콜·포트·목적지로 자료를 빼돌리며, 처음 보는 바깥 주소로 많은 자료가 한꺼번에 나가는 것이 그 흔적이다. https://attack.mitre.org/techniques/T1048/",
  }),
  Object.freeze({
    name: "off-hours-archive-exfil",
    title: "업무 시간 밖 압축 파일 반출",
    mitre: "T1048 (반출), T1560 (압축, MITRE 분류)",
    condition: Object.freeze({
      summary: "업무·수업 시간 밖이거나 처음 보는 주소로 압축 파일이 나간다",
      strong: "업무 시간 밖에 처음 보는 주소로 압축 파일이 나가거나, 압축 파일 여러 개가 연속으로 또는 여러 목적지로 처음 보는 주소에 올라간다",
      weak: "수업 시간에 압축 파일을 만들기만 하고 외부 전송은 없거나, 압축 파일을 연 뒤 일부만 다른 주소로 나갔거나, 수업 끝 무렵 백업처럼 보이는 전송이 1건이다",
      fields: Object.freeze(["data.dstip","data.bytes","data.files","rule.description","rule.level"]),
    }),
    evidence: "MITRE ATT&CK T1048: 공격자는 빼낼 자료를 다른 통로로 내보내며, 그 전에 자료를 압축해 묶는 행위는 MITRE에서 T1560(Archive Collected Data)으로 분류되어 업무 시간 밖 압축 파일 반출은 유출의 흔적이 된다. https://attack.mitre.org/techniques/T1560/",
  }),
  Object.freeze({
    name: "c2-channel-exfil",
    title: "명령 통로로 자료 유출",
    mitre: "T1041",
    condition: Object.freeze({
      summary: "공격자가 원격 조종에 쓰는 명령 통로(C2)로 자료나 큰 파일이 처음 보는 목적지에 전송된다",
      strong: "명령 통로로 큰 파일이 처음 보는 목적지에 반복 전송되거나, 같은 목적지로 업무 시간 밖에 전송이 여러 번 반복된다",
      weak: "명령 통로에 짧은 자료 이름만 몇 번 보이고 큰 파일은 아니다",
      fields: Object.freeze(["data.dstip","data.bytes","data.count","rule.description","rule.level"]),
    }),
    evidence: "MITRE ATT&CK T1041: 공격자는 원격 조종에 쓰는 기존 명령 통로에 훔친 자료를 섞어 같은 목적지로 내보내며, 명령 통로로 큰 파일이 반복 전송되는 것이 그 흔적이다. https://attack.mitre.org/techniques/T1041/",
  }),
]);

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const MAX_TEXT = 2000;
const BULK_BYTES = 50_000_000;     // 대용량으로 보는 전송량(약 50MB)
const MEDIUM_BYTES = 1_000_000;    // 살펴볼 만한 전송량(약 1MB)
const MANY_FILES = 50;             // 많은 파일
const REPEAT = 5;                  // 반복으로 보는 횟수

// 유출 정황
const NEW_DEST = /처음\s*보는|처음\s*봅|외부\s*주소|평소에\s*쓰지\s*않던|평소와\s*다른\s*주소|다른\s*주소/u;
const OFF_HOURS = /(업무|수업)\s*시간\s*밖|업무처럼\s*보이지\s*않는\s*시각|새벽|심야/u;
const ARCHIVE = /압축\s*파일/u;
const C2 = /명령\s*통로/u;
const WHOLE = /자료실\s*전체|전체가\s*외부|한\s*번에\s*나갔|짧은\s*시간에|연속/u;
const REPEATED_TEXT = /(\d+)\s*번\s*(반복|입니다)|반복\s*전송|반복됐/u;
// 평소 목적지(정상 쪽)
const USUAL_DEST = /평소\s*목적지|수업\s*자료\s*주소|목적지는\s*자료실/u;
// 평소 활동
const BENIGN = /읽었습니다|동기화가\s*끝났|받았습니다|새로고침|저장했습니다|열었습니다|세션\s*확인|로그아웃/u;
// 애매한 시도 힌트
const WEAK_HINT = /처음\s*보는|처음\s*봅|평소와\s*다른|평소보다|압축\s*파일|백업|읽힌\s*뒤\s*전송|명령\s*통로|실패|파일\s*수가|일부만/u;

const clamp = (n) => Math.min(0.99, Math.max(0, Math.round(n * 100) / 100));
const str = (value) => (typeof value === 'string' ? value.slice(0, MAX_TEXT) : '');
function num(value) {
  const n = typeof value === 'number' ? value : Number.parseInt(String(value ?? '').replace(/[,_\s]/gu, ''), 10);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

function signalsOf(alert) {
  const data = alert && typeof alert.data === 'object' && alert.data ? alert.data : {};
  const rule = alert && typeof alert.rule === 'object' && alert.rule ? alert.rule : {};
  const text = str(rule.description);
  const mitre = Array.isArray(rule.mitre) ? rule.mitre.map(String) : [];
  const repeatedText = REPEATED_TEXT.exec(text);
  const filesText = /자료\s*(\d+)\s*건/u.exec(text);
  return {
    text, level: Number.isFinite(rule.level) ? rule.level : 0,
    tagged: mitre.some(t => /^T1041|^T1048|^T1560/u.test(t)),
    bytes: num(data.bytes),
    files: Math.max(num(data.files), filesText ? Number(filesText[1]) : 0),
    count: Math.max(num(data.count), repeatedText?.[1] ? Number(repeatedText[1]) : 0),
    repeated: Boolean(repeatedText) || num(data.count) >= REPEAT,
    newDest: NEW_DEST.test(text), offHours: OFF_HOURS.test(text), archive: ARCHIVE.test(text),
    c2: C2.test(text), whole: WHOLE.test(text), usualDest: USUAL_DEST.test(text),
    benign: BENIGN.test(text), weak: WEAK_HINT.test(text),
  };
}

function toAction(confidence) {
  if (confidence >= BLOCK_AT) return 'block';
  if (confidence >= ALERT_AT) return 'alert';
  return 'record';
}

function mb(bytes) { return `${Math.round(bytes / 1_000_000)}MB`; }

export function decide(alert) {
  const s = signalsOf(alert);
  const context = s.newDest || s.offHours || s.c2 || s.whole || s.repeated || s.files >= MANY_FILES;

  // 1) 대용량 전송 + 유출 정황(처음 보는 목적지·업무 시간 밖·명령 통로·반복·자료실 전체·많은 파일), 평소 목적지가 아님 → 차단 후보
  if (s.bytes >= BULK_BYTES && context && !s.usualDest) {
    const names = [];
    if (s.archive && (s.offHours || s.newDest)) names.push('off-hours-archive-exfil');
    if (s.c2 || (s.offHours && s.repeated && !s.archive)) names.push('c2-channel-exfil');
    if (!names.length || s.files >= MANY_FILES || s.whole || (s.newDest && !s.archive)) names.unshift('new-destination-bulk-transfer');
    let confidence = 0.86;
    if (s.newDest) confidence += 0.03;
    if (s.repeated || s.files >= 100) confidence += 0.03;
    if (s.offHours) confidence += 0.02;
    if (s.bytes >= 200_000_000) confidence += 0.02;
    if (s.level >= 12) confidence += 0.02;
    confidence = clamp(confidence);
    const extra = [mb(s.bytes), s.files ? `파일 ${s.files}건` : '', s.count >= 2 ? `${s.count}번` : ''].filter(Boolean).join('·');
    return { action: toAction(confidence), confidence, reason: `${[...new Set(names)].join(' + ')} (T1041·T1048): ${extra}` };
  }

  // 2) 평소 활동(작은 전송·읽기·저장·동기화) → 기록만
  if (s.benign && s.bytes < MEDIUM_BYTES && !s.newDest && !s.offHours && !s.c2) {
    return { action: 'record', confidence: s.tagged ? 0.15 : 0.05, reason: '평소 전송(작은 크기·평소 목적지)' };
  }

  // 3) 유출 정황이나 평소보다 큰 전송이 있지만 뚜렷하지 않음 → 알림만
  if (s.weak || context || s.bytes >= MEDIUM_BYTES || (s.tagged && s.level >= 5)) {
    const name = s.c2 ? 'c2-channel-exfil' : s.archive ? 'off-hours-archive-exfil' : 'new-destination-bulk-transfer';
    let confidence = 0.55;
    if (s.tagged) confidence += 0.05;
    if (s.bytes >= MEDIUM_BYTES) confidence += 0.05;
    if (s.newDest || s.offHours) confidence += 0.05;
    confidence = clamp(Math.min(confidence, 0.8));
    return { action: toAction(confidence), confidence, reason: `${name} 의심 (T1041·T1048): ${mb(s.bytes)}, 대용량·뚜렷한 유출 정황 없음` };
  }

  // 4) 어떤 패턴과도 맞지 않음 → 기록만
  return { action: 'record', confidence: 0.05, reason: '유출 패턴과 맞는 신호 없음' };
}
