// 9단계에서 학생이 채우는 탐지 함수입니다. 이 기본값은 어떤 접속도 회수하지 않습니다.
// 반 엔진이 검증한 사건만 전달해야 하며, 브라우저가 보낸 사용자 번호는 받지 않습니다.
//
// 9단계 제작 1 · 입력 정리(readDetectionEvents)
// 가상 사건(docs/DETECT_EVENTS.md)에서 아래 값만 골라 읽습니다.
//   가명 사용자  identity.sub      (엔진이 만든 가명 ID. 실명·이메일·Supabase 사용자 번호가 아님)
//   기기        deviceId           (16자리 소문자 16진수 가상 기기 ID. 개인키가 아님. 없으면 null)
//   요청 종류    method             (GET·POST·PUT·PATCH·DELETE)
//   판정        decision           (allow·deny·step_up. 없으면 null)
//   시각        at                 (10분 구간을 세기 위한 UTC ISO 시각)
//   네트워크     network 또는 signals.network (제작 2: 'usual'이면 평소, 그 밖의 값은 평소와 다름, 없거나 'unknown'이면 모름 null)
// 메모 내용(body·title·content)·토큰(authorization·token)·실명(name·email) 등 그 밖의 값은
// 읽지도, 저장하지도, 출력하지도 않습니다. 형식이 틀린 사건은 임의의 값으로 채우지 않고 건너뜁니다.

const SUB = /^[A-Za-z0-9_-]{1,128}$/u;
const DEVICE_ID = /^[0-9a-f]{16}$/u;
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
const DECISIONS = new Set(['allow', 'deny', 'step_up']);
const MAX_EVENTS = 100_000;
const NETWORK = /^[a-z][a-z0-9_-]{0,31}$/u;

function networkOf(event) {
  const raw = typeof event.network === 'string' ? event.network
    : (event.signals && typeof event.signals === 'object' && !Array.isArray(event.signals)
      && typeof event.signals.network === 'string') ? event.signals.network : null;
  return raw !== null && NETWORK.test(raw) && raw !== 'unknown' ? raw : null;
}

function readOne(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) return null;
  const identity = event.identity;
  if (!identity || typeof identity !== 'object' || Array.isArray(identity)) return null;
  const sub = identity.sub;
  if (typeof sub !== 'string' || !SUB.test(sub)) return null;
  if (typeof event.method !== 'string' || !METHODS.has(event.method)) return null;
  if (typeof event.at !== 'string') return null;
  const atMs = Date.parse(event.at);
  if (!Number.isFinite(atMs)) return null;
  const deviceId = typeof event.deviceId === 'string' && DEVICE_ID.test(event.deviceId) ? event.deviceId : null;
  const decision = typeof event.decision === 'string' && DECISIONS.has(event.decision) ? event.decision : null;
  return Object.freeze({ sub, deviceId, method: event.method, decision, network: networkOf(event), atMs });
}

// 가상 사건 배열 → 필요한 값만 담은 사건 배열(시각순). 원본 사건 객체는 바꾸지 않습니다.
export function readDetectionEvents(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');
  const list = [];
  for (const event of events.slice(0, MAX_EVENTS)) {
    const item = readOne(event);
    if (item) list.push(item);
  }
  list.sort((a, b) => a.atMs - b.atMs);
  return Object.freeze(list);
}

// 9단계 제작 2 · 탐지 규칙 하나: doppelganger_burst
// 같은 가명 사용자(sub)의 GET 이 어느 10분 구간에서든 120건을 넘고(갑작스러운 다량 조회),
// 그 구간에 평소와 다른 네트워크(network 가 'usual' 이 아님)에서 온 조회가 함께 있을 때만 의심으로 표시합니다.
// - 다량 조회만 있고 네트워크가 평소대로면 정상으로 둡니다. 네트워크만 다르고 조회가 적어도 정상으로 둡니다.
// - 지역(region)은 이 규칙에 쓰지 않습니다(지역 하나만으로 확정하지 않음).
// - 다른 사용자의 사건을 합산하지 않고, 10분 밖의 사건을 같은 묶음으로 세지 않습니다.
// - 사건에 네트워크 정보가 전혀 없는 경우(docs/DETECT_EVENTS.md 의 로컬 연습 형식)는 그 문서의 계약대로
//   다량 조회만으로 판단합니다. 네트워크를 '평소'나 '다름'으로 임의로 채우지 않습니다.
export const DETECT_RULE_ID = 'doppelganger_burst';
const WINDOW_MS = 10 * 60 * 1000;
const BURST_LIMIT = 120; // 정확히 120건은 의심 아님, 121건부터

const isUnusual = item => item.network !== null && item.network !== 'usual';

// 의심 표시 목록: [{ sub, deviceId, reasons }] (메모 내용·토큰·실명 없음)
export function findSuspicious(events) {
  const bySub = new Map();
  for (const item of readDetectionEvents(events)) {
    if (item.method !== 'GET') continue;
    if (!bySub.has(item.sub)) bySub.set(item.sub, []);
    bySub.get(item.sub).push(item);
  }
  const marks = [];
  for (const [sub, reads] of bySub) {
    const hasNetworkInfo = reads.some(item => item.network !== null);
    let start = 0;
    let unusualInWindow = 0;
    let hit = null;
    for (let end = 0; end < reads.length; end += 1) {
      if (isUnusual(reads[end])) unusualInWindow += 1;
      while (reads[end].atMs - reads[start].atMs >= WINDOW_MS) {
        if (isUnusual(reads[start])) unusualInWindow -= 1;
        start += 1;
      }
      const burst = end - start + 1 > BURST_LIMIT;
      if (burst && (!hasNetworkInfo || unusualInWindow > 0)) { hit = { start, end }; break; }
    }
    if (!hit) continue;
    // 대상 기기 후보: 그 구간에서 평소와 다른 네트워크로 가장 많이 조회한 기기(네트워크 정보가 없으면 가장 많이 조회한 기기)
    const counts = new Map();
    for (let i = hit.start; i <= hit.end; i += 1) {
      const item = reads[i];
      if (item.deviceId === null || (hasNetworkInfo && !isUnusual(item))) continue;
      counts.set(item.deviceId, (counts.get(item.deviceId) ?? 0) + 1);
    }
    let deviceId = null;
    let best = 0;
    for (const [id, count] of counts) if (count > best) { deviceId = id; best = count; }
    marks.push(Object.freeze({ sub, deviceId,
      reasons: Object.freeze(hasNetworkInfo ? ['burst_read', 'new_network'] : ['burst_read']) }));
  }
  return Object.freeze(marks);
}

// 9단계 제작 3 · 회수 제안(propose_revocation)
// 탐지 결과는 판정기(decide)의 접속 허용/거부 응답과 별도입니다. 판정기 응답 다섯 항목은 바꾸지 않습니다.
// 여기서는 제안만 하고, 회수 API를 만들거나 기기 권한을 바꾸지 않습니다. 실제 회수와 경과 시간은 심판이 확인합니다.
// 이유 코드는 계약(docs/DETECT_EVENTS.md)의 'burst_read' 하나만 씁니다.
const REASON_CODE = 'burst_read';

// 별도 결과(자세히): 대상은 의심 표시된 첫 사용자의 확인된 가상 기기 한 개로 한정합니다.
//   { action: 'propose_revocation', reasonCode, ruleId, subject, deviceId, reasons } 또는 { action: 'observe' }
// 사건에 기기 ID가 없으면(로컬 연습 형식) deviceId 는 null 로 두고 임의의 기기를 만들지 않습니다.
export function revocationProposal(events) {
  const [mark] = findSuspicious(events);
  if (!mark) return Object.freeze({ action: 'observe' });
  return Object.freeze({ action: 'propose_revocation', reasonCode: REASON_CODE, ruleId: DETECT_RULE_ID,
    subject: mark.sub, deviceId: mark.deviceId, reasons: mark.reasons });
}

// 엔진·연습 명령이 부르는 결과: 계약의 세 항목만 돌려줍니다.
//   의심 → { action: 'propose_revocation', reasonCode: 'burst_read', subject }
//   정상 → { action: 'observe' }
export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');
  const proposal = revocationProposal(events);
  if (proposal.action !== 'propose_revocation') return { action: 'observe' };
  return { action: 'propose_revocation', reasonCode: proposal.reasonCode, subject: proposal.subject };
}
