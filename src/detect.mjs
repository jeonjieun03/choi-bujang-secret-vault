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
// 메모 내용(body·title·content)·토큰(authorization·token)·실명(name·email) 등 그 밖의 값은
// 읽지도, 저장하지도, 출력하지도 않습니다. 형식이 틀린 사건은 임의의 값으로 채우지 않고 건너뜁니다.

const SUB = /^[A-Za-z0-9_-]{1,128}$/u;
const DEVICE_ID = /^[0-9a-f]{16}$/u;
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
const DECISIONS = new Set(['allow', 'deny', 'step_up']);
const MAX_EVENTS = 100_000;

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
  return Object.freeze({ sub, deviceId, method: event.method, decision, atMs });
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

export function detect(events) {
  readDetectionEvents(events);
  // 탐지 규칙은 다음 제작에서 추가합니다. 지금은 어떤 접속도 회수하지 않습니다.
  return { action: 'observe' };
}
