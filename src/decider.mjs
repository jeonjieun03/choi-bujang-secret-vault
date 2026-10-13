// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계부터 규칙을 하나씩 추가합니다. 이 기본 응답은 모든 요청을 거부합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
//
// 6단계 device_registered: 엔진이 확인한 요청의 deviceRegistered 가 true 일 때만
// 내 자료실(notes) 읽기(GET)를 허용합니다. 미등록이거나 값이 없으면 device_not_registered 로 거부합니다.
// 계약(docs/DECIDER_REQUEST.md)에 있는 값(subjectId, deviceRegistered, service, method, route)만 씁니다.
//
// 7단계 step_up_required: 심판이 보낸 가상 접속 사건(judge_fixture)에서 평소와 다른 신호가 2개 이상 겹치면
// (평소와 다른 시각 · 처음 보는 네트워크 · 갑자기 많은 자료 요청 · 평소와 다른 지역) 추가 본인 확인(step_up)을 요구합니다.
// 신호 하나(지역만, 시각만 등)로는 막지 않으며, 영구 차단(deny)하지 않습니다. 최근에 추가 확인을 마친 요청은 다시 판정해 허용합니다.
export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered', 'step_up_required']);

const NOTES_READ_ROUTES = new Set(['GET /notes', 'GET /notes/:id']);

// 7단계 입력 검사: 엔진이 넘긴 접속 정보(request.signals, request.recentEvents)의 출처를 구분합니다.
// - 'judge_fixture': 심판이 보낸 가상 접속 사건. 가상 사건 규칙에만 쓰고 실제 위치 증거로 취급하지 않습니다.
// - 'none': 실제 경로. 엔진이 접속 정보를 주지 않았다는 뜻이며 값은 모두 '모름(null)'입니다.
// - 'untrusted': 그 밖의 출처(브라우저·클라이언트 헤더 등). 값을 버리고 '모름(null)'으로 둡니다.
// 값이 없거나 형식이 틀리면 임의의 정상값('local', 'usual' 등)으로 채우지 않고 null 로 남깁니다.
// request.headers, request.geo 같은 계약 밖 값은 읽지 않습니다.
const SIGNAL_KEYS = 'hour,network,region,source';
const TEXT_VALUE = /^[a-z][a-z0-9_-]{0,31}$/u;
const EVENT_KIND = /^[a-z][a-z0-9_]{0,47}$/u;
const MAX_EVENTS = 12;

function textOrNull(value) {
  return typeof value === 'string' && TEXT_VALUE.test(value) && value !== 'unknown' ? value : null;
}

function eventsFrom(list) {
  if (!Array.isArray(list) || list.length > MAX_EVENTS) return [];
  const events = [];
  for (const item of list) {
    if (!item || typeof item !== 'object' || Array.isArray(item)
        || Object.keys(item).sort().join(',') !== 'ageSeconds,count,kind') continue;
    const { kind, ageSeconds, count } = item;
    if (typeof kind !== 'string' || !EVENT_KIND.test(kind)) continue;
    if (!Number.isInteger(ageSeconds) || ageSeconds < 0 || ageSeconds > 86_400) continue;
    if (!Number.isInteger(count) || count < 0 || count > 1_000_000) continue;
    events.push(Object.freeze({ kind, ageSeconds, count }));
  }
  return events;
}

export function readAccessContext(request) {
  const unknown = Object.freeze({ source: 'untrusted', region: null, network: null, hour: null, events: Object.freeze([]) });
  const signals = request?.signals;
  if (!signals || typeof signals !== 'object' || Array.isArray(signals)
      || Object.keys(signals).sort().join(',') !== SIGNAL_KEYS) {
    return unknown;
  }
  if (signals.source === 'none') {
    return Object.freeze({ source: 'none', region: null, network: null, hour: null, events: Object.freeze([]) });
  }
  if (signals.source !== 'judge_fixture') return unknown;
  const hour = Number.isInteger(signals.hour) && signals.hour >= 0 && signals.hour <= 23 ? signals.hour : null;
  return Object.freeze({
    source: 'judge_fixture',
    region: textOrNull(signals.region),
    network: textOrNull(signals.network),
    hour,
    events: Object.freeze(eventsFrom(request.recentEvents)),
  });
}

// 평소 범위: 접속 시각 07~22시, 네트워크 'usual', 지역 'local'. 값이 없으면(null) 이상으로도 정상으로도 세지 않습니다.
const USUAL_HOURS = Object.freeze({ from: 7, to: 22 });
const BULK_COUNT = 10;          // 최근 사건 한 건에 이만큼 이상이면 "갑자기 많은 요청"
const BULK_WINDOW_SECONDS = 600;
const STEP_UP_MIN_SIGNALS = 2;
const STEP_UP_FRESH_SECONDS = 300; // 이 시간 안에 추가 확인을 마쳤으면 다시 묻지 않음

// 가상 사건에서 평소와 다른 신호 이름을 모읍니다(사유 기록용). 응답 다섯 항목은 바꾸지 않습니다.
export function stepUpReasons(request) {
  const ctx = readAccessContext(request);
  if (ctx.source !== 'judge_fixture') return [];
  const reasons = [];
  if (ctx.hour !== null && (ctx.hour < USUAL_HOURS.from || ctx.hour > USUAL_HOURS.to)) reasons.push('unusual_hour');
  if (ctx.network !== null && ctx.network !== 'usual') reasons.push('new_network');
  if (ctx.events.some(e => e.count >= BULK_COUNT && e.ageSeconds <= BULK_WINDOW_SECONDS)) reasons.push('bulk_activity');
  if (ctx.region !== null && ctx.region !== 'local') reasons.push('unusual_region');
  return reasons;
}

function recentlyStepUpVerified(request) {
  const s = request?.stepUp;
  return Boolean(s) && typeof s === 'object' && s.verified === true
    && Number.isInteger(s.authAgeSeconds) && s.authAgeSeconds >= 0 && s.authAgeSeconds <= STEP_UP_FRESH_SECONDS;
}

function isNotesRead(request) {
  return request.service === 'notes' && request.method === 'GET'
    && (typeof request.route !== 'string' || NOTES_READ_ROUTES.has(request.route));
}

export async function decide(request) {
  const base = { schema: 'aleph.decision.v1', requestId: request?.requestId };

  // device_registered: 등록 기기가 아니면(false·값 없음·true 가 아닌 모든 값) 거부
  if (request?.deviceRegistered !== true) {
    return { ...base, decision: 'deny', reasonCode: 'device_not_registered', ruleIds: ['device_registered'] };
  }

  // step_up_required: 평소와 다른 신호가 겹치는 가상 사건은 최근 추가 확인 전까지 자료를 주지 않고 추가 확인 요구
  if (stepUpReasons(request).length >= STEP_UP_MIN_SIGNALS && !recentlyStepUpVerified(request)) {
    return { ...base, decision: 'step_up', reasonCode: 'step_up_required', ruleIds: ['step_up_required'] };
  }

  // 등록 기기 + 엔진이 확인한 로그인 주체 + 내 자료실 읽기 → 허용
  if (typeof request.subjectId === 'string' && request.subjectId && isNotesRead(request)) {
    return { ...base, decision: 'allow', reasonCode: 'approved', ruleIds: ['device_registered'] };
  }

  // 그 밖의 요청은 시작 틀의 기본 응답대로 거부
  return { ...base, decision: 'deny', reasonCode: 'starter_not_ready', ruleIds: [RULE_IDS[0]] };
}
