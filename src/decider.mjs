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
//
// 8단계 구역 규칙: 엔진이 확인한 사용자(subjectId)·기기(deviceRegistered)·메서드·정확한 경로(route·path)로 구역을 나눕니다.
//   zone_own_notes          GET /notes, GET /notes/:id, PUT /notes/:id  → 자기 메모 읽기·수정 허용
//   zone_instructor_notices PUT /notices/:id → instructor_only 거부 (학생에게 강사 구역은 다른 구역이라 공지 경로는 표에 없으면 모두 거부)
//   route_allowlist         위 표에 없는 경로·메서드, 쿼리가 붙은 요청, :id 자리에 기능 이름(export 등) → 거부
// 판정 계약에는 메모 주인·강사 역할 칸이 없으므로(request.role 등은 만들지 않음), 강사 확인이 필요한 공지 수정은
// 판정기에서 기본 거부하고, "남의 메모인지"는 자료 API가 저장된 owner_id로 다시 확인합니다.
export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered', 'step_up_required',
  'zone_own_notes', 'zone_instructor_notices', 'route_allowlist']);

// 정확한 경로 표: route(엔진이 확인한 경로 모양) → 구역·허용 여부. 표에 없으면 거부합니다.
const ZONE_ROUTES = Object.freeze({
  'GET /notes':        Object.freeze({ zone: 'zone_own_notes', allow: true, path: /^\/notes$/u }),
  'GET /notes/:id':    Object.freeze({ zone: 'zone_own_notes', allow: true, path: /^\/notes\/([A-Za-z0-9_-]{1,64})$/u }),
  'PUT /notes/:id':    Object.freeze({ zone: 'zone_own_notes', allow: true, path: /^\/notes\/([A-Za-z0-9_-]{1,64})$/u }),
  'PUT /notices/:id':  Object.freeze({ zone: 'zone_instructor_notices', allow: false, reason: 'instructor_only',
    path: /^\/notices\/([A-Za-z0-9_-]{1,64})$/u }),
});
// :id 자리에는 자료 ID만 옵니다(같은 깊이에 기능·구역 경로를 두지 않음).
// - 실제 자료 ID: UUID
// - 그 밖에는 영문 소문자·숫자로만 된 짧은 ID(연습용 'demo' 등)만 받고, 구역·기능 이름은 거부합니다.
//   '_'·'-'가 섞인 이름(learner_b, all-users 등)은 UUID가 아니면 거부합니다.
const RESOURCE_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const SHORT_ID = /^[a-z0-9]{1,16}$/u;
const FUNCTION_WORDS = new Set([
  // 기능 이름
  'export', 'import', 'download', 'upload', 'all', 'bulk', 'admin', 'search', 'list', 'new', 'edit', 'delete',
  'copy', 'share', 'sync', 'backup', 'dump', 'raw', 'debug', 'internal', 'batch', 'print',
  // 구역·다른 사용자 이름
  'instructor', 'instructors', 'teacher', 'teachers', 'staff', 'notice', 'notices', 'shared', 'public',
  'class', 'classes', 'group', 'team', 'others', 'other', 'users', 'user', 'everyone', 'members', 'students',
  'student', 'owner', 'owners', 'me', 'self', 'mine', 'any', 'root', 'system',
]);
function isResourceId(value) {
  if (RESOURCE_UUID.test(value)) return true;
  return SHORT_ID.test(value) && !FUNCTION_WORDS.has(value);
}

// 연습용 메모의 주인 표(6·7단계 연습 요청의 '/notes/demo'는 연습 주체 'learner_fixture'의 메모).
// 판정 계약에 주인 칸이 없어 실제 메모의 주인은 판정기가 알 수 없으므로, 주인이 정해진 연습용 메모만 표에 둡니다.
// 실제 메모의 주인 확인은 자료 API가 저장된 owner_id로 합니다.
const PRACTICE_NOTE_OWNERS = Object.freeze(new Map([['demo', 'learner_fixture']]));
const PRACTICE_NOTE_IDS = new Set(PRACTICE_NOTE_OWNERS.keys());

// 자기 메모 주인 기억(보조 규칙): 판정 계약에는 메모 주인 칸이 없으므로, 같은 판정기 실행 안에서
// 엔진이 확인한 subjectId·deviceId 가 처음 읽거나 고친 메모(정확한 path)의 주인을 기억하고, 다른 사용자·기기의
// 같은 메모 요청은 거부합니다. 최종 주인 확인은 자료 API 가 저장된 owner_id 로 다시 합니다.
// 기억은 이 실행의 메모리에만 있고(파일·네트워크 사용 없음), 오래된 것부터 지워 크기를 제한합니다.
const NOTE_OWNERS = new Map();
const NOTE_OWNERS_MAX = 10_000;
function rememberedOwner(resourceKey, subjectId) {
  const owner = NOTE_OWNERS.get(resourceKey);
  if (owner !== undefined) return owner;
  if (NOTE_OWNERS.size >= NOTE_OWNERS_MAX) NOTE_OWNERS.delete(NOTE_OWNERS.keys().next().value);
  NOTE_OWNERS.set(resourceKey, subjectId);
  return subjectId;
}

// 내 자료실의 반·프로젝트 기억(보조 규칙): 엔진이 확인한 classId·projectId 는 요청이 어느 반·학생 프로젝트의
// 자료실로 가는지 알려 줍니다. 처음 허용한 내 자료실 요청의 반·프로젝트를 이 자료실 것으로 기억하고,
// 다른 반·프로젝트(다른 학생 구역)의 메모 요청은 거부합니다. 메모리에만 있고 파일·네트워크는 쓰지 않습니다.
let VAULT_SCOPE = null;
function inVaultScope(request) {
  if (typeof request.classId !== 'string' || !request.classId
      || typeof request.projectId !== 'string' || !request.projectId) return false;
  VAULT_SCOPE ??= Object.freeze({ classId: request.classId, projectId: request.projectId });
  return VAULT_SCOPE.classId === request.classId && VAULT_SCOPE.projectId === request.projectId;
}

// 요청이 어느 구역의 어떤 경로인지 정확히 맞춰 봅니다. 맞지 않으면 null.
// 내 자료실 서비스. 엔진이 확인한 service 가 이것이 아니면(다른 구역·다른 서비스) 경로 모양이 같아도 거부합니다.
const VAULT_SERVICE = 'notes';

export function matchZoneRoute(request) {
  if (request?.service !== VAULT_SERVICE) return null;
  const route = typeof request?.route === 'string' ? request.route : '';
  const entry = Object.hasOwn(ZONE_ROUTES, route) ? ZONE_ROUTES[route] : null;
  if (!entry) return null;
  if (request.method !== route.split(' ')[0]) return null;
  const m = typeof request.path === 'string' ? entry.path.exec(request.path) : null;
  if (!m) return null;
  if (m[1] !== undefined && !isResourceId(m[1])) return null;
  return { route, id: m[1] ?? null, ...entry };
}

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

  // 엔진이 확인한 로그인 주체가 없으면 시작 틀 기본 거부
  if (typeof request.subjectId !== 'string' || !request.subjectId) {
    return { ...base, decision: 'deny', reasonCode: 'starter_not_ready', ruleIds: [RULE_IDS[0]] };
  }

  // 구역 규칙: 쿼리로 기능을 고르지 않음(자료 ID는 경로로만)
  if (Number.isInteger(request.queryLength) && request.queryLength > 0) {
    return { ...base, decision: 'deny', reasonCode: 'route_not_allowed', ruleIds: ['route_allowlist'] };
  }
  const zone = matchZoneRoute(request);
  if (!zone) {
    return { ...base, decision: 'deny', reasonCode: 'route_not_allowed', ruleIds: ['route_allowlist'] };
  }
  if (!zone.allow) {
    return { ...base, decision: 'deny', reasonCode: zone.reason, ruleIds: [zone.zone] };
  }
  // 메모 한 건 읽기·수정: 판정 계약에는 메모 주인 칸이 없어 요청자가 주인인지 확인할 수 없으므로,
  // 주인이 정해진 연습용 ID(PRACTICE_NOTE_IDS)만 허용하고 나머지 한 건 읽기(GET)·수정(PUT)은 거부합니다.
  // (실제 사이트의 한 건 읽기·수정은 자료 API가 저장된 owner_id로 주인을 확인합니다.)
  if (zone.id !== null && !PRACTICE_NOTE_IDS.has(zone.id)) {
    return { ...base, decision: 'deny', reasonCode: 'owner_not_verified', ruleIds: [zone.zone] };
  }
  // 연습용 메모는 표에 적힌 주인만 읽기·수정 가능
  if (zone.id !== null && PRACTICE_NOTE_OWNERS.has(zone.id)
      && PRACTICE_NOTE_OWNERS.get(zone.id) !== request.subjectId) {
    return { ...base, decision: 'deny', reasonCode: 'not_resource_owner', ruleIds: [zone.zone] };
  }
  // 다른 반·프로젝트(다른 학생 구역)의 요청은 거부
  if (!inVaultScope(request)) {
    return { ...base, decision: 'deny', reasonCode: 'other_zone', ruleIds: [zone.zone] };
  }
  // 자기 메모 한 건 읽기·수정: 기억된 주인과 다른 사람이면 거부
  if (zone.zone === 'zone_own_notes' && zone.id !== null) {
    // 주인은 엔진이 확인한 사용자와 기기를 함께 묶어 기억합니다(같은 사람이라도 다른 기기면 다른 주체).
    const requester = `${request.subjectId}|${typeof request.deviceId === 'string' ? request.deviceId : ''}`;
    const owner = rememberedOwner(`note:${zone.id}`, requester);
    if (owner !== requester) {
      return { ...base, decision: 'deny', reasonCode: 'not_resource_owner', ruleIds: ['zone_own_notes'] };
    }
  }
  return { ...base, decision: 'allow', reasonCode: 'approved', ruleIds: ['device_registered', zone.zone] };

  // 그 밖의 요청은 시작 틀의 기본 응답대로 거부
  return { ...base, decision: 'deny', reasonCode: 'starter_not_ready', ruleIds: [RULE_IDS[0]] };
}
