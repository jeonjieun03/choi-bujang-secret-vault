// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계부터 규칙을 하나씩 추가합니다. 이 기본 응답은 모든 요청을 거부합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
//
// 6단계 device_registered: 엔진이 확인한 요청의 deviceRegistered 가 true 일 때만
// 내 자료실(notes) 읽기(GET)를 허용합니다. 미등록이거나 값이 없으면 device_not_registered 로 거부합니다.
// 계약(docs/DECIDER_REQUEST.md)에 있는 값(subjectId, deviceRegistered, service, method, route)만 씁니다.
export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered']);

const NOTES_READ_ROUTES = new Set(['GET /notes', 'GET /notes/:id']);

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

  // 등록 기기 + 엔진이 확인한 로그인 주체 + 내 자료실 읽기 → 허용
  if (typeof request.subjectId === 'string' && request.subjectId && isNotesRead(request)) {
    return { ...base, decision: 'allow', reasonCode: 'approved', ruleIds: ['device_registered'] };
  }

  // 그 밖의 요청은 시작 틀의 기본 응답대로 거부
  return { ...base, decision: 'deny', reasonCode: 'starter_not_ready', ruleIds: [RULE_IDS[0]] };
}
