// 8단계: 자료실 자원 ID
// 메모와 강사 공지를 서로 다른 자원(구역)으로 구별합니다. 서버는 요청마다 이 ID로 무엇을 다루는지 압니다.
//   메모 목록  notes          메모 한 건  note:<uuid>     구역 own_notes(본인 메모)
//   공지 목록  notices        공지 한 건  notice:<uuid>   구역 instructor_notices(강사 공지)
// 자원 ID는 경로의 자료 ID(UUID)만으로 만들고, 쿼리로 기능을 고르지 않습니다.

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

export const RESOURCE_KINDS = Object.freeze({
  note: Object.freeze({ collection: 'notes', zone: 'own_notes', apiPath: '/api/notes' }),
  notice: Object.freeze({ collection: 'notices', zone: 'instructor_notices', apiPath: '/api/notices' }),
});

// kind 와 자료 ID 로 자원 ID 를 만듭니다. ID 가 없으면 목록 자원입니다.
export function resourceId(kind, id = null) {
  const def = RESOURCE_KINDS[kind];
  if (!def) throw new TypeError('unknown_resource_kind');
  if (id === null || id === undefined) return def.collection;
  if (typeof id !== 'string' || !UUID.test(id)) throw new TypeError('invalid_resource_id');
  return `${kind}:${id.toLowerCase()}`;
}

// 자원 ID 를 다시 풀어 kind·id·구역을 돌려줍니다. 모르는 모양이면 null.
export function parseResourceId(value) {
  if (typeof value !== 'string') return null;
  for (const [kind, def] of Object.entries(RESOURCE_KINDS)) {
    if (value === def.collection) return { kind, id: null, zone: def.zone };
    const prefix = `${kind}:`;
    if (value.startsWith(prefix) && UUID.test(value.slice(prefix.length))) {
      return { kind, id: value.slice(prefix.length).toLowerCase(), zone: def.zone };
    }
  }
  return null;
}
