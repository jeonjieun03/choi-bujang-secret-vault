import { createRequire } from 'node:module';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { resourceId } from '../src/resources.mjs';
import { ownerKeyOf } from '../src/owner-key.mjs';
import { logAuthReject } from '../src/auth-log.mjs';
import { requireApprovedDevice } from '../src/device-guard.mjs';
import { traceRequest } from '../src/request-trace.mjs';

const require = createRequire(import.meta.url);
const config = require('../aleph.config.json');

// 8단계: 강사 공지(구역 instructor_notices). 메모(own_notes)와 다른 자원 ID를 씁니다.
//   GET /api/notices        공지 목록 [{id,title,body}]   자원 ID notices
//   GET /api/notices/:id    공지 한 건 {id,title,body}    자원 ID notice:<id>
//   PUT /api/notices/:id    {title,body} → {id,title,body}  강사만(403 INSTRUCTOR_ONLY)
// 강사 공지는 학생에게 다른 구역입니다. 공지 읽기·수정 모두 DB에 저장된 강사 명단(vault_instructors)에
// 검증된 사용자 ID가 있을 때만 허용하고, 학생은 403 INSTRUCTOR_ONLY 입니다. 화면 메뉴나 요청 본문의 role·is_instructor 값은 믿지 않습니다.
// SUPABASE_SECRET_KEY는 서버 전용이며 브라우저 파일·응답·로그에 넣지 않습니다.

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const COLUMNS = 'notice_id, title, content';
const TITLE_MAX = 120;
const BODY_MAX = 2000;

function readJson(request) {
  const raw = request.body;
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) return raw;
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
    } catch { return null; }
  }
  return null;
}
const validText = (v, max) => typeof v === 'string' && v.trim().length > 0 && v.length <= max;

let verifier = null;
function getVerifier(secretKey) {
  verifier ??= createLoginVerifier({ config, supabaseSecretKey: secretKey });
  return verifier;
}

const toNotice = row => ({ id: row.notice_id, title: row.title, body: row.content });
const fail = (response, status, error) => response.status(status).json({ error });

function noticeIdFrom(request) {
  const fromQuery = request.query?.id;
  if (typeof fromQuery === 'string' && fromQuery) return fromQuery;
  const path = (request.url ?? '').split('?')[0];
  const match = /^\/api\/notices\/([^/]+)\/?$/u.exec(path);
  return match ? decodeURIComponent(match[1]) : null;
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  traceRequest('notices', request, response); // 12단계: 요청 ID·상태 코드 추적 기록(관측만)

  const id = noticeIdFrom(request);
  const method = request.method ?? 'GET';
  const allowed = id ? ['GET', 'PUT'] : ['GET'];
  if (!allowed.includes(method)) {
    response.setHeader('Allow', allowed.join(', '));
    return fail(response, 405, 'METHOD_NOT_ALLOWED');
  }

  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) {
    console.error('notices: 서버 환경변수가 설정되지 않았습니다.');
    return fail(response, 500, 'SERVER_NOT_CONFIGURED');
  }

  let verify;
  try {
    verify = getVerifier(secretKey);
  } catch (error) {
    console.error('notices: 로그인 검사 설정이 올바르지 않습니다.', error?.message ?? 'unknown');
    return fail(response, 500, 'LOGIN_NOT_CONFIGURED');
  }
  const authorization = request.headers?.authorization;
  if (!authorization) {
    logAuthReject('notices', authorization);
    response.setHeader('WWW-Authenticate', 'Bearer');
    return fail(response, 401, 'LOGIN_REQUIRED');
  }
  const identity = await verify(authorization);
  if (!identity?.userId) {
    logAuthReject('notices', authorization);
    response.setHeader('WWW-Authenticate', 'Bearer error="invalid_token"');
    return fail(response, 401, 'INVALID_LOGIN');
  }

  if (id !== null && !UUID.test(id)) return fail(response, 400, 'INVALID_ID');
  response.setHeader('X-Resource-Id', resourceId('notice', id));

  const client = createClient(url, secretKey, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  });
  // 11단계: 학생 로그인은 서버가 승인한 기기 세션이 있을 때만 자료를 다룹니다.
  //   심판 토큰(kind: 'judge')의 기기는 ALEPH SDP 엔진과 판정기(deviceRegistered·device_registered 규칙)가 확인하므로
  //   브라우저 기기 세션 검사를 건너뜁니다. 주인 검사(A·B 구별)는 그대로 합니다.
  if (identity.kind === 'student') {
    const deviceCheck = await requireApprovedDevice({ client, request, ownerId: ownerKeyOf(identity) });
    if (!deviceCheck.ok) return fail(response, deviceCheck.status, deviceCheck.error);
  }
  const db = client.from('vault_notices');

  // 공지 읽기·수정 공통: 저장된 강사 명단과 검증된 사용자 ID를 대조합니다.
  const { data: instructor, error: roleError } = await client.from('vault_instructors')
    .select('user_id').eq('user_id', ownerKeyOf(identity)).maybeSingle();
  if (roleError) {
    console.error('notices: 강사 명단 확인 실패', roleError.code ?? 'unknown');
    return fail(response, 502, 'NOTICES_UNAVAILABLE');
  }
  if (!instructor) {
    console.info(`notices: deny ${method === 'PUT' ? 'update' : 'read'} reason=instructor_only`);
    return fail(response, 403, 'INSTRUCTOR_ONLY');
  }

  // 공지 수정
  if (method === 'PUT') {
    const input = readJson(request);
    if (!input) return fail(response, 400, 'INVALID_JSON');
    if (!validText(input.title, TITLE_MAX) || !validText(input.body, BODY_MAX)) {
      return fail(response, 400, 'INVALID_NOTICE');
    }
    const { data, error } = await db
      .update({ title: input.title, content: input.body, updated_at: new Date().toISOString() })
      .eq('notice_id', id).select(COLUMNS).maybeSingle();
    if (error) {
      console.error('notices: 수정 실패', error.code ?? 'unknown');
      return fail(response, 502, 'NOTICES_UNAVAILABLE');
    }
    if (!data) return fail(response, 404, 'NOT_FOUND');
    return response.status(200).json(toNotice(data));
  }

  if (id === null) {
    const { data, error } = await db.select(COLUMNS).order('created_at', { ascending: false });
    if (error) {
      console.error('notices: 목록 조회 실패', error.code ?? 'unknown');
      return fail(response, 502, 'NOTICES_UNAVAILABLE');
    }
    return response.status(200).json((data ?? []).map(toNotice));
  }

  const { data, error } = await db.select(COLUMNS).eq('notice_id', id).maybeSingle();
  if (error) {
    console.error('notices: 조회 실패', error.code ?? 'unknown');
    return fail(response, 502, 'NOTICES_UNAVAILABLE');
  }
  if (!data) return fail(response, 404, 'NOT_FOUND');
  return response.status(200).json(toNotice(data));
}
