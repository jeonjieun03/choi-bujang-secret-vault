import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';

const require = createRequire(import.meta.url);
const config = require('../aleph.config.json');

// 3단계: 로그인한 사용자의 가상 메모 목록·추가·조회·수정·삭제.
//   GET    /api/notes        로그인 사용자의 메모 배열 [{id,title,body}]
//   POST   /api/notes        {id?,title,body} → 201 {id}  (id 없으면 서버가 UUID 생성)
//   GET    /api/notes/:id    {id,title,body} 또는 404
//   PUT    /api/notes/:id    {title,body} → {id,title,body} 또는 404
//   DELETE /api/notes/:id    204 또는 404
// 로그인 여부와 사용자 ID는 시작 틀의 src/verify-login.mjs가 검증한 토큰에서만 얻습니다.
// 요청 본문·주소에 들어온 userId·role·owner_id는 읽지 않습니다.
// SUPABASE_SECRET_KEY는 서버 전용이며 브라우저 파일·응답·로그에 넣지 않습니다.
// 알려진 허점(4단계에서 고침): 한 건 조회·수정·삭제는 아직 소유자를 검사하지 않습니다.

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const TITLE_MAX = 120;
const BODY_MAX = 2000;
const COLUMNS = 'note_id, title, content';

let verifier = null;
function getVerifier(secretKey) {
  verifier ??= createLoginVerifier({ config, supabaseSecretKey: secretKey });
  return verifier;
}

const toNote = row => ({ id: row.note_id, title: row.title, body: row.content });

function noteIdFrom(request) {
  const fromQuery = request.query?.id;
  if (typeof fromQuery === 'string' && fromQuery) return fromQuery;
  const path = (request.url ?? '').split('?')[0];
  const match = /^\/api\/notes\/([^/]+)\/?$/u.exec(path);
  return match ? decodeURIComponent(match[1]) : null;
}

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

function validText(value, max) {
  return typeof value === 'string' && value.trim().length > 0 && value.length <= max;
}

function fail(response, status, error) {
  return response.status(status).json({ error });
}

function dbError(response, error, action) {
  // 오류 코드만 남기고 키·토큰·메모 내용은 기록하지 않습니다.
  console.error(`notes: ${action} 실패`, error?.code ?? 'unknown');
  return fail(response, 502, 'NOTES_UNAVAILABLE');
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');

  const id = noteIdFrom(request);
  const method = request.method ?? 'GET';
  const allowed = id ? ['GET', 'PUT', 'DELETE'] : ['GET', 'POST'];
  if (!allowed.includes(method)) {
    response.setHeader('Allow', allowed.join(', '));
    return fail(response, 405, 'METHOD_NOT_ALLOWED');
  }

  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) {
    console.error('notes: 서버 환경변수가 설정되지 않았습니다.');
    return fail(response, 500, 'SERVER_NOT_CONFIGURED');
  }

  let verify;
  try {
    verify = getVerifier(secretKey);
  } catch (error) {
    console.error('notes: 로그인 검사 설정이 올바르지 않습니다.', error?.message ?? 'unknown');
    return fail(response, 500, 'LOGIN_NOT_CONFIGURED');
  }

  const authorization = request.headers?.authorization;
  if (!authorization) {
    response.setHeader('WWW-Authenticate', 'Bearer');
    return fail(response, 401, 'LOGIN_REQUIRED');
  }
  const identity = await verify(authorization);
  if (!identity?.userId) {
    response.setHeader('WWW-Authenticate', 'Bearer error="invalid_token"');
    return fail(response, 401, 'INVALID_LOGIN');
  }
  const userId = identity.userId; // 서버가 검증한 토큰의 사용자 ID만 사용

  if (id !== null && !UUID.test(id)) return fail(response, 400, 'INVALID_ID');

  const db = createClient(url, secretKey, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  }).from('vault_notes');

  // 목록: 로그인 사용자의 메모만
  if (!id && method === 'GET') {
    const { data, error } = await db.select(COLUMNS).eq('owner_id', userId)
      .order('created_at', { ascending: true }).order('id', { ascending: true });
    if (error) return dbError(response, error, '목록 조회');
    return response.status(200).json((data ?? []).map(toNote));
  }

  // 추가: owner_id는 검증된 사용자 ID로 저장
  if (!id && method === 'POST') {
    const input = readJson(request);
    if (!input) return fail(response, 400, 'INVALID_JSON');
    if (!validText(input.title, TITLE_MAX) || !validText(input.body, BODY_MAX)) {
      return fail(response, 400, 'INVALID_NOTE');
    }
    let newId = input.id;
    if (newId === undefined || newId === null || newId === '') newId = randomUUID();
    else if (typeof newId !== 'string' || !UUID.test(newId)) return fail(response, 400, 'INVALID_ID');
    newId = newId.toLowerCase();
    const { error } = await db.insert({
      note_id: newId, owner_id: userId, title: input.title, content: input.body,
    });
    if (error?.code === '23505') return fail(response, 409, 'ID_ALREADY_EXISTS');
    if (error) return dbError(response, error, '추가');
    return response.status(201).json({ id: newId });
  }

  // 한 건 조회 (소유자 검사 없음 — 4단계에서 고칠 허점)
  if (method === 'GET') {
    const { data, error } = await db.select(COLUMNS).eq('note_id', id).maybeSingle();
    if (error) return dbError(response, error, '조회');
    if (!data) return fail(response, 404, 'NOT_FOUND');
    return response.status(200).json(toNote(data));
  }

  // 수정 (소유자 검사 없음 — 4단계에서 고칠 허점)
  if (method === 'PUT') {
    const input = readJson(request);
    if (!input) return fail(response, 400, 'INVALID_JSON');
    if (!validText(input.title, TITLE_MAX) || !validText(input.body, BODY_MAX)) {
      return fail(response, 400, 'INVALID_NOTE');
    }
    const { data, error } = await db
      .update({ title: input.title, content: input.body, updated_at: new Date().toISOString() })
      .eq('note_id', id).select(COLUMNS).maybeSingle();
    if (error) return dbError(response, error, '수정');
    if (!data) return fail(response, 404, 'NOT_FOUND');
    return response.status(200).json(toNote(data));
  }

  // 삭제 (소유자 검사 없음 — 4단계에서 고칠 허점)
  const { data, error } = await db.delete().eq('note_id', id).select('note_id');
  if (error) return dbError(response, error, '삭제');
  if (!data?.length) return fail(response, 404, 'NOT_FOUND');
  return response.status(204).end();
}
