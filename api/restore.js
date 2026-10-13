import { createRequire } from 'node:module';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { resourceId } from '../src/resources.mjs';
import { ownerKeyOf } from '../src/owner-key.mjs';
import { logAuthReject } from '../src/auth-log.mjs';
import { noteContentSha256 } from '../src/note-hash.mjs';

const require = createRequire(import.meta.url);
const config = require('../aleph.config.json');

// 10단계 제작 3: 비공개 가상 메모 사본에서 지정한 한 건만 복원합니다.
//   POST /api/notes/:id/restore   (본문 없음) → 200 {id,title,body,restored:{previous,sha256,matches}}
// - 로그인한 사용자(검증된 토큰의 주인 키)의 사본만 복원합니다. 남의 메모·사본 없음은 404(존재 여부를 알리지 않음).
// - 사본의 ID·소유자·내용 해시를 대조하고, 해시가 맞지 않는 사본은 409 BACKUP_INVALID 로 복원하지 않습니다.
// - 지정한 한 건(note_id + owner_id)만 고치거나 다시 넣고, 다른 메모는 건드리지 않습니다.
// - 복원 뒤 다시 읽어 ID·소유자·해시가 사본과 같은지 확인하고, 결과를 감사 기록(vault_restore_audit)에 한 줄 추가합니다.
//   감사 기록과 사본은 지우거나 고치지 않습니다(DB 트리거가 막음). 감사 기록에는 메모 본문을 남기지 않습니다.
// SUPABASE_SECRET_KEY는 서버 전용이며 브라우저 파일·응답·로그에 넣지 않습니다.

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const fail = (response, status, error) => response.status(status).json({ error });

let verifier = null;
function getVerifier(secretKey) {
  verifier ??= createLoginVerifier({ config, supabaseSecretKey: secretKey });
  return verifier;
}

function noteIdFrom(request) {
  const fromQuery = request.query?.id;
  if (typeof fromQuery === 'string' && fromQuery) return fromQuery;
  const match = /^\/api\/notes\/([^/]+)\/restore\/?$/u.exec((request.url ?? '').split('?')[0]);
  return match ? decodeURIComponent(match[1]) : null;
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if ((request.method ?? 'GET') !== 'POST') {
    response.setHeader('Allow', 'POST');
    return fail(response, 405, 'METHOD_NOT_ALLOWED');
  }
  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) {
    console.error('restore: 서버 환경변수가 설정되지 않았습니다.');
    return fail(response, 500, 'SERVER_NOT_CONFIGURED');
  }
  let verify;
  try { verify = getVerifier(secretKey); } catch (error) {
    console.error('restore: 로그인 검사 설정이 올바르지 않습니다.', error?.message ?? 'unknown');
    return fail(response, 500, 'LOGIN_NOT_CONFIGURED');
  }
  const authorization = request.headers?.authorization;
  if (!authorization) {
    logAuthReject('restore', authorization);
    response.setHeader('WWW-Authenticate', 'Bearer');
    return fail(response, 401, 'LOGIN_REQUIRED');
  }
  const identity = await verify(authorization);
  if (!identity?.userId) {
    logAuthReject('restore', authorization);
    response.setHeader('WWW-Authenticate', 'Bearer error="invalid_token"');
    return fail(response, 401, 'INVALID_LOGIN');
  }
  const ownerId = ownerKeyOf(identity);
  const raw = noteIdFrom(request);
  if (!raw || !UUID.test(raw)) return fail(response, 400, 'INVALID_ID');
  const id = raw.toLowerCase();
  response.setHeader('X-Resource-Id', resourceId('note', id));

  const client = createClient(url, secretKey, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  });
  const audit = async row => {
    const { error } = await client.from('vault_restore_audit').insert({ note_id: id, owner_id: ownerId, action: 'restore_note', ...row });
    if (error) console.error('restore: 감사 기록 실패', error.code ?? 'unknown');
    return !error;
  };

  // 1) 사본: ID와 소유자가 모두 맞는 사본만
  const { data: backup, error: backupError } = await client.from('vault_notes_backup')
    .select('note_id, owner_id, title, content, content_sha256')
    .eq('note_id', id).eq('owner_id', ownerId).maybeSingle();
  if (backupError) {
    console.error('restore: 사본 조회 실패', backupError.code ?? 'unknown');
    return fail(response, 502, 'RESTORE_UNAVAILABLE');
  }
  if (!backup) {
    console.info('restore: deny reason=no_backup_or_not_owner');
    return fail(response, 404, 'NOT_FOUND');
  }
  // 2) 사본 검증: 내용 해시가 저장된 해시와 같아야 함
  const backupSha = noteContentSha256(backup.title, backup.content);
  if (backupSha !== backup.content_sha256) {
    await audit({ result: 'backup_invalid', backup_sha256: backup.content_sha256 });
    return fail(response, 409, 'BACKUP_INVALID');
  }

  // 3) 지금 상태: 같은 ID의 메모가 있으면 주인이 같아야 함
  const notes = client.from('vault_notes');
  const { data: current, error: currentError } = await notes.select('note_id, owner_id, title, content')
    .eq('note_id', id).maybeSingle();
  if (currentError) {
    console.error('restore: 현재 메모 조회 실패', currentError.code ?? 'unknown');
    return fail(response, 502, 'RESTORE_UNAVAILABLE');
  }
  if (current && current.owner_id !== ownerId) {
    await audit({ result: 'owner_mismatch', backup_sha256: backupSha });
    return fail(response, 404, 'NOT_FOUND');
  }
  const previous = !current ? 'deleted'
    : noteContentSha256(current.title, current.content) === backupSha ? 'unchanged' : 'tampered';

  // 4) 지정한 한 건만 복원
  if (previous === 'tampered') {
    const { error } = await notes.update({ title: backup.title, content: backup.content, updated_at: new Date().toISOString() })
      .eq('note_id', id).eq('owner_id', ownerId);
    if (error) { console.error('restore: 수정 복원 실패', error.code ?? 'unknown'); return fail(response, 502, 'RESTORE_UNAVAILABLE'); }
  } else if (previous === 'deleted') {
    const { error } = await notes.insert({ note_id: id, owner_id: ownerId, title: backup.title, content: backup.content });
    if (error) { console.error('restore: 삭제 복원 실패', error.code ?? 'unknown'); return fail(response, 502, 'RESTORE_UNAVAILABLE'); }
  }

  // 5) 다시 읽어 ID·소유자·내용 해시 대조
  const { data: after, error: afterError } = await notes.select('note_id, owner_id, title, content')
    .eq('note_id', id).eq('owner_id', ownerId).maybeSingle();
  if (afterError || !after) {
    await audit({ result: 'verify_failed', previous_state: previous, backup_sha256: backupSha });
    return fail(response, 502, 'RESTORE_UNAVAILABLE');
  }
  const restoredSha = noteContentSha256(after.title, after.content);
  const matches = { id: after.note_id === backup.note_id, owner: after.owner_id === backup.owner_id,
    contentSha256: restoredSha === backup.content_sha256 };
  const ok = matches.id && matches.owner && matches.contentSha256;
  await audit({ result: ok ? 'restored' : 'verify_failed', previous_state: previous,
    backup_sha256: backupSha, restored_sha256: restoredSha });
  console.info(`restore: ${ok ? 'restored' : 'verify_failed'} previous=${previous}`);
  if (!ok) return fail(response, 502, 'RESTORE_VERIFY_FAILED');
  return response.status(200).json({ id: after.note_id, title: after.title, body: after.content,
    restored: { previous, sha256: restoredSha, matches } });
}
