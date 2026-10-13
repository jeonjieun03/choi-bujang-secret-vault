import { createRequire } from 'node:module';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { resourceId } from '../src/resources.mjs';
import { ownerKeyOf } from '../src/owner-key.mjs';
import { logAuthReject } from '../src/auth-log.mjs';
import { noteContentSha256 } from '../src/note-hash.mjs';
import { sealMatches } from '../src/backup-seal.mjs';

const require = createRequire(import.meta.url);
const config = require('../aleph.config.json');

// 10단계 제작 3: 비공개 가상 메모 사본에서 지정한 한 건만 복원합니다.
//   POST /api/notes/:id/restore  {"preview":true}            → 미리 보기: 검증 결과·사본 버전·바뀔 항목만, 아무것도 쓰지 않음
//   POST /api/notes/:id/restore  {"expectBackupSha256":"…"}  → 미리 본 사본과 같을 때만 실행(다르면 409로 멈춤)
//   POST /api/notes/:id/restore  (본문 없음)                   → 검증 후 실행 → 200 {id,title,body,restored:{…}}
// - 실행 뒤 다시 읽은 대조가 실패하면 쓴 내용을 복원 전 상태로 되돌리고 502 로 끝냅니다(검증 실패한 복원을 남기지 않음).
// - 로그인한 사용자(검증된 토큰의 주인 키)의 사본만 복원합니다. 남의 메모·사본 없음은 404(존재 여부를 알리지 않음).
// - 사본의 ID·소유자·내용 해시를 대조하고, 해시가 맞지 않는 사본은 409 BACKUP_INVALID 로 복원하지 않습니다.
// - 사본을 다시 읽어 서버 전용 키로 만든 봉인(vault_notes_backup_seal)과 대조합니다. 봉인이 없거나 맞지 않으면
//   409 BACKUP_UNVERIFIED 로 멈추고 아무것도 쓰지 않습니다(DB의 사본이 바뀌었어도 봉인은 위조할 수 없음).
// - 쓰기 전에 사본 버전(사본을 뜬 시각)과 바뀔 항목을 정하고, 응답과 감사 기록에 함께 남깁니다.
// - 지정한 한 건(note_id + owner_id)만 고치거나 다시 넣고, 다른 메모는 건드리지 않습니다.
// - 복원 뒤 다시 읽어 ID·소유자·해시가 사본과 같은지 확인하고, 결과를 감사 기록(vault_restore_audit)에 한 줄 추가합니다.
//   감사 기록과 사본은 지우거나 고치지 않습니다(DB 트리거가 막음). 감사 기록에는 메모 본문을 남기지 않습니다.
// SUPABASE_SECRET_KEY는 서버 전용이며 브라우저 파일·응답·로그에 넣지 않습니다.

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const fail = (response, status, error) => response.status(status).json({ error });
const HEX64 = /^[0-9a-f]{64}$/u;

function readBody(request) {
  const raw = request.body;
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) return raw;
  if (typeof raw === 'string' && raw.trim()) {
    try { const parsed = JSON.parse(raw); return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null; }
    catch { return null; }
  }
  return {};
}

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
  const input = readBody(request);
  if (!input) return fail(response, 400, 'INVALID_JSON');
  const previewOnly = input.preview === true;
  const expected = input.expectBackupSha256;
  if (expected !== undefined && (typeof expected !== 'string' || !HEX64.test(expected))) return fail(response, 400, 'INVALID_EXPECTATION');

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
    .select('note_id, owner_id, title, content, content_sha256, backed_up_at')
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

  // 2-1) 봉인 대조: 사본을 다시 읽어 봉인과 비교. 없거나 다르면 멈춤(복원하지 않음)
  const { data: sealRow, error: sealError } = await client.from('vault_notes_backup_seal')
    .select('note_id, owner_id, seal').eq('note_id', id).eq('owner_id', ownerId).maybeSingle();
  if (sealError) {
    console.error('restore: 봉인 조회 실패', sealError.code ?? 'unknown');
    return fail(response, 502, 'RESTORE_UNAVAILABLE');
  }
  const { data: reread, error: rereadError } = await client.from('vault_notes_backup')
    .select('note_id, owner_id, title, content, content_sha256')
    .eq('note_id', id).eq('owner_id', ownerId).maybeSingle();
  let verified = false;
  try {
    verified = Boolean(sealRow && reread && !rereadError
      && noteContentSha256(reread.title, reread.content) === reread.content_sha256
      && reread.content_sha256 === backupSha
      && sealMatches(secretKey, { noteId: reread.note_id, ownerId: reread.owner_id, contentSha256: reread.content_sha256 }, sealRow.seal));
  } catch { verified = false; }
  if (!verified) {
    await audit({ result: sealRow ? 'backup_seal_mismatch' : 'backup_unsealed', backup_sha256: backup.content_sha256 });
    console.info(`restore: stop reason=${sealRow ? 'backup_seal_mismatch' : 'backup_unsealed'}`);
    return fail(response, 409, 'BACKUP_UNVERIFIED');
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
  // 쓰기 전에 정한 복원 계획: 사본 버전과 바뀔 항목(본문 값은 응답·기록에 넣지 않고 항목 이름만)
  const backupVersion = backup.backed_up_at ?? null;
  const changes = !current ? ['note'] : [
    ...(current.title !== backup.title ? ['title'] : []), ...(current.content !== backup.content ? ['body'] : [])];
  const plan = { previous, backupVersion, changes, backupVerified: true, backupSha256: backupSha };
  // 되돌리기용: 복원 전 상태를 따로 복사해 둠
  const before = current ? Object.freeze({ title: String(current.title), content: String(current.content) }) : null;

  // 3-1) 미리 보기: 검증된 사본의 버전과 바뀔 항목만 보여 주고 아무것도 쓰지 않음
  if (previewOnly) {
    await audit({ result: 'previewed', previous_state: previous, backup_sha256: backupSha });
    return response.status(200).json({ id, preview: true, restored: null, plan });
  }
  // 3-2) 미리 본 사본과 지금 검증한 사본이 다르면 멈춤
  if (expected !== undefined && expected !== backupSha) {
    await audit({ result: 'expectation_mismatch', previous_state: previous, backup_sha256: backupSha });
    return fail(response, 409, 'BACKUP_CHANGED_SINCE_PREVIEW');
  }

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
  const restoredSha = after ? noteContentSha256(after.title, after.content) : null;
  const matches = { id: after?.note_id === backup.note_id, owner: after?.owner_id === backup.owner_id,
    contentSha256: restoredSha === backup.content_sha256 };
  const ok = !afterError && Boolean(after) && matches.id && matches.owner && matches.contentSha256;
  if (!ok) {
    // 검증 실패한 복원은 남기지 않음: 쓴 내용을 복원 전 상태로 되돌림
    let rolledBack = previous === 'unchanged';
    if (previous === 'tampered') {
      const { error } = await notes.update({ title: before.title, content: before.content, updated_at: new Date().toISOString() })
        .eq('note_id', id).eq('owner_id', ownerId);
      rolledBack = !error;
    } else if (previous === 'deleted') {
      const { error } = await notes.delete().eq('note_id', id).eq('owner_id', ownerId);
      rolledBack = !error;
    }
    await audit({ result: rolledBack ? 'verify_failed_rolled_back' : 'verify_failed_rollback_failed', previous_state: previous,
      backup_sha256: backupSha, restored_sha256: restoredSha });
    console.error(`restore: verify_failed rolled_back=${rolledBack} previous=${previous}`);
    return fail(response, 502, 'RESTORE_VERIFY_FAILED');
  }
  await audit({ result: 'restored', previous_state: previous, backup_sha256: backupSha, restored_sha256: restoredSha });
  console.info(`restore: restored previous=${previous}`);
  return response.status(200).json({ id: after.note_id, title: after.title, body: after.content,
    restored: { previous, backupVersion, changes, backupVerified: true, sha256: restoredSha, matches } });
}
