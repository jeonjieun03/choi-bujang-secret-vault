import { createRequire } from 'node:module';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { resourceId } from '../src/resources.mjs';
import { ownerKeyOf } from '../src/owner-key.mjs';
import { logAuthReject } from '../src/auth-log.mjs';
import { noteContentSha256 } from '../src/note-hash.mjs';
import { sealMatches } from '../src/backup-seal.mjs';
import { requireApprovedDevice } from '../src/device-guard.mjs';

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
  // 11단계: 학생 로그인은 서버가 승인한 기기 세션이 있을 때만 자료를 다룹니다.
  //   심판 토큰(kind: 'judge')의 기기는 ALEPH SDP 엔진과 판정기(deviceRegistered·device_registered 규칙)가 확인하므로
  //   브라우저 기기 세션 검사를 건너뜁니다. 주인 검사(A·B 구별)는 그대로 합니다.
  if (identity.kind === 'student') {
    const deviceCheck = await requireApprovedDevice({ client, request, ownerId });
    if (!deviceCheck.ok) return fail(response, deviceCheck.status, deviceCheck.error);
  }
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

  // 3) 나머지는 DB 함수 하나가 한 번에 합니다(supabase/step10_restore_function.sql):
  //    사본 다시 읽기 → 해시 재계산·대조 → 봉인 기록 확인 → (미리 보기면 여기서 끝) → 한 건 복원
  //    → 다시 읽어 ID·소유자·해시 대조, 다르면 함수 안의 변경 전체 취소. 멈춤·미리 보기·복원은 DB 감사 기록에 남습니다.
  const { data: result, error: rpcError } = await client.rpc('vault_restore_note', {
    p_note_id: id, p_owner_id: ownerId, p_preview: previewOnly, p_expect_sha256: expected ?? backupSha,
  });
  if (rpcError) {
    const failed = String(rpcError.message ?? '').includes('restore_verify_failed');
    if (failed) await audit({ result: 'verify_failed_rolled_back', backup_sha256: backupSha });
    console.error(`restore: ${failed ? 'verify_failed rolled_back=true' : 'rpc 실패'}`, rpcError.code ?? 'unknown');
    return fail(response, 502, failed ? 'RESTORE_VERIFY_FAILED' : 'RESTORE_UNAVAILABLE');
  }
  if (!result || typeof result !== 'object') return fail(response, 502, 'RESTORE_UNAVAILABLE');
  if (result.status === 'stopped') {
    console.info(`restore: stop reason=${result.reason}`);
    if (result.reason === 'backup_missing' || result.reason === 'not_found') return fail(response, 404, 'NOT_FOUND');
    if (result.reason === 'backup_changed') return fail(response, 409, 'BACKUP_CHANGED_SINCE_PREVIEW');
    return fail(response, 409, 'BACKUP_UNVERIFIED');
  }
  const plan = { previous: result.previous, backupVersion: result.backupVersion ?? null, changes: result.changes ?? [],
    backupVerified: result.backupVerified === true, backupSha256: result.backupSha256 };
  if (result.status === 'preview') return response.status(200).json({ id, preview: true, restored: null, plan });
  if (result.status !== 'restored') return fail(response, 502, 'RESTORE_UNAVAILABLE');

  const { data: after } = await client.from('vault_notes').select('note_id, title, content')
    .eq('note_id', id).eq('owner_id', ownerId).maybeSingle();
  console.info(`restore: restored previous=${result.previous}`);
  return response.status(200).json({ id, title: after?.title ?? backup.title, body: after?.content ?? backup.content,
    restored: { ...plan, sha256: result.restoredSha256, matches: result.matches } });
}
