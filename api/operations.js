import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { ownerKeyOf } from '../src/owner-key.mjs';
import { logAuthReject } from '../src/auth-log.mjs';
import { requireApprovedDevice } from '../src/device-guard.mjs';
import { RULE_IDS } from '../src/decider.mjs';
import { DETECT_RULE_ID } from '../src/detect.mjs';

const require = createRequire(import.meta.url);
const config = require('../aleph.config.json');

// 12단계 제작 1: 탈환 작전실 요약 (GET /api/operations, 로그인 + 학생은 승인된 기기 세션 필요)
//   판정기 규칙 — 배포된 src/decider.mjs 의 RULE_IDS (서버 코드에서 읽음)
//   탐지 사건   — 운영 엔진의 실제 사건 전달이 연결되지 않아 not_run (탐지 규칙 이름만 표시)
//   회수 상태   — 기기 명단 vault_devices 에서 이 사용자 기기의 승인·대기·회수 상태 (DB 실측)
//   복구 버전   — 정책 사본 vault_policy_backup, 정책 감사 vault_policy_audit, 이 사용자의 메모 복원 감사 vault_restore_audit (DB 실측)
// 각 구역의 status: 'confirmed' = 이번 요청에서 서버가 실제로 읽음, 'not_run' = 읽을 실제 기록이 없음/연결 안 됨,
// 'unavailable' = 읽기 실패. 수치(counts)는 응답에 담은 기록(records)을 서버가 직접 센 값입니다.
// 가림: 메모 본문·제목·사용자 ID·이메일·토큰·키는 응답과 로그에 넣지 않습니다. 기기·메모 ID는 앞 4자리만 보여 줍니다.
// 같은 수치를 요청 ID·확인 시각과 함께 서버 로그(operations: summary …)에 남겨 화면과 대조할 수 있게 합니다.

const LIMIT = 10;
const fail = (response, status, error) => response.status(status).json({ error });
const mask = value => (typeof value === 'string' && value.length >= 4 ? `${value.slice(0, 4)}…` : '…');
const countBy = (rows, key) => rows.reduce((acc, row) => { acc[row[key]] = (acc[row[key]] ?? 0) + 1; return acc; }, {});

let verifier = null;
function getVerifier(secretKey) {
  verifier ??= createLoginVerifier({ config, supabaseSecretKey: secretKey });
  return verifier;
}

async function readSection(name, read) {
  try { return await read(); } catch (error) {
    console.error(`operations: ${name} 읽기 실패`, error?.code ?? 'unknown');
    return { status: 'unavailable', records: [], counts: {} };
  }
}
function throwIf(error) { if (error) throw error; }

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if ((request.method ?? 'GET') !== 'GET') {
    response.setHeader('Allow', 'GET');
    return fail(response, 405, 'METHOD_NOT_ALLOWED');
  }
  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) { console.error('operations: 서버 환경변수가 설정되지 않았습니다.'); return fail(response, 500, 'SERVER_NOT_CONFIGURED'); }
  let verify;
  try { verify = getVerifier(secretKey); } catch (error) {
    console.error('operations: 로그인 검사 설정이 올바르지 않습니다.', error?.message ?? 'unknown');
    return fail(response, 500, 'LOGIN_NOT_CONFIGURED');
  }
  const authorization = request.headers?.authorization;
  const identity = authorization ? await verify(authorization) : null;
  if (!identity?.userId) {
    logAuthReject('operations', authorization);
    response.setHeader('WWW-Authenticate', 'Bearer');
    return fail(response, 401, authorization ? 'INVALID_LOGIN' : 'LOGIN_REQUIRED');
  }
  const ownerId = ownerKeyOf(identity);
  const client = createClient(url, secretKey, { auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false } });
  // 자료 API와 같은 기준: 학생 로그인은 서버가 승인한 기기 세션이 있어야 작전실을 엽니다.
  if (identity.kind === 'student') {
    const deviceCheck = await requireApprovedDevice({ client, request, ownerId });
    if (!deviceCheck.ok) return fail(response, deviceCheck.status, deviceCheck.error);
  }

  const requestId = randomUUID();
  const checkedAt = new Date().toISOString();

  const decider = { status: 'confirmed', source: 'server_code', records: RULE_IDS.map(ruleId => ({ ruleId })),
    counts: { rules: RULE_IDS.length } };

  const detection = { status: 'not_run', source: 'engine_events', records: [], counts: { events: 0 },
    ruleId: DETECT_RULE_ID, note: '운영 엔진의 실제 사건 전달이 연결되지 않아 실행하지 않았습니다(npm run detect:test 는 가상 사건 연습).' };

  const revocation = await readSection('기기 명단', async () => {
    const { data, error } = await client.from('vault_devices').select('device_id, status, created_at, approved_at')
      .eq('owner_id', ownerId).order('created_at', { ascending: false }).limit(LIMIT);
    throwIf(error);
    const rows = data ?? [];
    const records = rows.map(row => ({ device: mask(row.device_id), status: row.status, requestedAt: row.created_at, approvedAt: row.approved_at ?? null }));
    const byStatus = countBy(rows, 'status');
    return { status: rows.length ? 'confirmed' : 'not_run', source: 'db:vault_devices', records,
      counts: { devices: rows.length, approved: byStatus.approved ?? 0, pending: byStatus.pending ?? 0, revoked: byStatus.revoked ?? 0 } };
  });

  const recovery = await readSection('복구 기록', async () => {
    const [backups, policyAudit, restoreAudit] = await Promise.all([
      client.from('vault_policy_backup').select('version, snapshot_sha256, captured_at').order('captured_at', { ascending: false }).limit(LIMIT),
      client.from('vault_policy_audit').select('at, action, version, result').order('id', { ascending: false }).limit(LIMIT),
      client.from('vault_restore_audit').select('at, note_id, action, result').eq('owner_id', ownerId).order('id', { ascending: false }).limit(LIMIT),
    ]);
    throwIf(backups.error); throwIf(policyAudit.error); throwIf(restoreAudit.error);
    const versions = (backups.data ?? []).map(row => ({ version: row.version, sha256: mask(row.snapshot_sha256), capturedAt: row.captured_at }));
    const policyEvents = (policyAudit.data ?? []).map(row => ({ at: row.at, action: row.action, version: row.version ?? null, result: row.result }));
    const restoreEvents = (restoreAudit.data ?? []).map(row => ({ at: row.at, note: mask(row.note_id), action: row.action, result: row.result }));
    const total = versions.length + policyEvents.length + restoreEvents.length;
    return { status: total ? 'confirmed' : 'not_run', source: 'db:vault_policy_backup,vault_policy_audit,vault_restore_audit',
      records: { versions, policyEvents, restoreEvents },
      counts: { versions: versions.length, policyEvents: policyEvents.length, restoreEvents: restoreEvents.length,
        restored: restoreEvents.filter(event => event.result === 'restored').length,
        stopped: restoreEvents.filter(event => String(event.result).startsWith('stopped')).length } };
  });

  const sections = { decider, detection, revocation, recovery };
  // 가린 서버 기록: 화면과 같은 요청 ID·확인 시각·구역별 상태와 수치만 남깁니다(사용자·기록 내용 없음).
  console.info(`operations: summary ${JSON.stringify({ requestId, checkedAt,
    sections: Object.fromEntries(Object.entries(sections).map(([name, s]) => [name, { status: s.status, counts: s.counts }])) })}`);
  return response.status(200).json({ schema: 'aleph.operations.v1', requestId, checkedAt, limit: LIMIT, sections });
}
