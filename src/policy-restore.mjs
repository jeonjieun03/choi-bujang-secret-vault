// 10단계 제작 2: 검증한 안전 정책 버전으로 "시험 정책"을 되돌리는 절차입니다.
// - 먼저 검증 사본(loadVerifiedBackup)을 다시 읽어 검증합니다. 실패하면 중단합니다.
// - 지정한 서비스 한 개(--service)만 사본으로 되돌리고, 다른 서비스 규칙과 사본에 없는 서비스는 그대로 둡니다.
// - 감사 이력(audit-log.jsonl)은 지우거나 고치지 않고 맨 끝에 한 줄만 덧붙입니다.
// - 실행 전에는 바뀔 항목만 보여 주고(미리 보기), 확인(--yes)을 받아야 파일을 씁니다.
// - 운영 판정기(src/decider.mjs)·aleph.config.json·api/·supabase/·backup/ 은 쓰지 않습니다.
import { appendFileSync, existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { diffPolicies, loadTestPolicy, loadVerifiedBackup, PolicyBackupError } from './policy-diff.mjs';

const SERVICE = /^[a-z][a-z0-9_-]{0,31}$/u;
const PROTECTED = ['src', 'api', 'supabase', 'backup', 'scripts', 'public', 'xdr'];

export function assertWritableTestPolicy(root, target) {
  const rel = relative(root, resolve(target));
  if (rel === 'aleph.config.json' || PROTECTED.some(dir => rel === dir || rel.startsWith(dir + sep))) {
    throw new PolicyBackupError('운영 파일이나 사본 폴더에는 쓰지 않음(시험 정책 파일만 복원)');
  }
}

// 복원 계획: 대상 서비스의 차이만 보여 줍니다. 파일은 바꾸지 않습니다.
export async function planRestore(root, target, service) {
  if (typeof service !== 'string' || !SERVICE.test(service)) throw new PolicyBackupError('--service 에 되돌릴 서비스 이름 하나가 필요함');
  assertWritableTestPolicy(root, target);
  const backup = await loadVerifiedBackup(root);
  if (!backup.snapshot.services[service]) throw new PolicyBackupError(`검증 사본에 ${service} 서비스가 없음`);
  const current = loadTestPolicy(target);
  const all = diffPolicies(current, backup.snapshot);
  const prefix = `services › ${service} › `;
  const changes = all.changes.filter(c => c.path.startsWith(prefix) || c.path === `services › ${service}`);
  const kept = all.services.filter(name => name !== service);
  return Object.freeze({ backup, current, service, changes, keptServices: kept,
    fromVersion: current.version, toVersion: backup.snapshot.version });
}

// 계획대로 실행: 쓰기 직전에 사본을 다시 읽어 검증하고, 미리 보기 때의 사본·시험 정책과 같을 때만
// 대상 서비스를 사본 값으로 바꾼 뒤 감사 이력에 한 줄 덧붙입니다. 다르면 아무것도 쓰지 않고 멈춥니다.
export async function applyRestore(root, target, plan, { now = new Date() } = {}) {
  assertWritableTestPolicy(root, target);
  const recheck = await loadVerifiedBackup(root);
  if (recheck.manifest.sha256 !== plan.backup.manifest.sha256 || recheck.snapshot.version !== plan.toVersion) {
    throw new PolicyBackupError('실행 직전 사본 재검증 결과가 미리 보기 때와 다름');
  }
  if (JSON.stringify(loadTestPolicy(target)) !== JSON.stringify(plan.current)) {
    throw new PolicyBackupError('미리 보기 뒤 시험 정책이 바뀜(다시 미리 보기 필요)');
  }
  const next = structuredClone(plan.current);
  next.services[plan.service] = structuredClone(plan.backup.snapshot.services[plan.service]);
  const remaining = diffPolicies({ ...next, version: plan.toVersion }, plan.backup.snapshot).changes;
  // 모든 서비스가 사본과 같아지면 정책 버전도 사본 버전으로, 아니면 현재 버전을 두고 서비스에 복원 출처만 적습니다.
  if (!remaining.length) next.version = plan.toVersion;
  else next.services[plan.service].restoredFrom = plan.toVersion;
  const tmp = `${target}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(next, null, 2)}\n`, { encoding: 'utf8', flag: 'w' });
  renameSync(tmp, target);
  const audit = join(dirname(target), 'audit-log.jsonl');
  const before = existsSync(audit) ? readFileSync(audit, 'utf8').split('\n').filter(Boolean).length : 0;
  appendFileSync(audit, `${JSON.stringify({
    at: now.toISOString(), action: 'policy_restore', service: plan.service,
    fromVersion: plan.fromVersion, toVersion: plan.toVersion, changedItems: plan.changes.length,
    keptServices: plan.keptServices, backupSha256: plan.backup.manifest.sha256,
  })}\n`, 'utf8');
  return Object.freeze({ policy: next, auditFile: audit, auditLinesBefore: before });
}

// 시험 정책만으로 가상 요청을 판정합니다(운영 판정기와 별도). 메모 주인 비교는 자료 API 몫입니다.
export function evaluateNotesPolicy(policy, request) {
  const rules = policy?.services?.notes;
  if (!rules) return 'deny';
  if (rules.requireRegisteredDevice !== false && request.deviceRegistered !== true) return 'deny';
  if (!rules.queryAllowed && request.queryLength > 0) return 'deny';
  const rule = rules.routes?.[request.route];
  return rule?.decision === 'allow' ? 'allow' : (rules.defaultDecision === 'allow' && !rule ? 'allow' : 'deny');
}

// 복원 뒤 확인할 가상 요청: A 정상 요청은 allow, B 가 A 자료로 가는 길·금지 요청은 deny 여야 합니다.
export const RESTORE_CHECKS = Object.freeze([
  { name: 'A 정상: 자기 메모 한 건 읽기', expect: 'allow', request: { route: 'GET /notes/:id', deviceRegistered: true, queryLength: 0 } },
  { name: 'A 정상: 자기 메모 한 건 수정', expect: 'allow', request: { route: 'PUT /notes/:id', deviceRegistered: true, queryLength: 0 } },
  { name: 'B → A 자료: 메모 전체 목록으로 남의 메모 열기', expect: 'deny', request: { route: 'GET /notes', deviceRegistered: true, queryLength: 0 } },
  { name: 'B → A 자료: 남의 메모 삭제 경로', expect: 'deny', request: { route: 'DELETE /notes/:id', deviceRegistered: true, queryLength: 0 } },
  { name: 'B 금지: 학생의 공지 수정', expect: 'deny', request: { route: 'PUT /notices/:id', deviceRegistered: true, queryLength: 0 } },
  { name: 'B 금지: 미등록 기기로 메모 읽기', expect: 'deny', request: { route: 'GET /notes/:id', deviceRegistered: false, queryLength: 0 } },
]);
