// 사용: npm run backup:verify
// 10단계 백업 검증: 침해 전 정책 사본을 다시 읽어 검증하고(지문·고정 기준·Git 이력·판정기 대조),
// 실제로 복원되는지 "시험 복원"까지 해 본 뒤 결과를 backup/policy/verify-log.jsonl 에 한 줄 남깁니다.
// 시험 복원은 메모리 안의 침공 연습 정책 사본에만 하고, 시험 정책·운영 판정기·DB 는 바꾸지 않습니다.
// 검증이나 시험 복원이 하나라도 실패하면 결과를 fail 로 남기고 멈춥니다(종료 코드 1).
import { appendFileSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadVerifiedBackup, PolicyBackupError } from '../src/policy-diff.mjs';
import { evaluateNotesPolicy, RESTORE_CHECKS } from '../src/policy-restore.mjs';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const log = join(root, 'backup', 'policy', 'verify-log.jsonl');
const out = text => process.stdout.write(`${text}\n`);
const record = { at: new Date().toISOString(), action: 'backup_verify', target: 'policy' };

try {
  const backup = await loadVerifiedBackup(root);
  record.version = backup.manifest.version;
  record.sha256 = backup.manifest.sha256;
  record.anchor = backup.anchor;
  out(`1) 사본 다시 읽기·검증: 버전 ${record.version} · SHA-256 일치 · 고정 기준 일치 · Git 검증 커밋 ${backup.anchor.git === 'match' ? '일치' : '확인 불가(Git 없음)'} · 판정기 대조 일치`);

  // 2) 시험 복원: 침공 연습 정책(메모리 사본)에 검증 사본의 notes 서비스를 되돌려 보고 정상·금지 요청을 확인
  const attacked = JSON.parse(readFileSync(join(root, 'policy', 'fixtures', 'attacked-test-policy.json'), 'utf8'));
  const before = RESTORE_CHECKS.filter(c => evaluateNotesPolicy(attacked, c.request) !== c.expect).length;
  const restored = structuredClone(attacked);
  restored.services.notes = structuredClone(backup.snapshot.services.notes);
  const failed = RESTORE_CHECKS.filter(c => evaluateNotesPolicy(restored, c.request) !== c.expect).map(c => c.name);
  record.testRestore = { checks: RESTORE_CHECKS.length, failedBefore: before, failedAfter: failed.length };
  out(`2) 시험 복원: 침공 연습 정책에서 기대와 다른 요청 ${before}개 → 복원 뒤 ${failed.length}개`);
  if (failed.length) throw new PolicyBackupError(`시험 복원 뒤에도 기대와 다른 요청: ${failed.join(', ')}`);
  record.result = 'pass';
  out('결과: pass — 이 사본은 다시 읽어 검증했고 실제로 복원되는 것을 확인했습니다.');
} catch (error) {
  record.result = 'fail';
  record.reason = error instanceof PolicyBackupError ? error.message : '예상하지 못한 오류';
  out(`결과: fail — ${record.reason}. 이 사본으로는 복원하지 않습니다.`);
  process.exitCode = 1;
}
appendFileSync(log, `${JSON.stringify(record)}\n`, 'utf8');
out(`기록: backup/policy/verify-log.jsonl 에 한 줄 추가(지우지 않고 쌓음)`);
