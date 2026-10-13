// 사용: npm run policy:diff            → policy/test-policy.json 과 검증 사본 비교
//       npm run policy:diff -- --current <파일>  → 연습용 정책 파일과 비교
// 읽기만 합니다. 어떤 파일도 바꾸지 않습니다.
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { diffPolicies, loadTestPolicy, loadVerifiedBackup, PolicyBackupError } from '../src/policy-diff.mjs';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const at = process.argv.indexOf('--current');
const currentPath = resolve(root, at > 0 && process.argv[at + 1] ? process.argv[at + 1] : 'policy/test-policy.json');
const label = { changed: '바뀜', added: '침해 뒤 추가됨(복원 시 삭제)', removed: '침해 뒤 사라짐(복원 시 되살림)' };

try {
  const backup = await loadVerifiedBackup(root);
  process.stdout.write(`검증된 사본: 버전 ${backup.manifest.version} · 원본 커밋 ${backup.manifest.sourceCommit ?? '-'} · SHA-256 일치 · 판정기 대조 일치\n`);
  const current = loadTestPolicy(currentPath);
  const diff = diffPolicies(current, backup.snapshot);
  process.stdout.write(`복원할 버전: ${diff.fromVersion} → ${diff.toVersion}\n`);
  if (!diff.changes.length) {
    process.stdout.write('차이 없음: 시험 정책이 검증 사본과 같습니다.\n');
  } else {
    process.stdout.write(`변경 범위: ${diff.changes.length}개 항목 · 서비스 ${diff.services.join(', ') || '-'}\n`);
    for (const c of diff.changes) process.stdout.write(`- [${label[c.kind]}] ${c.path}\n    지금 ${c.current ?? '(없음)'}  →  복원 ${c.restore ?? '(삭제)'}\n`);
  }
  process.stdout.write('이 명령은 차이만 보여 주며 아무 파일도 바꾸지 않았습니다.\n');
} catch (error) {
  const reason = error instanceof PolicyBackupError ? error.message : '예상하지 못한 오류';
  process.stderr.write(`중단: ${reason}. 복원하지 않습니다.\n`);
  process.exitCode = 1;
}
