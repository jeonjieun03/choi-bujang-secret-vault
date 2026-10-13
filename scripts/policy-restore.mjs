// 사용: npm run policy:restore -- --service notes            → 미리 보기(바뀔 항목만 표시, 파일 안 바꿈)
//       npm run policy:restore -- --service notes --yes      → 확인 후 실행(시험 정책만 복원 + 감사 이력 한 줄 추가)
//       --current <파일>  : policy/test-policy.json 대신 연습용 시험 정책 파일을 대상으로 함
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PolicyBackupError } from '../src/policy-diff.mjs';
import { applyRestore, evaluateNotesPolicy, planRestore, RESTORE_CHECKS } from '../src/policy-restore.mjs';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const arg = name => { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : undefined; };
const target = resolve(root, arg('--current') ?? 'policy/test-policy.json');
const service = arg('--service');
const confirmed = process.argv.includes('--yes');
const out = text => process.stdout.write(`${text}\n`);

function showChecks(policy, title) {
  out(title);
  let ok = true;
  for (const check of RESTORE_CHECKS) {
    const got = evaluateNotesPolicy(policy, check.request);
    ok &&= got === check.expect;
    out(`  ${got === check.expect ? '통과' : '확인 필요'} · ${check.name} → ${got} (기대 ${check.expect})`);
  }
  return ok;
}

try {
  const plan = await planRestore(root, target, service);
  out(`검증된 사본: 버전 ${plan.toVersion} · SHA-256 일치 · 판정기 대조 일치`);
  out(`복원 대상: 서비스 ${plan.service} · 시험 정책 버전 ${plan.fromVersion} → ${plan.toVersion}`);
  out(`보존: 다른 서비스 ${plan.keptServices.length ? plan.keptServices.join(', ') + '(차이가 있어도 이번에 바꾸지 않음)' : '(차이 없음)'} · 감사 이력은 지우지 않고 한 줄 추가`);
  if (!plan.changes.length) {
    out(`바뀔 항목 없음: ${plan.service} 서비스가 이미 검증 사본과 같습니다. 아무 파일도 바꾸지 않았습니다.`);
    showChecks(plan.current, '현재 시험 정책 가상 요청 확인:');
  } else {
    out(`바뀔 항목 ${plan.changes.length}개:`);
    for (const c of plan.changes) out(`  - ${c.path}: ${c.current ?? '(없음)'} → ${c.restore ?? '(삭제)'}`);
    if (!confirmed) {
      showChecks(plan.current, '복원 전 시험 정책 가상 요청 확인:');
      out('미리 보기만 했습니다. 위 항목을 확인한 뒤 같은 명령 끝에 --yes 를 붙이면 실행합니다.');
    } else {
      const done = applyRestore(root, target, plan);
      out(`복원 완료: 시험 정책 ${plan.service} 서비스를 ${plan.toVersion} 으로 되돌렸습니다. 감사 이력 ${done.auditLinesBefore}줄 보존 + 1줄 추가.`);
      const ok = showChecks(done.policy, '복원 뒤 시험 정책 가상 요청 확인:');
      if (!ok) process.exitCode = 1;
    }
  }
  out('운영 판정기(src/decider.mjs)·aleph.config.json·DB 는 바꾸지 않았습니다. 메모 한 건의 주인 비교는 자료 API(404)가 합니다.');
} catch (error) {
  out(`중단: ${error instanceof PolicyBackupError ? error.message : '예상하지 못한 오류'}. 복원하지 않습니다.`);
  process.exitCode = 1;
}
