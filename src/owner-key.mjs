import { createHash } from 'node:crypto';

// 8단계: 자료 주인을 가리키는 키(owner_id 에 저장되는 UUID).
// - 학생 본인 로그인(student): 검증된 사용자 ID 그대로.
// - 심판 시험 계정(judge): 같은 sub 로 A·B 두 신원이 올 수 있으므로 (sub, 시험 회차, 신원 a/b)를 묶어
//   서로 다른 키를 만듭니다. 그래야 시험 계정 B가 시험 계정 A의 메모를 자기 것으로 보지 않습니다.
// 토큰 원문은 쓰지 않고, verify-login.mjs 가 검증해 돌려준 값만 씁니다.
export function ownerKeyOf(identity) {
  if (!identity?.userId) return null;
  if (identity.kind !== 'judge') return identity.userId;
  const h = createHash('sha256')
    .update(`aleph-judge-owner:${identity.userId}:${identity.runId}:${identity.identity}`)
    .digest();
  h[6] = (h[6] & 0x0f) | 0x80; // UUID 버전 8(직접 만든 값)
  h[8] = (h[8] & 0x3f) | 0x80; // RFC 4122 변형
  const hex = h.subarray(0, 16).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}
