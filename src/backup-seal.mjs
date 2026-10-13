// 10단계 보강: 메모 사본 봉인(서명). 사본을 만들 때 서버만 아는 키로 봉인을 남기고,
// 복원할 때 사본을 다시 읽어 봉인을 다시 계산해 비교합니다. 봉인 키는 서버 전용 키에서 만든 값이라 DB에 없으므로,
// DB의 사본(내용·해시)을 바꿔도 봉인은 위조할 수 없습니다. 키·봉인 계산값은 로그·응답에 남기지 않습니다.
import { createHmac, timingSafeEqual } from 'node:crypto';

const HEX64 = /^[0-9a-f]{64}$/u;

function sealKey(serverSecret) {
  if (typeof serverSecret !== 'string' || !serverSecret) throw new Error('seal_key_missing');
  return createHmac('sha256', serverSecret).update('aleph-vault-backup-seal-v1').digest();
}

// 봉인 대상: 메모 ID · 소유자 · 내용 해시
export function backupSeal(serverSecret, { noteId, ownerId, contentSha256 }) {
  return createHmac('sha256', sealKey(serverSecret))
    .update(`${String(noteId).toLowerCase()}|${String(ownerId).toLowerCase()}|${contentSha256}`, 'utf8').digest('hex');
}

export function sealMatches(serverSecret, backup, seal) {
  if (typeof seal !== 'string' || !HEX64.test(seal)) return false;
  const expected = backupSeal(serverSecret, backup);
  return timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(seal, 'hex'));
}
