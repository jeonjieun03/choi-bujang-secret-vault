// 10단계: 메모 내용 해시. SHA-256(제목 + 구분 문자(코드 31) + 내용)을 16진수 64자로 돌려줍니다.
// supabase/step10_note_backup.sql 의 encode(sha256(convert_to(title || chr(31) || content, 'UTF8')), 'hex') 와 같습니다.
import { createHash } from 'node:crypto';

export function noteContentSha256(title, content) {
  return createHash('sha256').update(`${title}\u001f${content}`, 'utf8').digest('hex');
}
