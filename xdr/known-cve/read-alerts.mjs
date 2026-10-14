// 확인용 읽기 모듈: xdr/fixtures/known-cve.json 의 Wazuh 경보에서
// 시각·출발 주소·계정·규칙 수준·설명만 뽑아 보여 줍니다.
// - 원본 경보 파일은 읽기만 하고 고치지 않습니다.
// - 비밀값처럼 보이는 값(키·토큰·비밀번호·이메일 등)은 [가림]으로 바꿔 출력합니다.
// - 원격 조회 구문(${...} 형태)은 문서용 표기라도 다른 곳에 옮기지 않도록 [조회 구문 가림]으로 바꿉니다.
//   요청 머리글(useragent)·주소(url)·반복 횟수(count) 칸은 뽑지 않습니다.
// - decide.mjs 는 이 파일을 불러오지 않습니다(판단 모듈과 따로 둡니다).
//
// 실행: node xdr/known-cve/read-alerts.mjs

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const FIXTURE = new URL('../fixtures/known-cve.json', import.meta.url);

// 비밀값처럼 보이는 문자열
const SECRET_PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/gu,
  /\bBearer\s+[A-Za-z0-9._~+/-]{8,}/giu,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}/gu, // JWT
  /\b(?:sb_secret|sb_publishable|sk|pk|ghp|gho|xox[abpr])[-_][A-Za-z0-9_-]{8,}/gu,
  /\b(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*\S+/giu,
  /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/giu, // 이메일
];
// 원격 조회 구문 모양: "${" 부터 짝이 맞는 "}" 까지(겹친 구문 포함, 닫는 괄호가 없으면 끝까지) 통째로 가립니다.
function maskLookups(text) {
  let out = '';
  let i = 0;
  while (i < text.length) {
    const start = text.indexOf('${', i);
    if (start < 0) { out += text.slice(i); break; }
    out += `${text.slice(i, start)}[조회 구문 가림]`;
    let depth = 0;
    let j = start;
    for (; j < text.length; j += 1) {
      if (text[j] === '$' && text[j + 1] === '{') { depth += 1; j += 1; }
      else if (text[j] === '}') { depth -= 1; if (depth === 0) break; }
    }
    i = j + 1;
  }
  return out;
}

export function mask(value) {
  if (value === null || value === undefined) return '-';
  let text = String(value).replace(/[\r\n\t]+/gu, ' ');
  text = maskLookups(text);
  for (const pattern of SECRET_PATTERNS) text = text.replace(pattern, '[가림]');
  return text.length > 200 ? `${text.slice(0, 200)}…` : text;
}

// 경보 하나에서 필요한 칸만 뽑습니다(대조용 경보 번호 + 다섯 칸). 원본 객체는 바꾸지 않습니다.
export function extract(alert) {
  const data = alert?.data && typeof alert.data === 'object' ? alert.data : {};
  return {
    id: mask(alert?.id),
    time: mask(alert?.timestamp),
    srcip: mask(data.srcip),
    user: mask(data.srcuser ?? data.dstuser),
    level: Number.isFinite(alert?.rule?.level) ? alert.rule.level : '-',
    description: mask(alert?.rule?.description),
  };
}

export async function readAlerts(path = FIXTURE) {
  const fixture = JSON.parse(await readFile(path, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || !Array.isArray(fixture.alerts)) {
    throw new Error('경보 묶음 형식이 아닙니다.');
  }
  return { total: fixture.alerts.length, rows: fixture.alerts.map(extract) };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const { total, rows } = await readAlerts();
  for (const r of rows) {
    console.log([r.id, r.time, r.srcip, r.user, `level ${r.level}`, r.description].join(' | '));
  }
  console.log(`경보 ${total}건 · 뽑은 줄 ${rows.length}줄 · ${total === rows.length ? '일치' : '불일치'}`);
}
