// brute-force 대응 모듈: decide() 결과를 받아
//   1) block(차단 후보)만 ZTNA 판정기에 꽂을 "추가 거부 규칙"으로 만들고
//   2) alert·block 을 xdr/alerts.log 에 한 줄씩 쌓습니다.
// decide.mjs 는 판단만 하고, 파일 쓰기·판정기 연결은 이 파일에서만 합니다.
// 판정기(src/decider.mjs)의 기존 규칙은 고치지 않습니다. 이 모듈은 판정기 앞에 끼우는 확인 단계 부품입니다.
//
// 실행: node xdr/brute-force/respond.mjs   (시험 경보를 흘려 규칙·알림을 만들고 다시 흘려 확인)

import { appendFile, readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const FIXTURE = new URL('../fixtures/brute-force.json', import.meta.url);
const RULES_FILE = new URL('./deny-rules.json', import.meta.url);
const ALERT_LOG = new URL('../alerts.log', import.meta.url);

export const RULE_ID = 'xdr.brute_force.deny_source';
export const BLOCK_MINUTES = 60;      // 차단 규칙 유지 시간
const MIN_BLOCK_CONFIDENCE = 0.85;     // decide 의 block 기준과 같음

const IPV4 = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/u;

const clean = (value) => String(value ?? '-').replace(/[\r\n\t|]+/gu, ' ').slice(0, 200);

function isoTime(value) {
  const t = Date.parse(value);
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
}

// 경보 묶음을 판단합니다. decide 결과에 경보의 주소·계정·시각만 붙입니다.
export async function judgeAlerts(alerts) {
  const out = [];
  for (const alert of alerts) {
    const decision = await decide(alert);
    out.push({
      alertId: clean(alert?.id),
      at: isoTime(alert?.timestamp),
      srcip: typeof alert?.data?.srcip === 'string' ? alert.data.srcip : null,
      user: typeof alert?.data?.srcuser === 'string' ? alert.data.srcuser : null,
      ...decision,
    });
  }
  return out;
}

// 차단 후보만 거부 규칙으로 만듭니다.
// - 규칙은 출발 주소 하나만 막습니다. 계정은 막지 않습니다(같은 계정의 정상 사용자를 막지 않도록).
// - 같은 주소에서 정상(record) 이벤트가 하나라도 있으면 그 주소는 막지 않습니다.
// - 만료 시각과 근거 경보 번호를 붙입니다.
export function buildDenyRules(judged) {
  const normalSources = new Set(judged.filter(j => j.action === 'record' && j.srcip).map(j => j.srcip));
  const bySource = new Map();
  for (const j of judged) {
    if (j.action !== 'block' || j.confidence < MIN_BLOCK_CONFIDENCE) continue;
    if (!j.srcip || !IPV4.test(j.srcip) || !j.at) continue;
    if (normalSources.has(j.srcip)) continue;
    const expiresAt = new Date(Date.parse(j.at) + BLOCK_MINUTES * 60_000).toISOString();
    const rule = bySource.get(j.srcip) ?? {
      ruleId: RULE_ID, action: 'deny', match: { srcip: j.srcip },
      createdAt: j.at, expiresAt, evidenceAlertIds: [], reason: j.reason,
    };
    if (!rule.evidenceAlertIds.includes(j.alertId)) rule.evidenceAlertIds.push(j.alertId);
    if (expiresAt > rule.expiresAt) rule.expiresAt = expiresAt;
    bySource.set(j.srcip, rule);
  }
  return [...bySource.values()];
}

// 판정기 앞에 끼우는 확인 단계: 이 주소가 아직 유효한 거부 규칙에 걸리는지 봅니다.
// 반환이 null 이면 이 단계는 통과이고, 그 뒤는 판정기의 기존 규칙이 그대로 판단합니다.
// (현재 판정기 계약에는 출발 주소 항목이 없으므로, 운영 엔진이 확인한 주소를 따로 넘겨받을 때만 씁니다.)
export function checkDeny({ srcip, at }, rules) {
  const now = Date.parse(at);
  if (!srcip || !Number.isFinite(now)) return null;
  const hit = rules.find(r => r.match?.srcip === srcip
    && Date.parse(r.createdAt) <= now && now < Date.parse(r.expiresAt));
  return hit ? { decision: 'deny', reasonCode: 'xdr_brute_force', ruleIds: [hit.ruleId] } : null;
}

// alert·block 결과를 alerts.log 에 한 줄씩 쌓습니다. 같은 경보·같은 행동은 두 번 쓰지 않습니다.
export async function appendAlertLog(judged, logUrl = ALERT_LOG) {
  let existing = '';
  try { existing = await readFile(logUrl, 'utf8'); } catch { existing = ''; }
  const seen = new Set(existing.split('\n').map(line => line.split(' | ').slice(1, 3).join(' | ')));
  const lines = [];
  for (const j of judged) {
    if (j.action === 'record') continue;
    const key = `${j.action} | ${j.alertId}`;
    if (seen.has(key)) continue;
    seen.add(key);
    lines.push([j.at ?? '-', j.action, j.alertId, clean(j.srcip), clean(j.user),
      `confidence ${j.confidence.toFixed(2)}`, clean(j.reason)].join(' | '));
  }
  if (lines.length) await appendFile(logUrl, `${lines.join('\n')}\n`, 'utf8');
  return lines.length;
}

export async function respond({ fixtureUrl = FIXTURE, rulesUrl = RULES_FILE, logUrl = ALERT_LOG } = {}) {
  const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || !Array.isArray(fixture.alerts)) {
    throw new Error('경보 묶음 형식이 아닙니다.');
  }
  const judged = await judgeAlerts(fixture.alerts);
  const rules = buildDenyRules(judged);
  await writeFile(rulesUrl, `${JSON.stringify({ schema: 'aleph.xdr.deny-rules.v1', moduleKey: 'brute-force', rules }, null, 2)}\n`, 'utf8');
  const logged = await appendAlertLog(judged, logUrl);
  return { judged, rules, logged };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const { judged, rules, logged } = await respond();
  console.log(`거부 규칙 ${rules.length}개 · 알림 로그 새 줄 ${logged}줄`);
  // 시험 경보를 다시 흘려 확인: 같은 시각에 같은 주소로 요청이 왔다고 보고 막히는지 봅니다.
  let wrong = 0;
  for (const j of judged) {
    const blocked = Boolean(checkDeny({ srcip: j.srcip, at: j.at }, rules));
    const shouldBlock = j.action === 'block';
    if (blocked !== shouldBlock) wrong += 1;
    console.log(`${j.alertId} ${j.action.padEnd(6)} → ${blocked ? '막힘' : '통과'}${blocked !== shouldBlock ? '  ← 확인 필요' : ''}`);
  }
  console.log(wrong ? `확인 필요 ${wrong}건` : '명확한 공격만 막히고 나머지는 통과했습니다.');
}
