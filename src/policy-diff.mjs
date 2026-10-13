// 10단계 제작 1: 침해 전에 검증한 안전 정책 사본과 현재 시험 정책의 차이만 보여 줍니다(읽기 전용).
// - 사본: backup/policy/manifest.json 이 가리키는 파일. SHA-256 지문·형식·버전이 맞아야 하고,
//   사본의 notes 경로 규칙이 실제 판정기(src/decider.mjs)의 가상 요청 결과와 같아야 "검증됨"입니다.
// - 사본이 없거나 검증에 실패하면 차이를 보여 주지 않고 중단합니다(PolicyBackupError).
// - 시험 정책(policy/test-policy.json)만 읽습니다. 운영 판정기·aleph.config.json·DB는 읽기만 하고 바꾸지 않습니다.
// - 비밀값·메모 본문·실명은 정책에 없고, 출력하지도 않습니다.
import { createHash, randomUUID } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';

export const POLICY_SCHEMA = 'aleph.vault.policy.v1';
export const BACKUP_SCHEMA = 'aleph.vault.policy-backup.v1';
const VERSION = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;

export class PolicyBackupError extends Error {}

const sha256 = buffer => createHash('sha256').update(buffer).digest('hex');

function parseJson(buffer, label) {
  try { return JSON.parse(buffer.toString('utf8')); } catch { throw new PolicyBackupError(`${label}: JSON 형식이 아님`); }
}

function checkPolicyShape(policy, label) {
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) throw new PolicyBackupError(`${label}: 객체가 아님`);
  if (policy.schema !== POLICY_SCHEMA) throw new PolicyBackupError(`${label}: schema 가 ${POLICY_SCHEMA} 가 아님`);
  if (typeof policy.version !== 'string' || !VERSION.test(policy.version)) throw new PolicyBackupError(`${label}: version 형식이 틀림`);
  const services = policy.services;
  if (!services || typeof services !== 'object' || Array.isArray(services) || !services.notes?.routes) {
    throw new PolicyBackupError(`${label}: services.notes.routes 가 없음`);
  }
}

// 사본의 notes 경로 규칙을 실제 판정기에 가상 요청으로 넣어 같은 결정이 나오는지 확인합니다.
async function crossCheckWithDecider(snapshot, root) {
  const { decide } = await import(new URL(`file://${join(root, 'src', 'decider.mjs')}`).href);
  const { fixtureRequests } = await import(new URL(`file://${join(root, 'scripts', 'fixture-7.mjs')}`).href);
  const { normal } = fixtureRequests();
  const sampleId = { notes: 'demo', notices: '11111111-2222-4333-8444-555555555555' };
  for (const [route, rule] of Object.entries(snapshot.services.notes.routes)) {
    const [method, shape] = route.split(' ');
    const collection = shape.split('/')[1];
    const path = shape.replace(':id', sampleId[collection] ?? 'demo');
    const result = await decide({ ...normal, requestId: randomUUID(), at: new Date().toISOString(), method, route, path });
    if (result.decision !== rule.decision || (rule.reasonCode && result.reasonCode !== rule.reasonCode)) {
      throw new PolicyBackupError(`사본 검증 실패: ${route} 는 사본에서 ${rule.decision}, 판정기에서 ${result.decision}`);
    }
  }
}

// 사본을 다시 읽어 검증합니다. 성공하면 { manifest, snapshot, file } 를 돌려줍니다.
export async function loadVerifiedBackup(root, { crossCheck = true } = {}) {
  const manifestPath = join(root, 'backup', 'policy', 'manifest.json');
  if (!existsSync(manifestPath)) throw new PolicyBackupError('사본 목록(backup/policy/manifest.json)이 없음');
  const manifest = parseJson(readFileSync(manifestPath), '사본 목록');
  if (manifest?.schema !== BACKUP_SCHEMA) throw new PolicyBackupError('사본 목록: schema 가 맞지 않음');
  if (typeof manifest.file !== 'string' || basename(manifest.file) !== manifest.file) throw new PolicyBackupError('사본 목록: file 이름이 틀림');
  if (typeof manifest.sha256 !== 'string' || !SHA256.test(manifest.sha256)) throw new PolicyBackupError('사본 목록: sha256 형식이 틀림');
  const file = join(dirname(manifestPath), manifest.file);
  if (!existsSync(file)) throw new PolicyBackupError(`사본 파일(${manifest.file})이 없음`);
  const raw = readFileSync(file);
  if (sha256(raw) !== manifest.sha256) throw new PolicyBackupError('사본 검증 실패: SHA-256 지문이 사본 목록과 다름');
  const snapshot = parseJson(raw, '사본');
  checkPolicyShape(snapshot, '사본');
  if (snapshot.version !== manifest.version) throw new PolicyBackupError('사본 검증 실패: 사본 버전과 사본 목록 버전이 다름');
  if (crossCheck) await crossCheckWithDecider(snapshot, root);
  return Object.freeze({ manifest, snapshot, file });
}

export function loadTestPolicy(path) {
  if (!existsSync(path)) throw new PolicyBackupError('시험 정책 파일이 없음');
  const policy = parseJson(readFileSync(path), '시험 정책');
  checkPolicyShape(policy, '시험 정책');
  return policy;
}

// 값이 있는 칸(잎)만 "a.b.c" 경로로 펼칩니다. 배열은 한 값으로 비교합니다.
function flatten(value, prefix, out) {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const key of Object.keys(value).sort()) flatten(value[key], prefix ? `${prefix} › ${key}` : key, out);
  } else {
    out.set(prefix, JSON.stringify(value));
  }
  return out;
}

// 차이만 돌려줍니다: [{ path, kind: 'changed'|'added'|'removed', current, restore }]
// note(설명 문장)는 비교하지 않습니다.
export function diffPolicies(current, snapshot) {
  const pick = policy => flatten({ version: policy.version, services: policy.services }, '', new Map());
  const a = pick(current);
  const b = pick(snapshot);
  const changes = [];
  for (const path of [...new Set([...a.keys(), ...b.keys()])].sort()) {
    if (a.get(path) === b.get(path)) continue;
    const kind = !a.has(path) ? 'removed' : !b.has(path) ? 'added' : 'changed';
    changes.push(Object.freeze({ path, kind, current: a.get(path) ?? null, restore: b.get(path) ?? null }));
  }
  const services = [...new Set(changes.map(c => c.path.split(' › ')[1]).filter(Boolean))].sort();
  return Object.freeze({ fromVersion: current.version, toVersion: snapshot.version, services, changes });
}
