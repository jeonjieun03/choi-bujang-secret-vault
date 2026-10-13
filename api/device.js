import { createHash, randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { ownerKeyOf } from '../src/owner-key.mjs';
import { logAuthReject } from '../src/auth-log.mjs';
import { checkChallenge, issueChallenge, sha256Hex, verifyAssertion, verifyRegistration } from '../src/device-auth.mjs';
import { decide } from '../src/decider.mjs';

const require = createRequire(import.meta.url);
const config = require('../aleph.config.json');

// 11단계: 기기 승인 요청과 결과 (POST /api/device, 로그인 필요)
//   {action:'challenge', purpose:'register'|'unlock'}  → 일회용 확인 문구(2분)
//   {action:'register', ...패스키 등록 결과}            → 공개키를 기기 명단에 'pending'(대기)으로 저장. 승인하지 않음
//   {action:'unlock', ...패스키 확인 결과}              → ① 패스키 서명 확인 ② 서버 기기 명단에서 등록(approved) 여부 확인
//                                                         ③ 판정기 decide()에 deviceRegistered 를 넣어 판정
//                                                         ④ 판정이 allow 일 때만 기기 세션(30분)을 줌
// 승인 버튼(등록 요청)만으로는 권한이 생기지 않습니다. 명단의 승인은 서버 쪽(Supabase)에서만 바뀝니다.
// 기기 개인키는 기기(운영체제)에만 있고, 서버에는 공개키만 저장합니다. 키·토큰·서명 값은 기록하지 않습니다.

const fail = (response, status, error) => response.status(status).json({ error });
const SESSION_MINUTES = 30;

let verifier = null;
function getVerifier(secretKey) {
  verifier ??= createLoginVerifier({ config, supabaseSecretKey: secretKey });
  return verifier;
}
function readJson(request) {
  const raw = request.body;
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) return raw;
  if (typeof raw === 'string') { try { const v = JSON.parse(raw); return v && typeof v === 'object' && !Array.isArray(v) ? v : null; } catch { return null; } }
  return null;
}
function originOf(request) {
  const host = String(request.headers?.['x-forwarded-host'] ?? request.headers?.host ?? '').split(',')[0].trim().toLowerCase();
  const proto = String(request.headers?.['x-forwarded-proto'] ?? 'https').split(',')[0].trim();
  if (!/^[a-z0-9.-]+(:\d+)?$/u.test(host)) return null;
  return { origin: `${proto}://${host}`, rpId: host.split(':')[0] };
}

// 판정기 계약(docs/DECIDER_REQUEST.md)의 18개 항목으로 "이 기기로 내 자료실 메모 읽기" 대표 요청을 만들어 묻습니다.
// deviceRegistered 는 서버가 방금 확인한 기기 명단 값입니다(브라우저가 보낸 값이 아님).
export function deviceDecisionRequest({ ownerId, deviceId, registered }) {
  return {
    schema: 'aleph.decision.v1', requestId: randomUUID(),
    classId: 'vault', projectId: 'choi-bujang-secret-vault',
    subjectId: `vault-${createHash('sha256').update(String(ownerId)).digest('hex').slice(0, 24)}`,
    deviceId, service: 'notes', method: 'GET', path: '/notes/vault', route: 'GET /notes/:id',
    queryLength: 0, querySha256: sha256Hex(''), at: new Date().toISOString(), policyRevision: 1,
    deviceRegistered: registered === true, stepUp: { verified: true, authAgeSeconds: 0 }, recentEvents: [],
    signals: { source: 'none', region: 'unknown', network: 'unknown', hour: null },
  };
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if ((request.method ?? 'GET') !== 'POST') { response.setHeader('Allow', 'POST'); return fail(response, 405, 'METHOD_NOT_ALLOWED'); }
  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) { console.error('device: 서버 환경변수가 설정되지 않았습니다.'); return fail(response, 500, 'SERVER_NOT_CONFIGURED'); }
  let verify;
  try { verify = getVerifier(secretKey); } catch (error) {
    console.error('device: 로그인 검사 설정이 올바르지 않습니다.', error?.message ?? 'unknown');
    return fail(response, 500, 'LOGIN_NOT_CONFIGURED');
  }
  const authorization = request.headers?.authorization;
  const identity = authorization ? await verify(authorization) : null;
  if (!identity?.userId) {
    logAuthReject('device', authorization);
    response.setHeader('WWW-Authenticate', 'Bearer');
    return fail(response, 401, authorization ? 'INVALID_LOGIN' : 'LOGIN_REQUIRED');
  }
  const ownerId = ownerKeyOf(identity);
  const input = readJson(request);
  if (!input) return fail(response, 400, 'INVALID_JSON');
  const site = originOf(request);
  if (!site) return fail(response, 400, 'INVALID_ORIGIN');
  const client = createClient(url, secretKey, { auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false } });

  try {
    if (input.action === 'challenge' && (input.purpose === 'register' || input.purpose === 'unlock')) {
      const handle = createHash('sha256').update(`vault-user:${ownerId}`).digest('base64url').slice(0, 32);
      return response.status(200).json({ challenge: issueChallenge(secretKey, { ownerId, purpose: input.purpose }),
        rpId: site.rpId, user: { handle, name: '내 자료실 사용자' } });
    }

    if (input.action === 'register') {
      if (!checkChallenge(secretKey, input.challenge, { ownerId, purpose: 'register' })) return fail(response, 400, 'CHALLENGE_INVALID');
      const reg = verifyRegistration(input, { challenge: input.challenge, origin: site.origin });
      const { error } = await client.from('vault_devices').insert({ device_id: reg.deviceId, owner_id: ownerId,
        credential_id: reg.credentialId, public_key_spki: reg.publicKeySpki, status: 'pending' });
      if (error?.code === '23505') return fail(response, 409, 'DEVICE_ALREADY_REGISTERED');
      if (error) { console.error('device: 등록 저장 실패', error.code ?? 'unknown'); return fail(response, 502, 'DEVICE_UNAVAILABLE'); }
      console.info('device: registered status=pending');
      return response.status(201).json({ deviceId: reg.deviceId, status: 'pending', approved: false });
    }

    if (input.action === 'unlock') {
      if (!checkChallenge(secretKey, input.challenge, { ownerId, purpose: 'unlock' })) return fail(response, 400, 'CHALLENGE_INVALID');
      if (typeof input.credentialId !== 'string' || input.credentialId.length > 1400) return fail(response, 404, 'DEVICE_UNKNOWN');
      const { data: device, error } = await client.from('vault_devices').select('device_id, public_key_spki, status')
        .eq('credential_id', input.credentialId).eq('owner_id', ownerId).maybeSingle();
      if (error) { console.error('device: 기기 조회 실패', error.code ?? 'unknown'); return fail(response, 502, 'DEVICE_UNAVAILABLE'); }
      if (!device) { console.info('device: deny reason=unknown_device'); return fail(response, 404, 'DEVICE_UNKNOWN'); }
      // ① 이 기기가 등록된 패스키를 실제로 가졌는지 확인
      verifyAssertion(input, { publicKeySpki: device.public_key_spki, challenge: input.challenge, origin: site.origin, rpId: site.rpId });
      // ② 서버 기기 명단 + ③ 판정기
      const verdict = await decide(deviceDecisionRequest({ ownerId, deviceId: device.device_id, registered: device.status === 'approved' }));
      if (verdict?.decision !== 'allow') {
        console.info(`device: unlock decision=${verdict?.decision ?? 'none'} reason=${verdict?.reasonCode ?? 'none'} status=${device.status}`);
        return response.status(200).json({ deviceId: device.device_id, status: device.status, approved: false,
          decision: verdict?.decision ?? 'deny', reasonCode: verdict?.reasonCode ?? 'unknown' });
      }
      // ④ 판정기 허용일 때만 기기 세션
      const expiresAt = new Date(Date.now() + SESSION_MINUTES * 60_000).toISOString();
      const { data: session, error: sessionError } = await client.from('vault_device_sessions')
        .insert({ device_id: device.device_id, owner_id: ownerId, expires_at: expiresAt }).select('session_id').single();
      if (sessionError) { console.error('device: 세션 저장 실패', sessionError.code ?? 'unknown'); return fail(response, 502, 'DEVICE_UNAVAILABLE'); }
      console.info('device: unlock decision=allow');
      return response.status(200).json({ deviceId: device.device_id, status: 'approved', approved: true,
        decision: 'allow', reasonCode: verdict.reasonCode, sessionId: session.session_id, expiresAt });
    }
    return fail(response, 400, 'UNKNOWN_ACTION');
  } catch (error) {
    console.info(`device: deny reason=${String(error?.message ?? 'invalid').slice(0, 40)}`);
    return fail(response, 400, 'DEVICE_PROOF_INVALID');
  }
}
