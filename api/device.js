import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { ownerKeyOf } from '../src/owner-key.mjs';
import { logAuthReject } from '../src/auth-log.mjs';
import { checkChallenge, issueChallenge, sessionJwkOf, verifyAssertion, verifyRegistration } from '../src/device-auth.mjs';

const require = createRequire(import.meta.url);
const config = require('../aleph.config.json');

// 11단계: 기기 승인 요청과 확인 (POST /api/device, 로그인 필요)
//   {action:'challenge', purpose:'register'}                 → 등록용 일회용 문구
//   {action:'register', challenge, credentialId, publicKeySpki, publicKeyAlgorithm, clientDataJSON}
//                                                            → 패스키 공개키를 '대기(pending)'로 저장. 승인하지 않음
//   {action:'challenge', purpose:'unlock', sessionJwk}       → 잠금 해제용 일회용 문구(이번 화면용 공개키에 묶임)
//   {action:'unlock', challenge, sessionJwk, credentialId, authenticatorData, clientDataJSON, signature}
//                                                            → 패스키 서명 확인 후, DB에서 '승인(approved)'된 기기일 때만
//                                                              이번 화면용 서명 세션(30분)을 만듦. 대기·거절이면 세션 없음
// 승인은 주인이 Supabase에서 vault_devices.status 를 approved 로 바꿀 때만 됩니다(화면 버튼으로는 승인되지 않음).
// 기기 개인키·토큰·서명 값은 저장·기록하지 않습니다. 서버에는 공개키만 저장합니다.

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
// 화면이 열린 주소(출처)와 패스키 범위(rpId): Vercel 이 알려 주는 호스트 기준
function originOf(request) {
  const host = String(request.headers?.['x-forwarded-host'] ?? request.headers?.host ?? '').split(',')[0].trim().toLowerCase();
  const proto = String(request.headers?.['x-forwarded-proto'] ?? 'https').split(',')[0].trim();
  if (!/^[a-z0-9.-]+(:\d+)?$/u.test(host)) return null;
  return { origin: `${proto}://${host}`, rpId: host.split(':')[0] };
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
  const devices = () => client.from('vault_devices');

  try {
    if (input.action === 'challenge' && input.purpose === 'register') {
      const handle = createHash('sha256').update(`vault-user:${ownerId}`).digest('base64url').slice(0, 32);
      return response.status(200).json({ challenge: issueChallenge(secretKey, { ownerId, purpose: 'register' }),
        rpId: site.rpId, user: { handle, name: '내 자료실 사용자' } });
    }
    if (input.action === 'challenge' && input.purpose === 'unlock') {
      const { thumbprint } = sessionJwkOf(input.sessionJwk);
      return response.status(200).json({ challenge: issueChallenge(secretKey, { ownerId, purpose: 'unlock', bind: thumbprint }), rpId: site.rpId });
    }

    if (input.action === 'register') {
      if (!checkChallenge(secretKey, input.challenge, { ownerId, purpose: 'register' })) return fail(response, 400, 'CHALLENGE_INVALID');
      const reg = verifyRegistration(input, { challenge: input.challenge, origin: site.origin });
      const { error } = await devices().insert({ device_id: reg.deviceId, owner_id: ownerId,
        credential_id: reg.credentialId, public_key_spki: reg.publicKeySpki, status: 'pending' });
      if (error?.code === '23505') return fail(response, 409, 'DEVICE_ALREADY_REGISTERED');
      if (error) { console.error('device: 등록 저장 실패', error.code ?? 'unknown'); return fail(response, 502, 'DEVICE_UNAVAILABLE'); }
      console.info('device: registered status=pending');
      return response.status(201).json({ deviceId: reg.deviceId, status: 'pending', approved: false });
    }

    if (input.action === 'unlock') {
      const { jwk, thumbprint } = sessionJwkOf(input.sessionJwk);
      if (!checkChallenge(secretKey, input.challenge, { ownerId, purpose: 'unlock', bind: thumbprint })) return fail(response, 400, 'CHALLENGE_INVALID');
      if (typeof input.credentialId !== 'string' || input.credentialId.length > 1400) return fail(response, 400, 'DEVICE_UNKNOWN');
      const { data: device, error } = await devices().select('device_id, owner_id, public_key_spki, status')
        .eq('credential_id', input.credentialId).eq('owner_id', ownerId).maybeSingle();
      if (error) { console.error('device: 기기 조회 실패', error.code ?? 'unknown'); return fail(response, 502, 'DEVICE_UNAVAILABLE'); }
      if (!device) { console.info('device: deny reason=unknown_device'); return fail(response, 404, 'DEVICE_UNKNOWN'); }
      verifyAssertion(input, { publicKeySpki: device.public_key_spki, challenge: input.challenge, origin: site.origin, rpId: site.rpId });
      if (device.status !== 'approved') {
        console.info(`device: unlock status=${device.status}`);
        return response.status(200).json({ deviceId: device.device_id, status: device.status, approved: false });
      }
      const expiresAt = new Date(Date.now() + SESSION_MINUTES * 60_000).toISOString();
      const { data: session, error: sessionError } = await client.from('vault_device_sessions')
        .insert({ device_id: device.device_id, owner_id: ownerId, session_jwk: jwk, expires_at: expiresAt })
        .select('session_id').single();
      if (sessionError) { console.error('device: 세션 저장 실패', sessionError.code ?? 'unknown'); return fail(response, 502, 'DEVICE_UNAVAILABLE'); }
      console.info('device: unlock status=approved');
      return response.status(200).json({ deviceId: device.device_id, status: 'approved', approved: true,
        sessionId: session.session_id, expiresAt });
    }
    return fail(response, 400, 'UNKNOWN_ACTION');
  } catch (error) {
    // 검증 실패 이유 코드만 남깁니다(값은 남기지 않음)
    console.info(`device: deny reason=${String(error?.message ?? 'invalid').slice(0, 40)}`);
    return fail(response, 400, 'DEVICE_PROOF_INVALID');
  }
}
