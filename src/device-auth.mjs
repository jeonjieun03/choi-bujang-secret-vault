// 11단계: 기기 승인용 검증 함수(순수 함수). 키·토큰·서명 값은 로그나 응답에 넣지 않습니다.
// - 기기 열쇠 = 패스키(WebAuthn, ES256). 개인키는 기기(운영체제)가 보관하고, 서버에는 공개키(SPKI)만 저장합니다.
// - 등록(verifyRegistration)은 '대기'로 저장할 값만 만들고 승인하지 않습니다.
// - 잠금 해제(verifyAssertion)는 이 기기가 등록된 패스키를 실제로 가졌는지 확인합니다.
// - 승인 여부는 서버의 기기 명단과 판정기(decide)가 정합니다(api/device.js).
import { createHash, createHmac, createPublicKey, randomBytes, timingSafeEqual, verify } from 'node:crypto';

export const b64u = Object.freeze({
  enc: value => Buffer.from(value).toString('base64url'),
  dec: value => Buffer.from(String(value), 'base64url'),
});
const B64U = /^[A-Za-z0-9_-]{1,8192}$/u;
const sha256 = data => createHash('sha256').update(data).digest();
export const sha256Hex = text => createHash('sha256').update(text ?? '', 'utf8').digest('hex');

// 기기 ID: 패스키 자격 ID의 SHA-256 앞 16자리(판정기 deviceId 와 같은 16자리 소문자 16진수 모양)
export const deviceIdOf = credentialId => createHash('sha256').update(String(credentialId)).digest('hex').slice(0, 16);

// ── 일회용 확인 문구(challenge): 서버 전용 키로 서명한 짧은 문구(2분), 사용자·목적·묶을 값이 맞아야 통과
function challengeKey(secret) {
  if (typeof secret !== 'string' || !secret) throw new Error('challenge_key_missing');
  return createHmac('sha256', secret).update('aleph-vault-device-challenge-v1').digest();
}
export function issueChallenge(secret, { ownerId, purpose, bind = '', now = Date.now() }) {
  const body = b64u.enc(JSON.stringify({ o: ownerId, p: purpose, b: bind, e: now + 120_000, n: randomBytes(12).toString('base64url') }));
  return `${body}.${createHmac('sha256', challengeKey(secret)).update(body).digest('base64url')}`;
}
export function checkChallenge(secret, challenge, { ownerId, purpose, bind = '', now = Date.now() }) {
  if (typeof challenge !== 'string' || challenge.length > 600) return false;
  const [body, mac, extra] = challenge.split('.');
  if (!body || !mac || extra !== undefined || !B64U.test(body) || !B64U.test(mac)) return false;
  const expected = createHmac('sha256', challengeKey(secret)).update(body).digest();
  const got = b64u.dec(mac);
  if (got.length !== expected.length || !timingSafeEqual(got, expected)) return false;
  let payload;
  try { payload = JSON.parse(b64u.dec(body).toString('utf8')); } catch { return false; }
  return payload?.o === ownerId && payload.p === purpose && payload.b === bind
    && Number.isFinite(payload.e) && now <= payload.e;
}

// ── WebAuthn 공통: clientDataJSON 확인(종류·문구·출처)
function readClientData(clientDataB64, { type, challenge, origin }) {
  if (typeof clientDataB64 !== 'string' || !B64U.test(clientDataB64)) throw new Error('client_data_invalid');
  const raw = b64u.dec(clientDataB64);
  let data;
  try { data = JSON.parse(raw.toString('utf8')); } catch { throw new Error('client_data_invalid'); }
  if (data?.type !== type) throw new Error('client_data_type');
  if (data.challenge !== b64u.enc(Buffer.from(challenge, 'utf8'))) throw new Error('client_data_challenge');
  if (data.origin !== origin) throw new Error('client_data_origin');
  if (data.crossOrigin === true) throw new Error('client_data_cross_origin');
  return raw;
}

function p256Spki(spkiB64) {
  if (typeof spkiB64 !== 'string' || !B64U.test(spkiB64)) throw new Error('public_key_invalid');
  const key = createPublicKey({ key: b64u.dec(spkiB64), format: 'der', type: 'spki' });
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') throw new Error('public_key_not_p256');
  return key;
}

// 등록: 패스키 공개키(SPKI, ES256)와 clientData 를 확인합니다. 승인은 하지 않습니다(대기 상태로 저장할 값만 돌려줌).
export function verifyRegistration(input, { challenge, origin }) {
  readClientData(input?.clientDataJSON, { type: 'webauthn.create', challenge, origin });
  if (input.publicKeyAlgorithm !== -7) throw new Error('algorithm_not_es256');
  if (typeof input.credentialId !== 'string' || !B64U.test(input.credentialId) || input.credentialId.length > 1400) {
    throw new Error('credential_id_invalid');
  }
  p256Spki(input.publicKeySpki);
  return Object.freeze({ deviceId: deviceIdOf(input.credentialId), credentialId: input.credentialId, publicKeySpki: input.publicKeySpki });
}

// 잠금 해제: 패스키 서명(authenticatorData || SHA-256(clientDataJSON))을 저장된 공개키로 확인합니다.
export function verifyAssertion(input, { publicKeySpki, challenge, origin, rpId }) {
  const clientData = readClientData(input?.clientDataJSON, { type: 'webauthn.get', challenge, origin });
  if (typeof input.authenticatorData !== 'string' || !B64U.test(input.authenticatorData)) throw new Error('authenticator_data_invalid');
  if (typeof input.signature !== 'string' || !B64U.test(input.signature)) throw new Error('signature_invalid');
  const authData = b64u.dec(input.authenticatorData);
  if (authData.length < 37) throw new Error('authenticator_data_invalid');
  if (!authData.subarray(0, 32).equals(sha256(Buffer.from(rpId, 'utf8')))) throw new Error('rp_id_mismatch');
  if ((authData[32] & 0x01) === 0) throw new Error('user_not_present');
  const ok = verify('sha256', Buffer.concat([authData, sha256(clientData)]), p256Spki(publicKeySpki), b64u.dec(input.signature));
  if (!ok) throw new Error('assertion_signature_invalid');
  return true;
}
