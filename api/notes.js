import { createRequire } from 'node:module';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';

const require = createRequire(import.meta.url);
const config = require('../aleph.config.json');

// 3단계: 학습용 Supabase의 vault_notes를 읽기 전에 요청의 로그인 토큰을 검사합니다.
// 토큰 검사는 시작 틀의 src/verify-login.mjs만 사용합니다.
// 브라우저가 보낸 userId·role 같은 값은 읽지 않습니다. 신원은 검증된 토큰에서만 나옵니다.
// SUPABASE_SECRET_KEY는 서버 전용이며 브라우저 파일·응답·로그에 넣지 않습니다.
// 남은 약점: 로그인한 사람은 아직 모든 가상 메모를 봅니다(타인 자료 차단은 4단계).

let verifier = null;
function getVerifier(secretKey) {
  verifier ??= createLoginVerifier({ config, supabaseSecretKey: secretKey });
  return verifier;
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');

  if (request.method && request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) {
    console.error('notes: 서버 환경변수가 설정되지 않았습니다.');
    return response.status(500).json({ error: 'SERVER_NOT_CONFIGURED' });
  }

  let verify;
  try {
    verify = getVerifier(secretKey);
  } catch (error) {
    console.error('notes: 로그인 검사 설정이 올바르지 않습니다.', error?.message ?? 'unknown');
    return response.status(500).json({ error: 'LOGIN_NOT_CONFIGURED' });
  }

  const authorization = request.headers?.authorization;
  if (!authorization) {
    response.setHeader('WWW-Authenticate', 'Bearer');
    return response.status(401).json({ error: 'LOGIN_REQUIRED' });
  }

  const identity = await verify(authorization);
  if (!identity) {
    response.setHeader('WWW-Authenticate', 'Bearer error="invalid_token"');
    return response.status(401).json({ error: 'INVALID_LOGIN' });
  }

  const supabase = createClient(url, secretKey, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  });

  const { data, error } = await supabase
    .from('vault_notes')
    .select('title, content')
    .order('id', { ascending: true });

  if (error) {
    // 오류 코드만 남기고 키·토큰·요청 내용은 기록하지 않습니다.
    console.error('notes: 자료를 읽지 못했습니다.', error.code ?? 'unknown');
    return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
  }

  return response.status(200).json({ notes: data ?? [] });
}
