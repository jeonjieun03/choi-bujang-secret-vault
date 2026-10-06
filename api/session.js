import { createClient } from '@supabase/supabase-js';

// 로그인 세션 서버 함수: 브라우저는 Supabase 키를 갖지 않고 이 함수에만 요청합니다.
//   POST /api/session {action:'login', email, password} → {access_token, refresh_token, expires_at, email}
//   POST /api/session {action:'refresh', refresh_token}  → 새 세션 (같은 모양)
//   POST /api/session {action:'logout'} + Authorization  → 204 (서버에서 세션 폐기)
// 공식 SDK(@supabase/supabase-js)의 Auth 흐름만 사용하며 비밀번호·JWT를 직접 만들지 않습니다.
// SUPABASE_SECRET_KEY는 서버 전용이며 응답·로그에 넣지 않습니다. 비밀번호와 토큰도 기록하지 않습니다.

const EMAIL_MAX = 254;
const PASSWORD_MAX = 256;
const TOKEN_MAX = 8192;
const BEARER = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/u;

function readJson(request) {
  const raw = request.body;
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) return raw;
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
    } catch { return null; }
  }
  return null;
}

const fail = (response, status, error, message) =>
  response.status(status).json(message ? { error, message } : { error });

function sessionBody(session) {
  return {
    access_token: session.access_token,
    refresh_token: session.refresh_token,
    expires_at: session.expires_at,
    email: session.user?.email ?? null,
  };
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return fail(response, 405, 'METHOD_NOT_ALLOWED');
  }

  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) {
    console.error('session: 서버 환경변수가 설정되지 않았습니다.');
    return fail(response, 500, 'SERVER_NOT_CONFIGURED');
  }
  const supabase = createClient(url, secretKey, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  });

  const input = readJson(request);
  if (!input) return fail(response, 400, 'INVALID_JSON');

  if (input.action === 'login') {
    const { email, password } = input;
    if (typeof email !== 'string' || !email.trim() || email.length > EMAIL_MAX
        || typeof password !== 'string' || !password || password.length > PASSWORD_MAX) {
      return fail(response, 400, 'validation_failed', '이메일과 비밀번호를 확인하세요.');
    }
    const { data, error } = await supabase.auth.signInWithPassword({ email: email.trim(), password });
    if (error || !data?.session) {
      const status = error?.status === 429 ? 429 : 401;
      return fail(response, status, error?.code ?? 'login_failed', error?.message ?? 'Login failed');
    }
    return response.status(200).json(sessionBody(data.session));
  }

  if (input.action === 'refresh') {
    const token = input.refresh_token;
    if (typeof token !== 'string' || !token || token.length > TOKEN_MAX) {
      return fail(response, 400, 'INVALID_REFRESH_TOKEN');
    }
    const { data, error } = await supabase.auth.refreshSession({ refresh_token: token });
    if (error || !data?.session) return fail(response, 401, 'SESSION_EXPIRED');
    return response.status(200).json(sessionBody(data.session));
  }

  if (input.action === 'logout') {
    const match = BEARER.exec(request.headers?.authorization ?? '');
    if (match) {
      const { error } = await supabase.auth.admin.signOut(match[1], 'local');
      if (error) console.error('session: 로그아웃 처리 실패', error.code ?? 'unknown');
    }
    return response.status(204).end();
  }

  return fail(response, 400, 'UNKNOWN_ACTION');
}
