import { createClient } from '@supabase/supabase-js';

// 2단계: 학습용 Supabase의 vault_notes에서 가상 메모를 읽는 서버 함수.
// SUPABASE_SECRET_KEY는 서버 전용입니다. 브라우저 파일·응답·로그에 넣지 않습니다.
// 약점(의도적으로 남김): 아직 로그인 검사가 없어 이 주소를 누구나 부를 수 있습니다.
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

  const supabase = createClient(url, secretKey, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  });

  const { data, error } = await supabase
    .from('vault_notes')
    .select('title, content')
    .order('id', { ascending: true });

  if (error) {
    // 오류 코드만 남기고 키·요청 내용은 기록하지 않습니다.
    console.error('notes: 자료를 읽지 못했습니다.', error.code ?? 'unknown');
    return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
  }

  return response.status(200).json({ notes: data ?? [] });
}
