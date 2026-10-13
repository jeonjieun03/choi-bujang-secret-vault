-- BYTE BACK 방어전 8단계 제작 3: 강사 명단(공지 수정 권한)
-- 학습용 Supabase SQL Editor에서 한 번 실행합니다. 여러 번 실행해도 안전합니다.
-- 공지 수정 API는 이 표에 검증된 사용자 ID가 있을 때만 허용합니다. 화면 메뉴나 요청 본문의 role은 쓰지 않습니다.
-- 이번에는 강사를 한 명도 넣지 않습니다. 그래서 A·B 같은 학생 계정의 공지 수정은 모두 거부됩니다.

create table if not exists public.vault_instructors (
  user_id    uuid primary key,
  created_at timestamptz not null default now()
);

alter table public.vault_instructors enable row level security;
revoke all on table public.vault_instructors from public, anon, authenticated;

-- (선택) 강사 시험 계정을 따로 만들었다면, 아래 줄의 앞 '--'를 지우고 그 계정 이메일을 넣어 실행합니다.
-- 학생 A·B 계정은 넣지 마세요.
-- insert into public.vault_instructors (user_id) select id from auth.users where email = '강사계정이메일' on conflict do nothing;

-- 확인
select
  (select count(*) from public.vault_instructors) as instructor_count,
  (select relrowsecurity from pg_class where oid = 'public.vault_instructors'::regclass) as rls_enabled,
  has_table_privilege('anon', 'public.vault_instructors', 'select') as anon_can_select,
  has_table_privilege('authenticated', 'public.vault_instructors', 'select') as authenticated_can_select;
