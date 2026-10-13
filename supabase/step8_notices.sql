-- BYTE BACK 방어전 8단계 제작 1: 강사 공지 테이블(구역 instructor_notices)
-- 학습용 Supabase SQL Editor에서 한 번 실행합니다. 여러 번 실행해도 안전합니다.
-- 메모 테이블(vault_notes)과 다른 테이블이며, 공지마다 자원 ID notice:<notice_id> 로 구별합니다.
-- 공지 내용은 실습용 가상 문장입니다. 이메일이나 키는 넣지 않습니다.

create table if not exists public.vault_notices (
  id         bigint generated always as identity primary key,
  notice_id  uuid not null unique default gen_random_uuid(),
  title      text not null,
  content    text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- 5단계와 같은 원칙: RLS 켬, 브라우저용 역할의 직접 권한 없음(서버 함수만 접근)
alter table public.vault_notices enable row level security;
revoke all on table public.vault_notices from public, anon, authenticated;

-- 가상 공지 2건 (이미 있으면 건너뜀)
insert into public.vault_notices (title, content)
select v.title, v.content
from (values
  ('가상 공지 1', '실습용 가상 공지입니다. 3주차 과제 제출 안내'),
  ('가상 공지 2', '실습용 가상 공지입니다. 다음 수업 장소 안내')
) as v(title, content)
where not exists (select 1 from public.vault_notices n where n.title = v.title);

-- 확인
select
  (select count(*) from public.vault_notices) as notice_count,
  (select relrowsecurity from pg_class where oid = 'public.vault_notices'::regclass) as rls_enabled,
  has_table_privilege('anon', 'public.vault_notices', 'select') as anon_can_select,
  has_table_privilege('authenticated', 'public.vault_notices', 'select') as authenticated_can_select,
  (select count(*) from public.vault_notes) as note_count_unchanged;
