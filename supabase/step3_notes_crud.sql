-- BYTE BACK 방어전 3단계: 메모 추가·수정·삭제 API를 위한 칸 추가
-- 학습용 Supabase 프로젝트의 SQL Editor에서 한 번 실행합니다. 여러 번 실행해도 안전합니다.
-- 이 파일에는 메모 본문, 이메일, 키가 없습니다. 실행 전에 아래 'A계정이메일'만 바꿔 넣으세요(파일에는 저장하지 마세요).

-- 1) API에서 쓰는 메모 ID(UUID). 기존 숫자 id는 그대로 둡니다.
alter table public.vault_notes
  add column if not exists note_id uuid not null default gen_random_uuid();
create unique index if not exists vault_notes_note_id_key on public.vault_notes (note_id);

-- 2) 마지막 수정 시각
alter table public.vault_notes
  add column if not exists updated_at timestamptz not null default now();

-- 3) 주인이 없는 기존 가상 메모 네 건을 A 계정 소유로 지정합니다.
--    목록 API는 로그인 사용자의 메모만 돌려주므로, 이 단계를 해야 A 화면에 기존 카드가 보입니다.
update public.vault_notes
set owner_id = (select id from auth.users where email = 'A계정이메일')
where owner_id is null
  and exists (select 1 from auth.users where email = 'A계정이메일');

-- 4) 권한은 2단계와 같습니다: RLS 켬, anon·authenticated는 직접 접근 불가(서버 함수만 접근).
alter table public.vault_notes enable row level security;
revoke all on table public.vault_notes from anon, authenticated;

-- 5) 확인용 조회
select
  (select count(*) from public.vault_notes)                         as note_count,
  (select count(*) from public.vault_notes where owner_id is null)  as notes_without_owner,
  (select count(distinct note_id) from public.vault_notes)          as distinct_note_ids,
  (select relrowsecurity from pg_class where oid = 'public.vault_notes'::regclass) as rls_enabled,
  has_table_privilege('anon', 'public.vault_notes', 'select')          as anon_can_select,
  has_table_privilege('authenticated', 'public.vault_notes', 'select') as authenticated_can_select;
