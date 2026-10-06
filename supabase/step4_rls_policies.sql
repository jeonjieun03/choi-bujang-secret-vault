-- ② 메모 테이블(public.vault_notes)에 RLS와 최소 권한 적용
-- 다른 테이블은 건드리지 않습니다. 전체가 한 덩어리로 실행되며, 중간에 오류가 나면 하나도 바뀌지 않습니다.
-- 여러 번 실행해도 결과가 같습니다.
-- 참고: 서버 API는 서버 전용 키(service_role)로 접근하며, 이 SQL은 service_role 권한을 바꾸지 않습니다.

begin;

-- 1) RLS 켜기 (이미 켜져 있어도 그대로)
alter table public.vault_notes enable row level security;

-- 2) 기존 권한 회수
revoke all on table public.vault_notes from public, anon, authenticated;

-- 3) 로그인 사용자(authenticated)에게 필요한 네 가지만 부여
grant select, insert, update, delete on table public.vault_notes to authenticated;

-- 4) 행 단위 정책: 모두 "로그인한 본인 = 메모 주인"일 때만
drop policy if exists vault_notes_select_own on public.vault_notes;
drop policy if exists vault_notes_insert_own on public.vault_notes;
drop policy if exists vault_notes_update_own on public.vault_notes;
drop policy if exists vault_notes_delete_own on public.vault_notes;

-- 읽기: 기존 행이 본인 것일 때만 (USING)
create policy vault_notes_select_own on public.vault_notes
  for select to authenticated
  using ((select auth.uid()) = owner_id);

-- 추가: 새 행의 주인이 본인일 때만 (WITH CHECK)
create policy vault_notes_insert_own on public.vault_notes
  for insert to authenticated
  with check ((select auth.uid()) = owner_id);

-- 수정: 기존 행이 본인 것이고(USING), 고친 뒤 새 행도 본인 것일 때만(WITH CHECK)
create policy vault_notes_update_own on public.vault_notes
  for update to authenticated
  using ((select auth.uid()) = owner_id)
  with check ((select auth.uid()) = owner_id);

-- 삭제: 기존 행이 본인 것일 때만 (USING)
create policy vault_notes_delete_own on public.vault_notes
  for delete to authenticated
  using ((select auth.uid()) = owner_id);

commit;

-- 적용 후 확인 쿼리
-- (A) information_schema.role_table_grants: 역할별로 실제 부여된 권한
select 'role_table_grants' as source, grantee as role,
       string_agg(privilege_type, ', ' order by privilege_type) as privileges
from information_schema.role_table_grants
where table_schema = 'public' and table_name = 'vault_notes'
  and grantee in ('PUBLIC', 'anon', 'authenticated', 'service_role')
group by grantee

union all

-- (B) has_table_privilege: 상속까지 포함한 실제 권한 (true인 것만 표시)
select 'has_table_privilege', r.role,
       coalesce(nullif(concat_ws(', ',
         case when has_table_privilege(r.role, 'public.vault_notes', 'SELECT')     then 'SELECT' end,
         case when has_table_privilege(r.role, 'public.vault_notes', 'INSERT')     then 'INSERT' end,
         case when has_table_privilege(r.role, 'public.vault_notes', 'UPDATE')     then 'UPDATE' end,
         case when has_table_privilege(r.role, 'public.vault_notes', 'DELETE')     then 'DELETE' end,
         case when has_table_privilege(r.role, 'public.vault_notes', 'TRUNCATE')   then 'TRUNCATE' end,
         case when has_table_privilege(r.role, 'public.vault_notes', 'REFERENCES') then 'REFERENCES' end,
         case when has_table_privilege(r.role, 'public.vault_notes', 'TRIGGER')    then 'TRIGGER' end
       ), ''), '(권한 없음)')
from (values ('anon'), ('authenticated'), ('service_role')) as r(role)

union all

-- (C) RLS 상태와 정책 목록
select 'rls', 'vault_notes',
       case when relrowsecurity then 'RLS 켜짐' else 'RLS 꺼짐' end
from pg_class where oid = 'public.vault_notes'::regclass

union all

select 'policy', policyname,
       cmd || ' → ' || array_to_string(roles, ',')
       || coalesce(' | USING ' || qual, '') || coalesce(' | WITH CHECK ' || with_check, '')
from pg_policies
where schemaname = 'public' and tablename = 'vault_notes'

order by 1, 2;
