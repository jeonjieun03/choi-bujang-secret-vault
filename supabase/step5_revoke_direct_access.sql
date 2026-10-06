-- 5단계: 학습용 메모 테이블(public.vault_notes)의 직접 접근 권한 회수
-- 브라우저가 공개 키나 로그인 토큰으로 Supabase 자료 API(/rest/v1/vault_notes)를 직접 부르는 길을 닫습니다.
-- 메모 읽기·추가·수정·삭제는 이제 Vercel 서버 함수(/api/notes)만 합니다.
-- 서버 함수는 서버 전용 키(service_role)를 쓰므로 이 SQL의 영향을 받지 않습니다. service_role 권한은 바꾸지 않습니다.
-- 다른 테이블은 건드리지 않습니다. 한 덩어리로 실행되며, 중간에 오류가 나면 하나도 바뀌지 않습니다.

begin;

-- 1) RLS는 켜 둔 채로 유지 (혹시 권한이 다시 생겨도 정책이 막도록)
alter table public.vault_notes enable row level security;

-- 2) 직접 권한 회수: PUBLIC·anon·authenticated 모두
revoke all on table public.vault_notes from public, anon, authenticated;

commit;

-- 적용 전후 확인 쿼리
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
