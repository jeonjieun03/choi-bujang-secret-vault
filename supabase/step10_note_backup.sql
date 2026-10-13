-- BYTE BACK 방어전 10단계 제작 3: 비공개 가상 메모 사본 + 복원 감사 기록
-- 학습용 Supabase SQL Editor에서 한 번 실행합니다. 여러 번 실행해도 안전합니다.
-- 이 파일에는 메모 본문·이메일·키가 없습니다. 사본은 DB 안에만 두고 Git·제출 묶음에 넣지 않습니다.

-- 1) 비공개 메모 사본: 메모 ID·소유자·제목·내용·내용 해시. 브라우저용 역할은 접근 불가(서버 함수만).
create table if not exists public.vault_notes_backup (
  note_id        uuid primary key,
  owner_id       uuid not null,
  title          text not null,
  content        text not null,
  content_sha256 text not null check (content_sha256 ~ '^[0-9a-f]{64}$'),
  backed_up_at   timestamptz not null default now()
);
alter table public.vault_notes_backup enable row level security;
revoke all on table public.vault_notes_backup from public, anon, authenticated;

-- 2) 복원 감사 기록: 추가만 가능(수정·삭제는 트리거가 막음). 메모 본문은 남기지 않고 해시만 남깁니다.
create table if not exists public.vault_restore_audit (
  id              bigint generated always as identity primary key,
  at              timestamptz not null default now(),
  note_id         uuid not null,
  owner_id        uuid not null,
  action          text not null,
  result          text not null,
  previous_state  text,
  backup_sha256   text,
  restored_sha256 text
);
alter table public.vault_restore_audit enable row level security;
revoke all on table public.vault_restore_audit from public, anon, authenticated;

-- 3) 사본·감사 기록은 한 번 쓰면 고치거나 지울 수 없습니다(서버 키로도).
create or replace function public.vault_block_change() returns trigger
language plpgsql set search_path = '' as $$
begin
  raise exception 'append-only table: % on %', tg_op, tg_table_name;
end;
$$;
drop trigger if exists vault_notes_backup_no_change on public.vault_notes_backup;
create trigger vault_notes_backup_no_change before update or delete on public.vault_notes_backup
  for each row execute function public.vault_block_change();
drop trigger if exists vault_restore_audit_no_change on public.vault_restore_audit;
create trigger vault_restore_audit_no_change before update or delete on public.vault_restore_audit
  for each row execute function public.vault_block_change();

-- 4) 침해 전 사본 뜨기: 지금 있는 메모를 사본에 넣습니다(이미 사본이 있는 메모는 건너뜀).
--    내용 해시 = SHA-256(제목 + 구분 문자(코드 31) + 내용), 서버 함수와 같은 방식입니다.
insert into public.vault_notes_backup (note_id, owner_id, title, content, content_sha256)
select n.note_id, n.owner_id, n.title, n.content,
       encode(sha256(convert_to(n.title || chr(31) || n.content, 'UTF8')), 'hex')
from public.vault_notes n
where n.owner_id is not null
on conflict (note_id) do nothing;

-- 5) 확인 (메모 본문은 보여 주지 않습니다)
select
  (select count(*) from public.vault_notes)          as note_count,
  (select count(*) from public.vault_notes_backup)   as backup_count,
  (select count(*) from public.vault_restore_audit)  as audit_count,
  (select relrowsecurity from pg_class where oid = 'public.vault_notes_backup'::regclass) as backup_rls,
  has_table_privilege('authenticated', 'public.vault_notes_backup', 'select') as authenticated_can_read_backup;
