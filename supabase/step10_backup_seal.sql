-- BYTE BACK 방어전 10단계 보강: 메모 사본 봉인 표
-- step10_note_backup.sql 을 실행한 뒤, 학습용 Supabase SQL Editor에서 한 번 실행합니다. 여러 번 실행해도 안전합니다.
-- 봉인은 서버 함수가 서버 전용 키로 계산해 넣습니다. 이 파일에는 키·메모 본문·이메일이 없습니다.
-- 이 표가 생긴 뒤에 새로 만든 메모만 봉인이 있고, 봉인이 없는 사본은 복원하지 않습니다(멈춤).

create table if not exists public.vault_notes_backup_seal (
  note_id   uuid primary key,
  owner_id  uuid not null,
  seal      text not null check (seal ~ '^[0-9a-f]{64}$'),
  sealed_at timestamptz not null default now()
);
alter table public.vault_notes_backup_seal enable row level security;
revoke all on table public.vault_notes_backup_seal from public, anon, authenticated;

-- 봉인도 한 번 쓰면 고치거나 지울 수 없습니다(step10_note_backup.sql 의 vault_block_change 함수 사용).
drop trigger if exists vault_notes_backup_seal_no_change on public.vault_notes_backup_seal;
create trigger vault_notes_backup_seal_no_change before update or delete on public.vault_notes_backup_seal
  for each row execute function public.vault_block_change();

-- 확인
select
  (select count(*) from public.vault_notes_backup)      as backup_count,
  (select count(*) from public.vault_notes_backup_seal) as seal_count,
  (select relrowsecurity from pg_class where oid = 'public.vault_notes_backup_seal'::regclass) as seal_rls,
  has_table_privilege('authenticated', 'public.vault_notes_backup_seal', 'select') as authenticated_can_read_seal;
