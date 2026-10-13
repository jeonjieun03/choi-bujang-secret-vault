-- BYTE BACK 방어전 10단계: DB 안에서 "사본 다시 읽기 → 검증 → 복원 → 다시 대조"를 한 번에 하는 복원 함수
-- step10_note_backup.sql, step10_backup_seal.sql 을 실행한 뒤 학습용 Supabase SQL Editor에서 한 번 실행합니다.
-- 여러 번 실행해도 안전합니다. 이 파일에는 키·메모 본문·이메일이 없습니다.
--
-- public.vault_restore_note(메모 ID, 소유자 ID, 미리 보기 여부, 미리 본 사본 해시)
--  1) 사본을 DB에서 다시 읽습니다. 없으면 멈춤(backup_missing).
--  2) 사본 내용으로 해시를 다시 계산해 저장된 해시와 비교합니다. 다르면 멈춤(backup_unverified).
--  3) 봉인 기록이 없으면 멈춤(backup_unsealed). 봉인 값(서버 키 HMAC)은 서버 함수가 먼저 확인합니다.
--  4) 미리 본 사본 해시가 주어졌는데 다르면 멈춤(backup_changed).
--  5) 미리 보기면 사본 버전(사본을 뜬 시각)과 바뀔 항목만 돌려주고 아무것도 쓰지 않습니다.
--  6) 지정한 한 건만 복원한 뒤 다시 읽어 ID·소유자·내용 해시를 대조하고, 하나라도 다르면 예외로
--     이 함수 안의 변경 전체를 취소합니다(검증 실패한 복원은 남지 않음).
--  멈춤·미리 보기·복원은 감사 기록(vault_restore_audit)에 한 줄씩 남깁니다(본문 없이 해시만).
--  메모 원본 표와 다른 메모, 사본·봉인·감사 기록의 기존 줄은 바꾸지 않습니다.

create or replace function public.vault_restore_note(
  p_note_id uuid,
  p_owner_id uuid,
  p_preview boolean default false,
  p_expect_sha256 text default null
) returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  b public.vault_notes_backup%rowtype;
  cur public.vault_notes%rowtype;
  cur_found boolean;
  aft public.vault_notes%rowtype;
  aft_found boolean;
  backup_sha text;
  after_sha text;
  prev text;
  changed text[] := array[]::text[];
begin
  -- 1) 사본 다시 읽기
  select * into b from public.vault_notes_backup
   where note_id = p_note_id and owner_id = p_owner_id;
  if not found then
    insert into public.vault_restore_audit (note_id, owner_id, action, result)
    values (p_note_id, p_owner_id, 'restore_note', 'stopped_backup_missing');
    return jsonb_build_object('status', 'stopped', 'reason', 'backup_missing');
  end if;

  -- 2) 사본 해시 다시 계산·대조
  backup_sha := encode(sha256(convert_to(b.title || chr(31) || b.content, 'UTF8')), 'hex');
  if backup_sha <> b.content_sha256 then
    insert into public.vault_restore_audit (note_id, owner_id, action, result, backup_sha256)
    values (p_note_id, p_owner_id, 'restore_note', 'stopped_backup_unverified', b.content_sha256);
    return jsonb_build_object('status', 'stopped', 'reason', 'backup_unverified');
  end if;

  -- 3) 봉인 기록 확인
  if not exists (select 1 from public.vault_notes_backup_seal s
                  where s.note_id = p_note_id and s.owner_id = p_owner_id) then
    insert into public.vault_restore_audit (note_id, owner_id, action, result, backup_sha256)
    values (p_note_id, p_owner_id, 'restore_note', 'stopped_backup_unsealed', backup_sha);
    return jsonb_build_object('status', 'stopped', 'reason', 'backup_unsealed');
  end if;

  -- 4) 미리 본 사본과 같은지
  if p_expect_sha256 is not null and p_expect_sha256 <> backup_sha then
    insert into public.vault_restore_audit (note_id, owner_id, action, result, backup_sha256)
    values (p_note_id, p_owner_id, 'restore_note', 'stopped_backup_changed', backup_sha);
    return jsonb_build_object('status', 'stopped', 'reason', 'backup_changed');
  end if;

  -- 지금 상태
  select * into cur from public.vault_notes where note_id = p_note_id;
  cur_found := found;
  if cur_found and cur.owner_id is distinct from p_owner_id then
    insert into public.vault_restore_audit (note_id, owner_id, action, result, backup_sha256)
    values (p_note_id, p_owner_id, 'restore_note', 'stopped_owner_mismatch', backup_sha);
    return jsonb_build_object('status', 'stopped', 'reason', 'not_found');
  end if;
  if not cur_found then
    prev := 'deleted';
    changed := array['note'];
  else
    if cur.title is distinct from b.title then changed := array_append(changed, 'title'); end if;
    if cur.content is distinct from b.content then changed := array_append(changed, 'body'); end if;
    prev := case when cardinality(changed) = 0 then 'unchanged' else 'tampered' end;
  end if;

  -- 5) 미리 보기: 쓰지 않음
  if p_preview then
    insert into public.vault_restore_audit (note_id, owner_id, action, result, previous_state, backup_sha256)
    values (p_note_id, p_owner_id, 'restore_note', 'previewed', prev, backup_sha);
    return jsonb_build_object('status', 'preview', 'previous', prev, 'changes', to_jsonb(changed),
      'backupVersion', b.backed_up_at, 'backupSha256', backup_sha, 'backupVerified', true);
  end if;

  -- 6) 지정한 한 건만 복원
  if prev = 'tampered' then
    update public.vault_notes
       set title = b.title, content = b.content, updated_at = now()
     where note_id = p_note_id and owner_id = p_owner_id;
  elsif prev = 'deleted' then
    insert into public.vault_notes (note_id, owner_id, title, content)
    values (p_note_id, p_owner_id, b.title, b.content);
  end if;

  -- 다시 읽어 대조: 다르면 예외로 이 함수의 변경 전체 취소
  select * into aft from public.vault_notes where note_id = p_note_id and owner_id = p_owner_id;
  aft_found := found;
  after_sha := case when aft_found
    then encode(sha256(convert_to(aft.title || chr(31) || aft.content, 'UTF8')), 'hex') end;
  if not aft_found or after_sha is distinct from backup_sha or aft.owner_id is distinct from b.owner_id then
    raise exception 'restore_verify_failed';
  end if;

  insert into public.vault_restore_audit (note_id, owner_id, action, result, previous_state, backup_sha256, restored_sha256)
  values (p_note_id, p_owner_id, 'restore_note', 'restored', prev, backup_sha, after_sha);
  return jsonb_build_object('status', 'restored', 'previous', prev, 'changes', to_jsonb(changed),
    'backupVersion', b.backed_up_at, 'backupSha256', backup_sha, 'backupVerified', true,
    'restoredSha256', after_sha,
    'matches', jsonb_build_object('id', aft.note_id = b.note_id, 'owner', aft.owner_id = b.owner_id,
                                  'contentSha256', after_sha = b.content_sha256));
end;
$$;

-- 서버 함수(서버 전용 키)만 실행할 수 있습니다. 브라우저용 역할은 실행 불가.
revoke all on function public.vault_restore_note(uuid, uuid, boolean, text) from public, anon, authenticated;
grant execute on function public.vault_restore_note(uuid, uuid, boolean, text) to service_role;

-- 확인
select
  exists (select 1 from pg_proc where proname = 'vault_restore_note') as restore_function_exists,
  has_function_privilege('anon', 'public.vault_restore_note(uuid, uuid, boolean, text)', 'execute') as anon_can_execute,
  has_function_privilege('authenticated', 'public.vault_restore_note(uuid, uuid, boolean, text)', 'execute') as authenticated_can_execute;
