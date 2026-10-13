-- BYTE BACK 방어전 11단계: 기기 명단(등록 기기)과 기기 세션 표
-- 학습용 Supabase SQL Editor에서 한 번 실행합니다. 여러 번 실행해도 안전합니다(이전에 만든 같은 이름의 표도 맞춰 고칩니다).
-- 이 파일에는 키·메모 본문·이메일이 없습니다. 기기 명단에는 패스키 공개키만 저장합니다(개인키는 기기에만 있음).
--
-- 승인 흐름: 화면의 "이 기기 승인 요청" → vault_devices 에 status='pending' 줄이 생김(버튼만으로는 승인되지 않음)
--   → 서버 쪽 명단에서 status 를 approved 로 바꿈 → "승인 확인"에서 서버가 패스키를 확인하고 명단을 본 뒤
--   판정기(decide)에 deviceRegistered 를 넣어 allow 일 때만 기기 세션(30분)을 줌 → 그때만 자료실이 열림.

create table if not exists public.vault_devices (
  device_id       text primary key check (device_id ~ '^[0-9a-f]{16}$'),
  owner_id        uuid not null,
  credential_id   text not null unique,
  public_key_spki text not null,
  status          text not null default 'pending' check (status in ('pending', 'approved', 'revoked')),
  created_at      timestamptz not null default now(),
  approved_at     timestamptz
);

create table if not exists public.vault_device_sessions (
  session_id uuid primary key default gen_random_uuid(),
  device_id  text not null references public.vault_devices (device_id),
  owner_id   uuid not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);
-- 이전 시도에서 만든 표에 남은 칸·표 정리(이번 설계에서는 쓰지 않음)
alter table public.vault_device_sessions drop column if exists session_jwk;
drop table if exists public.vault_request_nonces;

alter table public.vault_devices enable row level security;
alter table public.vault_device_sessions enable row level security;
revoke all on table public.vault_devices from public, anon, authenticated;
revoke all on table public.vault_device_sessions from public, anon, authenticated;

-- 기기 줄은 상태만 바꿀 수 있습니다(공개키·주인·자격 ID 는 등록 뒤 고정). 승인 시각은 자동 기록.
create or replace function public.vault_device_guard() returns trigger
language plpgsql set search_path = '' as $$
begin
  if new.device_id is distinct from old.device_id or new.owner_id is distinct from old.owner_id
     or new.credential_id is distinct from old.credential_id or new.public_key_spki is distinct from old.public_key_spki then
    raise exception 'device_identity_is_fixed';
  end if;
  if new.status = 'approved' and old.status is distinct from 'approved' then
    new.approved_at := now();
  elsif new.status <> 'approved' then
    new.approved_at := null;
  end if;
  return new;
end;
$$;
drop trigger if exists vault_devices_guard on public.vault_devices;
create trigger vault_devices_guard before update on public.vault_devices
  for each row execute function public.vault_device_guard();

-- 확인
select
  (select count(*) from public.vault_devices) as device_count,
  (select relrowsecurity from pg_class where oid = 'public.vault_devices'::regclass) as devices_rls,
  has_table_privilege('authenticated', 'public.vault_devices', 'select') as authenticated_can_read_devices,
  exists (select 1 from information_schema.columns where table_name = 'vault_device_sessions' and column_name = 'session_jwk') as old_column_left;
