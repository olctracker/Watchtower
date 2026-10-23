-- =========================================================
-- Watchtower — record every OLC Database app open (option 2)
-- The app calls log_app_open() quietly in the background when it
-- opens or comes back to the screen. To keep the log small, a new
-- entry is only written when the member's IP changed, or it's been
-- an hour since their last entry.
-- =========================================================

-- allow the new "open" entry type
alter table public.login_log drop constraint if exists login_log_result_check;
alter table public.login_log add constraint login_log_result_check
  check (result in ('ok', 'wrong_pin', 'locked', 'unknown_user', 'open'));

create index if not exists login_log_uid_idx on public.login_log (user_id, at desc);

create or replace function public.log_app_open()
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  h      json;
  v_ip   text;
  v_name text;
  l_ip   text;
  l_at   timestamptz;
begin
  if auth.uid() is null then return; end if;
  select username into v_name from profiles where id = auth.uid();
  if v_name is null then return; end if;          -- OLC Database members only

  begin h := nullif(current_setting('request.headers', true), '')::json;
  exception when others then h := null; end;
  v_ip := nullif(trim(coalesce(h ->> 'cf-connecting-ip', h ->> 'x-real-ip',
            split_part(h ->> 'x-forwarded-for', ',', 1))), '');

  select ip, at into l_ip, l_at
  from login_log
  where user_id = auth.uid() and site = 'olc' and result in ('ok', 'open')
  order by at desc limit 1;

  -- same IP and under an hour since the last entry → nothing new to record
  if l_at is not null and l_ip is not distinct from v_ip and l_at > now() - interval '1 hour' then
    return;
  end if;

  insert into login_log (site, username, user_id, result, ip, user_agent)
  values ('olc', v_name, auth.uid(), 'open', v_ip, left(h ->> 'user-agent', 300));
exception when others then
  null;  -- never let this affect the app
end;
$$;

revoke all on function public.log_app_open() from public, anon;
grant execute on function public.log_app_open() to authenticated;
