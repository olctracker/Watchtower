-- =========================================================
-- Watchtower — login logging for OLC Database
-- Run once in Supabase → SQL Editor (olc-database project).
-- Safe to run again. No changes to the OLC Database app needed:
-- it wraps the existing login_check / login_failed / login_ok
-- functions so every attempt gets recorded with its IP.
-- =========================================================

-- 1) The log table -------------------------------------------------
create table if not exists public.login_log (
  id          bigint generated always as identity primary key,
  at          timestamptz not null default now(),
  site        text not null default 'olc',
  username    text not null,
  user_id     uuid,
  result      text not null check (result in ('ok', 'wrong_pin', 'locked', 'unknown_user')),
  ip          text,
  user_agent  text
);
create index if not exists login_log_at_idx   on public.login_log (at desc);
create index if not exists login_log_user_idx on public.login_log (lower(username), at desc);
create index if not exists login_log_ip_idx   on public.login_log (ip);

-- Only the Admin can read it. Nobody can write to it directly;
-- rows only come from the login functions below.
alter table public.login_log enable row level security;
drop policy if exists "admin reads login log" on public.login_log;
create policy "admin reads login log" on public.login_log
  for select to authenticated
  using (exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin'));
revoke all on public.login_log from anon, authenticated;
grant select on public.login_log to authenticated;

-- 2) Recorder (reads the caller's IP from the request headers) ------
create or replace function public._log_login(p_username text, p_result text, p_uid uuid default null)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  h       json;
  v_ip    text;
  v_uid   uuid := p_uid;
  v_name  text := left(trim(coalesce(p_username, '')), 40);
  f_id    uuid;
  f_name  text;
begin
  begin
    h := nullif(current_setting('request.headers', true), '')::json;
  exception when others then h := null;
  end;
  v_ip := nullif(trim(coalesce(
            h ->> 'cf-connecting-ip',
            h ->> 'x-real-ip',
            split_part(h ->> 'x-forwarded-for', ',', 1))), '');

  if v_uid is not null then
    select username into f_name from profiles where id = v_uid;
    v_name := coalesce(f_name, v_name);
  elsif v_name <> '' then
    select id, username into f_id, f_name from profiles where lower(username) = lower(v_name) limit 1;
    if f_id is null and p_result = 'wrong_pin' then
      p_result := 'unknown_user';
    end if;
    v_uid  := f_id;
    v_name := coalesce(f_name, v_name);
  end if;

  if v_name = '' then return; end if;

  insert into login_log (username, user_id, result, ip, user_agent)
  values (v_name, v_uid, p_result, v_ip, left(h ->> 'user-agent', 300));
exception when others then
  -- never let logging break a login
  null;
end;
$$;
revoke all on function public._log_login(text, text, uuid) from public, anon, authenticated;

-- 3) Wrap the existing login functions ------------------------------
-- The originals are kept as *_core and still do all the real work
-- (lockouts, tries left, etc). The wrappers just log, then call them.
do $do$
declare
  rt text;
begin
  -- login_check(p_username) → seconds still locked; log when locked
  if to_regprocedure('public.login_check_core(text)') is null then
    alter function public.login_check(text) rename to login_check_core;
  end if;
  rt := pg_get_function_result('public.login_check_core(text)'::regprocedure);
  execute format($f$
    create or replace function public.login_check(p_username text) returns %s
    language plpgsql security definer set search_path = public as $b$
    declare r %s;
    begin
      r := public.login_check_core(p_username);
      if coalesce(r, 0) > 0 then perform public._log_login(p_username, 'locked'); end if;
      return r;
    end $b$;$f$, rt, rt);

  -- login_failed(p_username) → tries left; log every wrong PIN
  if to_regprocedure('public.login_failed_core(text)') is null then
    alter function public.login_failed(text) rename to login_failed_core;
  end if;
  rt := pg_get_function_result('public.login_failed_core(text)'::regprocedure);
  execute format($f$
    create or replace function public.login_failed(p_username text) returns %s
    language plpgsql security definer set search_path = public as $b$
    begin
      perform public._log_login(p_username, 'wrong_pin');
      return public.login_failed_core(p_username);
    end $b$;$f$, rt);

  -- login_ok() → called right after a successful sign-in
  if to_regprocedure('public.login_ok_core()') is null then
    alter function public.login_ok() rename to login_ok_core;
  end if;
  rt := pg_get_function_result('public.login_ok_core()'::regprocedure);
  if rt = 'void' then
    execute $f$
      create or replace function public.login_ok() returns void
      language plpgsql security definer set search_path = public as $b$
      begin
        perform public.login_ok_core();
        if auth.uid() is not null then perform public._log_login(null, 'ok', auth.uid()); end if;
      end $b$;$f$;
  else
    execute format($f$
      create or replace function public.login_ok() returns %s
      language plpgsql security definer set search_path = public as $b$
      declare r %s;
      begin
        r := public.login_ok_core();
        if auth.uid() is not null then perform public._log_login(null, 'ok', auth.uid()); end if;
        return r;
      end $b$;$f$, rt, rt);
  end if;
end
$do$;

grant execute on function public.login_check(text)  to anon, authenticated;
grant execute on function public.login_failed(text) to anon, authenticated;
grant execute on function public.login_ok()         to anon, authenticated;

-- 4) Live updates on the Watch site --------------------------------
do $$
begin
  alter publication supabase_realtime add table public.login_log;
exception when others then null;  -- already added
end $$;

-- Quick test after a login attempt on the app:
--   select * from public.login_log order by at desc limit 20;
