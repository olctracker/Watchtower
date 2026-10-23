-- =========================================================
-- Watchtower — its own accounts (10-digit PIN, admin approval)
-- Runs on the olc-database project after setup.sql.
-- Touches nothing OLC Database uses: new tables/functions only,
-- plus who is allowed to read login_log.
-- Watch accounts sign in as <name>@watch.olcdatabase.app, so they
-- can never sign into OLC Database (and OLC accounts can't sign in here).
-- =========================================================

-- 1) Accounts -------------------------------------------------------
create table if not exists public.watch_users (
  id          uuid primary key references auth.users (id) on delete cascade,
  username    text not null,
  role        text not null default 'member' check (role in ('admin', 'member')),
  approved    boolean not null default false,
  created_at  timestamptz not null default now()
);
create unique index if not exists watch_users_name_idx on public.watch_users (lower(username));

create table if not exists public.watch_lockouts (
  uname         text primary key,
  fails         int not null default 0,
  locked_until  timestamptz
);

alter table public.watch_users    enable row level security;
alter table public.watch_lockouts enable row level security;
revoke all on public.watch_users, public.watch_lockouts from anon, authenticated;
grant select on public.watch_users to authenticated;

create or replace function public.is_watch_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from watch_users where id = auth.uid() and role = 'admin' and approved)
$$;
create or replace function public.is_watch_member() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from watch_users where id = auth.uid() and approved)
$$;

drop policy if exists "watch users read" on public.watch_users;
create policy "watch users read" on public.watch_users
  for select to authenticated
  using (id = auth.uid() or public.is_watch_admin());

-- 2) Who can read the login log: approved Watch accounts only ---------
-- (Watch's own sign-in attempts are visible to the Watch admin only.)
drop policy if exists "admin reads login log" on public.login_log;
drop policy if exists "watch members read login log" on public.login_log;
create policy "watch members read login log" on public.login_log
  for select to authenticated
  using (public.is_watch_member() and (site <> 'watch' or public.is_watch_admin()));

-- 3) Logging Watch's own sign-in attempts ----------------------------
create or replace function public._log_watch(p_username text, p_result text, p_uid uuid default null)
returns void language plpgsql security definer set search_path = public as $$
declare
  h json; v_ip text; v_uid uuid := p_uid; v_name text := left(trim(coalesce(p_username, '')), 40);
  f_id uuid; f_name text;
begin
  begin h := nullif(current_setting('request.headers', true), '')::json;
  exception when others then h := null; end;
  v_ip := nullif(trim(coalesce(h ->> 'cf-connecting-ip', h ->> 'x-real-ip',
            split_part(h ->> 'x-forwarded-for', ',', 1))), '');
  if v_uid is not null then
    select username into f_name from watch_users where id = v_uid;
    v_name := coalesce(f_name, v_name);
  elsif v_name <> '' then
    select id, username into f_id, f_name from watch_users where lower(username) = lower(v_name);
    if f_id is null and p_result = 'wrong_pin' then p_result := 'unknown_user'; end if;
    v_uid := f_id; v_name := coalesce(f_name, v_name);
  end if;
  if v_name = '' then return; end if;
  insert into login_log (site, username, user_id, result, ip, user_agent)
  values ('watch', v_name, v_uid, p_result, v_ip, left(h ->> 'user-agent', 300));
exception when others then null;
end $$;
revoke all on function public._log_watch(text, text, uuid) from public, anon, authenticated;

-- 4) Sign up ----------------------------------------------------------
create or replace function public.watch_pin_password(p_pin text) returns text
language sql immutable as $$ select 'watch#' || p_pin || '#pin' $$;

create or replace function public.watch_signup(p_username text, p_pin text)
returns text language plpgsql security definer set search_path = public, extensions as $$
declare
  v_id uuid := gen_random_uuid();
  v_name text := trim(coalesce(p_username, ''));
  v_email text;
  v_first boolean;
begin
  if v_name !~ '^[A-Za-z0-9_.-]{3,20}$' then
    raise exception 'Username must be 3-20 letters, numbers, dots, dashes or underscores';
  end if;
  if coalesce(p_pin, '') !~ '^[0-9]{10}$' then
    raise exception 'PIN must be exactly 10 digits';
  end if;

  lock table watch_users in exclusive mode;   -- so only one account can ever be "first"
  if exists (select 1 from watch_users where lower(username) = lower(v_name)) then
    raise exception 'That username is taken';
  end if;
  if (select count(*) from watch_users where not approved) >= 20 then
    raise exception 'Sign-ups are paused right now. Ask the admin.';
  end if;
  v_email := lower(v_name) || '@watch.olcdatabase.app';
  v_first := not exists (select 1 from watch_users);

  insert into auth.users (instance_id, id, aud, role, email, encrypted_password,
    email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
    confirmation_token, recovery_token, email_change_token_new, email_change,
    email_change_token_current, reauthentication_token)
  values ('00000000-0000-0000-0000-000000000000', v_id, 'authenticated', 'authenticated',
    v_email, crypt(watch_pin_password(p_pin), gen_salt('bf')), now(),
    '{"provider":"email","providers":["email"]}'::jsonb,
    jsonb_build_object('username', v_name, 'app', 'watch'), now(), now(), '', '', '', '', '', '');

  insert into auth.identities (provider_id, user_id, identity_data, provider,
    last_sign_in_at, created_at, updated_at)
  values (v_id::text, v_id,
    jsonb_build_object('sub', v_id::text, 'email', v_email, 'email_verified', true),
    'email', now(), now(), now());

  insert into watch_users (id, username, role, approved)
  values (v_id, v_name, case when v_first then 'admin' else 'member' end, v_first);

  return case when v_first then 'admin' else 'pending' end;
end $$;

-- 5) Sign-in lockouts (5 wrong PINs → locked 15 minutes) ---------------
create or replace function public.watch_login_check(p_username text) returns integer
language plpgsql security definer set search_path = public as $$
declare r integer;
begin
  select greatest(0, ceil(extract(epoch from (locked_until - now()))))::int into r
  from watch_lockouts where uname = lower(trim(p_username));
  r := coalesce(r, 0);
  if r > 0 then perform _log_watch(p_username, 'locked'); end if;
  return r;
end $$;

create or replace function public.watch_login_failed(p_username text) returns integer
language plpgsql security definer set search_path = public as $$
declare v_u text := lower(left(trim(coalesce(p_username, '')), 40)); v_f int;
begin
  perform _log_watch(p_username, 'wrong_pin');
  insert into watch_lockouts (uname, fails) values (v_u, 1)
  on conflict (uname) do update
    set fails = case when watch_lockouts.locked_until is not null and watch_lockouts.locked_until <= now()
                     then 1 else watch_lockouts.fails + 1 end,
        locked_until = case when watch_lockouts.locked_until is not null and watch_lockouts.locked_until <= now()
                     then null else watch_lockouts.locked_until end
  returning fails into v_f;
  if v_f >= 5 then
    update watch_lockouts set locked_until = now() + interval '15 minutes' where uname = v_u;
    return 0;
  end if;
  return 5 - v_f;
end $$;

create or replace function public.watch_login_ok() returns void
language plpgsql security definer set search_path = public as $$
declare v_name text;
begin
  select username into v_name from watch_users where id = auth.uid();
  if v_name is null then return; end if;
  delete from watch_lockouts where uname = lower(v_name);
  perform _log_watch(null, 'ok', auth.uid());
end $$;

-- 6) Admin tools -------------------------------------------------------
create or replace function public.watch_approve(p_id uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not is_watch_admin() then raise exception 'Not allowed'; end if;
  update watch_users set approved = true where id = p_id;
end $$;

create or replace function public.watch_delete(p_id uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not is_watch_admin() then raise exception 'Not allowed'; end if;
  if p_id = auth.uid() then raise exception 'You can''t delete your own account'; end if;
  -- only ever deletes Watch accounts, never an OLC Database account
  if not exists (select 1 from watch_users where id = p_id) then raise exception 'Not a Watch account'; end if;
  if exists (select 1 from profiles where id = p_id) then raise exception 'Not a Watch account'; end if;
  delete from auth.users where id = p_id and email like '%@watch.olcdatabase.app';
end $$;

revoke all on function public.watch_signup(text, text), public.watch_login_check(text),
  public.watch_login_failed(text), public.watch_login_ok(), public.watch_approve(uuid),
  public.watch_delete(uuid) from public;
grant execute on function public.watch_signup(text, text), public.watch_login_check(text),
  public.watch_login_failed(text) to anon, authenticated;
grant execute on function public.watch_login_ok(), public.watch_approve(uuid),
  public.watch_delete(uuid), public.is_watch_admin(), public.is_watch_member() to authenticated;

-- live updates for the Accounts page
do $$ begin alter publication supabase_realtime add table public.watch_users;
exception when others then null; end $$;
