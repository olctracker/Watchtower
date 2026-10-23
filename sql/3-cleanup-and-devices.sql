-- =========================================================
-- Watchtower — log cleanup (Admin only) + active devices
-- watch_purge_log(days, username):
--   days only      → delete entries older than that many days
--   username only  → delete all of that member's entries
--   neither        → delete everything
-- Returns how many entries were deleted.
-- =========================================================
create or replace function public.watch_purge_log(p_older_than_days int default null, p_username text default null)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare n integer;
begin
  if not is_watch_admin() then raise exception 'Not allowed'; end if;
  if p_older_than_days is not null and p_older_than_days < 1 then
    raise exception 'Days must be 1 or more';
  end if;
  delete from login_log
  where (p_older_than_days is null or at < now() - make_interval(days => p_older_than_days))
    and (p_username is null or lower(username) = lower(trim(p_username)));
  get diagnostics n = row_count;
  return n;
end $$;

revoke all on function public.watch_purge_log(int, text) from public, anon;
grant execute on function public.watch_purge_log(int, text) to authenticated;

-- Optional hardening flagged by Supabase's security check
-- (no effect on how either site looks or works):
revoke execute on function public.watch_approve(uuid), public.watch_delete(uuid),
  public.watch_login_ok(), public.is_watch_admin(), public.is_watch_member() from anon;
revoke execute on function public.login_check_core(text), public.login_failed_core(text),
  public.login_ok_core() from anon, authenticated;

-- =========================================================
-- Active devices (option 1): reads Supabase's own session records
-- for OLC Database members. Nothing is stored or changed.
-- =========================================================
create or replace function public.watch_sessions()
returns table (username text, user_id uuid, ip text, user_agent text,
               signed_in timestamptz, last_active timestamptz)
language sql
stable
security definer
set search_path = public
as $$
  select p.username, s.user_id, host(s.ip), s.user_agent, s.created_at,
         greatest(s.created_at, s.updated_at, s.refreshed_at at time zone 'UTC')
  from auth.sessions s
  join profiles p on p.id = s.user_id
  where is_watch_member()
    and (s.not_after is null or s.not_after > now())
  order by 6 desc
$$;
revoke all on function public.watch_sessions() from public, anon;
grant execute on function public.watch_sessions() to authenticated;
