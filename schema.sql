-- =====================================================================
-- Observation Tracker (HOF + SLT) — Supabase database setup
-- Run this whole file once in Supabase: SQL Editor → New query → Run.
-- It only creates its own tables and functions; it touches nothing else.
-- =====================================================================

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------
-- 1. Staff usernames and what each person can access
-- ---------------------------------------------------------------------
create table if not exists public.staff (
  username     text primary key
               check (username = lower(username) and username ~ '^[a-z0-9._-]{2,40}$'),
  display_name text not null default '',
  can_hof      boolean not null default true,
  can_slt      boolean not null default false,
  can_sen      boolean not null default false,
  is_admin     boolean not null default false,
  user_id      uuid unique references auth.users(id) on delete set null,
  created_at   timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- 2. Tracker data. Each row belongs to one tracker: 'hof' or 'slt'.
-- ---------------------------------------------------------------------
create table if not exists public.teachers (
  id         uuid primary key default gen_random_uuid(),
  tracker    text not null check (tracker in ('hof','slt','sen')),
  name       text not null,
  subject    text not null default '',
  deleted    boolean not null default false,
  deleted_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.observations (
  id             uuid primary key default gen_random_uuid(),
  tracker        text not null check (tracker in ('hof','slt','sen')),
  type           text not null,
  date           date not null,
  teacher_id     uuid not null references public.teachers(id) on delete restrict,
  cls            text not null default '',
  topic          text not null default '',
  objective      text not null default '',
  notes          text not null default '',
  ratings        jsonb not null default '{}'::jsonb,
  action_text    text not null default '',
  action_due     date,
  action_done    boolean not null default false,
  observer_label text not null default '',
  created_by     uuid default auth.uid(),
  deleted        boolean not null default false,
  deleted_at     timestamptz,
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now()
);

create index if not exists teachers_tracker_idx on public.teachers(tracker);
create index if not exists observations_tracker_idx on public.observations(tracker);
create index if not exists observations_teacher_idx on public.observations(teacher_id);

-- An observation must stay in the same tracker as its teacher.
create or replace function public.obs_same_tracker() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.teachers t where t.id = new.teacher_id and t.tracker = new.tracker) then
    raise exception 'That teacher belongs to the other tracker.';
  end if;
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists obs_same_tracker on public.observations;
create trigger obs_same_tracker before insert or update on public.observations
for each row execute function public.obs_same_tracker();

-- ---------------------------------------------------------------------
-- 3. Permission helpers
-- ---------------------------------------------------------------------
create or replace function public.has_tracker(t text) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.staff s
    where s.user_id = auth.uid()
      and ((t = 'hof' and s.can_hof) or (t = 'slt' and s.can_slt) or (t = 'sen' and s.can_sen))
  )
$$;

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.staff s where s.user_id = auth.uid() and s.is_admin)
$$;

-- ---------------------------------------------------------------------
-- 4. Row-level security: nobody sees or changes a tracker they can't access
-- ---------------------------------------------------------------------
alter table public.staff        enable row level security;
alter table public.teachers     enable row level security;
alter table public.observations enable row level security;

drop policy if exists staff_read  on public.staff;
drop policy if exists staff_admin on public.staff;
create policy staff_read  on public.staff for select to authenticated
  using (user_id = auth.uid() or public.is_admin());
create policy staff_admin on public.staff for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

drop policy if exists teachers_access on public.teachers;
create policy teachers_access on public.teachers for all to authenticated
  using (public.has_tracker(tracker)) with check (public.has_tracker(tracker));

drop policy if exists observations_access on public.observations;
create policy observations_access on public.observations for all to authenticated
  using (public.has_tracker(tracker)) with check (public.has_tracker(tracker));

-- ---------------------------------------------------------------------
-- 5. Logins. An admin adds a username; the person then sets their own
--    password on first visit. Anyone not on the staff list is refused.
-- ---------------------------------------------------------------------
create or replace function public.claim_staff() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  u text := lower(split_part(new.email, '@', 1));
begin
  if split_part(lower(new.email), '@', 2) <> 'staff.obs-tracker.app' then
    raise exception 'Sign-ups are not allowed.';
  end if;
  update public.staff set user_id = new.id where username = u and user_id is null;
  if not found then
    raise exception 'This username has not been set up, or already has a password.';
  end if;
  return new;
end $$;
drop trigger if exists on_auth_user_created_obs on auth.users;
create trigger on_auth_user_created_obs after insert on auth.users
for each row execute function public.claim_staff();

-- Lets the login screen give a clear message before someone sets a password.
create or replace function public.username_status(u text) returns text
language sql stable security definer set search_path = public as $$
  select case
    when s.username is null then 'unknown'
    when s.user_id is null then 'unclaimed'
    else 'claimed' end
  from (select 1) x left join public.staff s on s.username = lower(trim(u))
$$;

-- Admin: clear someone's password so they can set a new one.
create or replace function public.admin_reset_login(u text) returns void
language plpgsql security definer set search_path = public, auth as $$
declare uid uuid;
begin
  if not public.is_admin() then raise exception 'Only admins can do this.'; end if;
  select user_id into uid from public.staff where username = lower(u);
  if uid = auth.uid() then raise exception 'You cannot reset your own login here.'; end if;
  if uid is not null then
    update public.staff set user_id = null where username = lower(u);
    delete from auth.users where id = uid;
  end if;
end $$;

-- Admin: remove a member of staff completely.
create or replace function public.admin_remove_staff(u text) returns void
language plpgsql security definer set search_path = public, auth as $$
declare uid uuid;
begin
  if not public.is_admin() then raise exception 'Only admins can do this.'; end if;
  select user_id into uid from public.staff where username = lower(u);
  if uid = auth.uid() then raise exception 'You cannot remove yourself.'; end if;
  delete from public.staff where username = lower(u);
  if uid is not null then delete from auth.users where id = uid; end if;
end $$;

revoke all on function public.claim_staff() from public, anon, authenticated;
revoke all on function public.admin_reset_login(text) from public, anon;
revoke all on function public.admin_remove_staff(text) from public, anon;
grant execute on function public.username_status(text) to anon, authenticated;
grant execute on function public.admin_reset_login(text) to authenticated;
grant execute on function public.admin_remove_staff(text) to authenticated;
grant execute on function public.has_tracker(text) to authenticated;
grant execute on function public.is_admin() to authenticated;

-- ---------------------------------------------------------------------
-- 6. Live updates between devices
-- ---------------------------------------------------------------------
do $$ begin
  begin alter publication supabase_realtime add table public.teachers;     exception when others then null; end;
  begin alter publication supabase_realtime add table public.observations; exception when others then null; end;
end $$;

-- ---------------------------------------------------------------------
-- 7. Starting usernames (change names later in the app's Staff tab)
-- ---------------------------------------------------------------------
insert into public.staff (username, display_name, can_hof, can_slt, can_sen, is_admin) values
  ('jsa', 'JSA', true, true,  true,  true),
  ('btu', 'BTU', true, true,  false, false),
  ('bbo', 'BBO', true, false, false, false)
on conflict (username) do nothing;


-- ---------------------------------------------------------------------
-- 8. Teacher sync: HOF → SLT and SEN, SLT → SEN
-- ---------------------------------------------------------------------
create or replace function public.mirror_teacher() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  targets text[];
  tgt text;
  existing uuid;
begin
  targets := case new.tracker when 'hof' then array['slt','sen']
                              when 'slt' then array['sen']
                              else array[]::text[] end;
  foreach tgt in array targets loop
    -- Already on that list (not removed)? Nothing to do.
    if exists (select 1 from public.teachers
               where tracker = tgt and not deleted
                 and lower(trim(name)) = lower(trim(new.name))) then
      continue;
    end if;
    -- In that tracker's Bin? Bring them back rather than making a duplicate.
    select id into existing from public.teachers
     where tracker = tgt and deleted and lower(trim(name)) = lower(trim(new.name))
     limit 1;
    if existing is not null then
      update public.teachers set deleted = false, deleted_at = null where id = existing;
    else
      insert into public.teachers (tracker, name, subject) values (tgt, new.name, new.subject);
    end if;
  end loop;
  return new;
end $$;

revoke all on function public.mirror_teacher() from public, anon, authenticated;

-- Replace the old HOF→SLT-only sync with this one
drop trigger if exists mirror_hof_teacher on public.teachers;
drop trigger if exists mirror_teacher on public.teachers;
create trigger mirror_teacher after insert on public.teachers
for each row execute function public.mirror_teacher();
drop function if exists public.mirror_hof_teacher();

-- One-off: copy everyone already on the HOF or SLT list into SEN (and HOF into SLT)
insert into public.teachers (tracker, name, subject)
select distinct on (lower(trim(src.name))) 'sen', src.name, src.subject
from public.teachers src
where src.tracker in ('hof','slt') and not src.deleted
  and not exists (select 1 from public.teachers s
                  where s.tracker = 'sen' and lower(trim(s.name)) = lower(trim(src.name)))
order by lower(trim(src.name)), (src.tracker = 'hof') desc;

insert into public.teachers (tracker, name, subject)
select distinct on (lower(trim(h.name))) 'slt', h.name, h.subject
from public.teachers h
where h.tracker = 'hof' and not h.deleted
  and not exists (select 1 from public.teachers s
                  where s.tracker = 'slt' and lower(trim(s.name)) = lower(trim(h.name)));
