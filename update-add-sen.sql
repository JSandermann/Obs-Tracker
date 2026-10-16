-- =====================================================================
-- Update: add the SEN Observation Tracker.
-- Run once in Supabase: SQL Editor → New query → paste → Run.
-- Safe to run more than once. Existing HOF and SLT data is untouched.
-- =====================================================================

-- 1. New access tickbox for staff (off for everyone except admins)
alter table public.staff add column if not exists can_sen boolean not null default false;
update public.staff set can_sen = true where is_admin;

-- 2. Allow 'sen' as a tracker for teachers and observations
alter table public.teachers     drop constraint if exists teachers_tracker_check;
alter table public.teachers     add  constraint teachers_tracker_check     check (tracker in ('hof','slt','sen'));
alter table public.observations drop constraint if exists observations_tracker_check;
alter table public.observations add  constraint observations_tracker_check check (tracker in ('hof','slt','sen'));

-- 3. Permission check now understands SEN
create or replace function public.has_tracker(t text) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.staff s
    where s.user_id = auth.uid()
      and ((t = 'hof' and s.can_hof) or (t = 'slt' and s.can_slt) or (t = 'sen' and s.can_sen))
  )
$$;
