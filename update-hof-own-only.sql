-- =====================================================================
-- Update: "HOF: own only".
--   Staff with this ticked only see (and can only change) the HOF
--   observations they recorded themselves. Everyone else with HOF
--   access, including SLT, still sees all HOF observations.
--   SLT and SEN trackers are not affected.
--   Starts ticked for BBO, FGR and SBA.
-- Run once in Supabase: SQL Editor → New query → paste → Run.
-- Safe to run more than once.
-- =====================================================================

-- 1. The new per-person setting
alter table public.staff add column if not exists hof_own_only boolean not null default false;
update public.staff set hof_own_only = true where username in ('bbo', 'fgr', 'sba');

create or replace function public.hof_own_only() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.staff s where s.user_id = auth.uid() and s.hof_own_only)
$$;
grant execute on function public.hof_own_only() to authenticated;

-- 2. Who recorded an observation is set by the database and can't be changed
create or replace function public.stamp_observation_author() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    new.created_by := coalesce(auth.uid(), new.created_by);
  else
    new.created_by := old.created_by;
  end if;
  return new;
end $$;
revoke all on function public.stamp_observation_author() from public, anon, authenticated;
drop trigger if exists stamp_observation_author on public.observations;
create trigger stamp_observation_author before insert or update on public.observations
for each row execute function public.stamp_observation_author();

-- 3. Permission rule: in HOF, "own only" staff are limited to their own records
drop policy if exists observations_access on public.observations;
create policy observations_access on public.observations for all to authenticated
  using (
    public.has_tracker(tracker)
    and (tracker <> 'hof' or not public.hof_own_only() or created_by = auth.uid())
  )
  with check (
    public.has_tracker(tracker)
    and (tracker <> 'hof' or not public.hof_own_only() or created_by = auth.uid())
  );
