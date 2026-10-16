-- =====================================================================
-- Update: SEN uses the HOF and SLT teacher lists.
--   Teacher added to HOF → also added to SLT and SEN
--   Teacher added to SLT → also added to SEN
--   Teacher added to SEN → stays SEN-only
-- Run once in Supabase: SQL Editor → New query → paste → Run.
-- Safe to run more than once.
-- =====================================================================

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
