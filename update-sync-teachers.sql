-- =====================================================================
-- Update: teachers added to HOF are automatically added to SLT too.
-- Run once in Supabase: SQL Editor → New query → paste → Run.
-- Safe to run more than once.
-- =====================================================================

create or replace function public.mirror_hof_teacher() returns trigger
language plpgsql security definer set search_path = public as $$
declare existing uuid;
begin
  if new.tracker <> 'hof' then return new; end if;

  -- Already on the SLT list (not removed)? Nothing to do.
  if exists (select 1 from public.teachers
             where tracker = 'slt' and not deleted
               and lower(trim(name)) = lower(trim(new.name))) then
    return new;
  end if;

  -- In the SLT Bin? Bring them back rather than making a duplicate.
  select id into existing from public.teachers
   where tracker = 'slt' and deleted and lower(trim(name)) = lower(trim(new.name))
   limit 1;
  if existing is not null then
    update public.teachers set deleted = false, deleted_at = null where id = existing;
    return new;
  end if;

  insert into public.teachers (tracker, name, subject) values ('slt', new.name, new.subject);
  return new;
end $$;

revoke all on function public.mirror_hof_teacher() from public, anon, authenticated;

drop trigger if exists mirror_hof_teacher on public.teachers;
create trigger mirror_hof_teacher after insert on public.teachers
for each row execute function public.mirror_hof_teacher();

-- One-off: copy across any HOF teachers already added who aren't on the SLT list yet.
insert into public.teachers (tracker, name, subject)
select distinct on (lower(trim(h.name))) 'slt', h.name, h.subject
from public.teachers h
where h.tracker = 'hof' and not h.deleted
  and not exists (select 1 from public.teachers s
                  where s.tracker = 'slt' and lower(trim(s.name)) = lower(trim(h.name)));
