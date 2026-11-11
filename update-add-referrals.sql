-- =====================================================================
-- Update: SEN referrals.
--   Anyone with SEN access can submit a referral (a comment).
--   Only staff with "See referrals" ticked (JSA and MSL to start)
--   can read or delete submitted referrals.
-- Run once in Supabase: SQL Editor → New query → paste → Run.
-- Safe to run more than once.
-- =====================================================================

-- 1. Who can see submitted referrals
alter table public.staff add column if not exists can_view_referrals boolean not null default false;
update public.staff set can_view_referrals = true where username in ('jsa', 'msl');

create or replace function public.can_view_referrals() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.staff s where s.user_id = auth.uid() and s.can_view_referrals)
$$;
grant execute on function public.can_view_referrals() to authenticated;

-- 2. The referrals themselves
create table if not exists public.referrals (
  id           uuid primary key default gen_random_uuid(),
  comment      text not null check (length(trim(comment)) > 0),
  submitted_by text not null default '',
  created_by   uuid default auth.uid(),
  created_at   timestamptz not null default now()
);
create index if not exists referrals_created_idx on public.referrals(created_at desc);

-- Who submitted it and when is filled in by the database, not the page.
create or replace function public.stamp_referral() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  new.created_by := auth.uid();
  new.created_at := now();
  new.submitted_by := coalesce(
    (select coalesce(nullif(trim(s.display_name), ''), upper(s.username))
       from public.staff s where s.user_id = auth.uid()), '');
  return new;
end $$;
revoke all on function public.stamp_referral() from public, anon, authenticated;
drop trigger if exists stamp_referral on public.referrals;
create trigger stamp_referral before insert on public.referrals
for each row execute function public.stamp_referral();

-- 3. Permissions
alter table public.referrals enable row level security;
drop policy if exists referrals_submit on public.referrals;
drop policy if exists referrals_read   on public.referrals;
drop policy if exists referrals_delete on public.referrals;
create policy referrals_submit on public.referrals for insert to authenticated
  with check (public.has_tracker('sen'));
create policy referrals_read   on public.referrals for select to authenticated
  using (public.can_view_referrals());
create policy referrals_delete on public.referrals for delete to authenticated
  using (public.can_view_referrals());
grant select, insert, delete on public.referrals to authenticated;

-- 4. New referrals appear live for JSA/MSL
do $$ begin
  begin alter publication supabase_realtime add table public.referrals; exception when others then null; end;
end $$;
