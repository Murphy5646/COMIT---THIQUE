-- COMITÉ D'ÉTHIQUE — SITE 73
-- À exécuter une seule fois dans Supabase > SQL Editor.
-- Compatible avec index.html fourni. Ne nécessite aucune clé secrète côté navigateur.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  username text not null default 'Personnel',
  department text not null default 'Personnel',
  role text not null default 'PERSONNEL' check (role in ('PERSONNEL','PCE')),
  created_at timestamptz not null default now()
);

alter table public.profiles add column if not exists email text;
alter table public.profiles add column if not exists username text not null default 'Personnel';
alter table public.profiles add column if not exists department text not null default 'Personnel';
alter table public.profiles add column if not exists role text not null default 'PERSONNEL';
alter table public.profiles add column if not exists created_at timestamptz not null default now();

-- Un seul compte PCE à la fois.
create unique index if not exists profiles_one_pce_only
  on public.profiles ((role)) where role = 'PCE';

create table if not exists public.reports (
  id uuid primary key default gen_random_uuid(),
  reporter_id uuid not null references auth.users(id) on delete restrict,
  reporter text not null,
  department text not null default 'Personnel',
  incident_date date,
  location text,
  subject text not null,
  facts text not null,
  evidence text,
  status text not null default 'Nouveau' check (status in ('Nouveau','En examen','Clos')),
  created_at timestamptz not null default now()
);

alter table public.reports add column if not exists reporter_id uuid references auth.users(id) on delete restrict;
alter table public.reports add column if not exists reporter text;
alter table public.reports add column if not exists department text not null default 'Personnel';
alter table public.reports add column if not exists incident_date date;
alter table public.reports add column if not exists location text;
alter table public.reports add column if not exists subject text;
alter table public.reports add column if not exists facts text;
alter table public.reports add column if not exists evidence text;
alter table public.reports add column if not exists status text not null default 'Nouveau';
alter table public.reports add column if not exists created_at timestamptz not null default now();

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id,email,username,department,role)
  values (
    new.id,
    coalesce(new.email,''),
    coalesce(nullif(new.raw_user_meta_data->>'username',''),'Personnel'),
    coalesce(nullif(new.raw_user_meta_data->>'department',''),'Personnel'),
    'PERSONNEL'
  )
  on conflict (id) do update set email = excluded.email;
  return new;
end;
$$;

 drop trigger if exists on_auth_user_created_scp73 on auth.users;
create trigger on_auth_user_created_scp73
  after insert on auth.users
  for each row execute function public.handle_new_user();

create or replace function public.is_current_user_pce()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = (select auth.uid()) and p.role = 'PCE'
  );
$$;

create or replace function public.transfer_pce(target_user uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform pg_advisory_xact_lock(hashtext('scp73_unique_pce'));
  if not exists (select 1 from public.profiles where id = (select auth.uid()) and role = 'PCE') then
    raise exception 'Accès refusé : seul le PCE actuel peut transférer la Présidence.';
  end if;
  if target_user is null or not exists (select 1 from public.profiles where id = target_user) then
    raise exception 'Compte destinataire introuvable.';
  end if;
  if target_user = (select auth.uid()) then
    raise exception 'Vous êtes déjà titulaire de la Présidence.';
  end if;
  update public.profiles set role = 'PERSONNEL' where role = 'PCE';
  update public.profiles set role = 'PCE' where id = target_user;
end;
$$;

create or replace function public.set_report_status(target_report uuid, new_status text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not exists (select 1 from public.profiles where id = (select auth.uid()) and role = 'PCE') then
    raise exception 'Accès refusé : fonction réservée au PCE.';
  end if;
  if new_status not in ('Nouveau','En examen','Clos') then
    raise exception 'État de signalement invalide.';
  end if;
  update public.reports set status = new_status where id = target_report;
  if not found then raise exception 'Signalement introuvable.'; end if;
end;
$$;

alter table public.profiles enable row level security;
alter table public.reports enable row level security;

drop policy if exists "profiles_read_own_or_pce" on public.profiles;
create policy "profiles_read_own_or_pce" on public.profiles
  for select to authenticated
  using (id = (select auth.uid()) or (select public.is_current_user_pce()));

-- Aucun INSERT/UPDATE/DELETE direct sur profiles depuis le navigateur.
drop policy if exists "reports_insert_own" on public.reports;
create policy "reports_insert_own" on public.reports
  for insert to authenticated
  with check (reporter_id = (select auth.uid()));

drop policy if exists "reports_read_pce" on public.reports;
create policy "reports_read_pce" on public.reports
  for select to authenticated
  using ((select public.is_current_user_pce()));

revoke all on function public.transfer_pce(uuid) from public, anon;
revoke all on function public.set_report_status(uuid,text) from public, anon;
grant execute on function public.transfer_pce(uuid) to authenticated;
grant execute on function public.set_report_status(uuid,text) to authenticated;
revoke all on function public.is_current_user_pce() from public, anon;
grant execute on function public.is_current_user_pce() to authenticated;

grant select on public.profiles to authenticated;
grant select, insert on public.reports to authenticated;

-- ÉTAPE INITIALE : après création et confirmation du premier compte,
-- remplacer l'adresse ci-dessous par celle du premier titulaire PCE puis exécuter :
-- update public.profiles set role = 'PCE' where email = 'pce@exemple.fr';


-- ===== Modules de travail connectés (annonces, agenda, demandes, notes privées) =====
create table if not exists public.announcements (
 id uuid primary key default gen_random_uuid(),
 title text not null,
 body text not null,
 category text not null default 'Information',
 pinned boolean not null default false,
 author_id uuid not null references auth.users(id) on delete restrict,
 author_name text not null default 'Présidence',
 created_at timestamptz not null default now()
);
create table if not exists public.agenda_events (
 id uuid primary key default gen_random_uuid(),
 title text not null,
 description text,
 event_date timestamptz not null,
 location text,
 created_by uuid not null references auth.users(id) on delete restrict,
 created_at timestamptz not null default now()
);
create table if not exists public.requests (
 id uuid primary key default gen_random_uuid(),
 user_id uuid not null references auth.users(id) on delete cascade,
 requester_name text not null,
 department text not null default 'Personnel',
 category text not null default 'Autre',
 title text not null,
 details text not null,
 status text not null default 'Reçue' check(status in ('Reçue','En traitement','Réponse apportée','Refusée')),
 created_at timestamptz not null default now()
);
create table if not exists public.personal_notes (
 user_id uuid primary key references auth.users(id) on delete cascade,
 content text not null default '',
 updated_at timestamptz not null default now()
);
create index if not exists agenda_events_date_idx on public.agenda_events(event_date);
create index if not exists requests_user_created_idx on public.requests(user_id,created_at desc);
create index if not exists announcements_created_idx on public.announcements(created_at desc);
alter table public.announcements enable row level security;
alter table public.agenda_events enable row level security;
alter table public.requests enable row level security;
alter table public.personal_notes enable row level security;
drop policy if exists "announcements_read_authenticated" on public.announcements;
create policy "announcements_read_authenticated" on public.announcements for select to authenticated using (true);
drop policy if exists "announcements_insert_pce" on public.announcements;
create policy "announcements_insert_pce" on public.announcements for insert to authenticated with check ((select public.is_current_user_pce()) and author_id=(select auth.uid()));
drop policy if exists "announcements_update_pce" on public.announcements;
create policy "announcements_update_pce" on public.announcements for update to authenticated using ((select public.is_current_user_pce())) with check ((select public.is_current_user_pce()));
drop policy if exists "announcements_delete_pce" on public.announcements;
create policy "announcements_delete_pce" on public.announcements for delete to authenticated using ((select public.is_current_user_pce()));
drop policy if exists "agenda_read_authenticated" on public.agenda_events;
create policy "agenda_read_authenticated" on public.agenda_events for select to authenticated using (true);
drop policy if exists "agenda_insert_pce" on public.agenda_events;
create policy "agenda_insert_pce" on public.agenda_events for insert to authenticated with check ((select public.is_current_user_pce()) and created_by=(select auth.uid()));
drop policy if exists "agenda_update_pce" on public.agenda_events;
create policy "agenda_update_pce" on public.agenda_events for update to authenticated using ((select public.is_current_user_pce())) with check ((select public.is_current_user_pce()));
drop policy if exists "agenda_delete_pce" on public.agenda_events;
create policy "agenda_delete_pce" on public.agenda_events for delete to authenticated using ((select public.is_current_user_pce()));
drop policy if exists "requests_insert_own" on public.requests;
create policy "requests_insert_own" on public.requests for insert to authenticated with check (user_id=(select auth.uid()));
drop policy if exists "requests_read_own_or_pce" on public.requests;
create policy "requests_read_own_or_pce" on public.requests for select to authenticated using (user_id=(select auth.uid()) or (select public.is_current_user_pce()));
drop policy if exists "requests_update_pce" on public.requests;
create policy "requests_update_pce" on public.requests for update to authenticated using ((select public.is_current_user_pce())) with check ((select public.is_current_user_pce()));
drop policy if exists "notes_own_select" on public.personal_notes;
create policy "notes_own_select" on public.personal_notes for select to authenticated using (user_id=(select auth.uid()));
drop policy if exists "notes_own_insert" on public.personal_notes;
create policy "notes_own_insert" on public.personal_notes for insert to authenticated with check (user_id=(select auth.uid()));
drop policy if exists "notes_own_update" on public.personal_notes;
create policy "notes_own_update" on public.personal_notes for update to authenticated using (user_id=(select auth.uid())) with check (user_id=(select auth.uid()));
grant select,insert,update,delete on public.announcements to authenticated;
grant select,insert,update,delete on public.agenda_events to authenticated;
grant select,insert,update on public.requests to authenticated;
grant select,insert,update on public.personal_notes to authenticated;


-- Bibliothèque documentaire interne, liens HTTP(S) et résumés.
create table if not exists public.library_documents (
 id uuid primary key default gen_random_uuid(),
 title text not null,
 category text not null default 'Archive',
 summary text,
 url text,
 author_id uuid not null references auth.users(id) on delete restrict,
 author_name text not null default 'Présidence',
 created_at timestamptz not null default now()
);
alter table public.library_documents enable row level security;
drop policy if exists "library_documents_read_authenticated" on public.library_documents;
create policy "library_documents_read_authenticated" on public.library_documents for select to authenticated using (true);
drop policy if exists "library_documents_insert_pce" on public.library_documents;
create policy "library_documents_insert_pce" on public.library_documents for insert to authenticated with check ((select public.is_current_user_pce()) and author_id=(select auth.uid()));
drop policy if exists "library_documents_update_pce" on public.library_documents;
create policy "library_documents_update_pce" on public.library_documents for update to authenticated using ((select public.is_current_user_pce())) with check ((select public.is_current_user_pce()));
drop policy if exists "library_documents_delete_pce" on public.library_documents;
create policy "library_documents_delete_pce" on public.library_documents for delete to authenticated using ((select public.is_current_user_pce()));
grant select,insert,update,delete on public.library_documents to authenticated;
