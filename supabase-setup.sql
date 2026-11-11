-- FONDATION S.C.P. — SITE 73 | PORTAIL DU COMITÉ D’ÉTHIQUE
-- Exécuter une seule fois dans Supabase > SQL Editor.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null unique,
  username text not null,
  department text not null default 'Personnel',
  role text not null default 'PERSONNEL' check (role in ('PCE','PERSONNEL')),
  created_at timestamptz not null default now()
);

-- Un seul compte peut détenir la Présidence du Comité.
create unique index if not exists profiles_one_pce_only
  on public.profiles ((role)) where role = 'PCE';

create table if not exists public.reports (
  id uuid primary key default gen_random_uuid(),
  reporter_id uuid not null default auth.uid() references auth.users(id) on delete restrict,
  reporter text not null,
  department text,
  incident_date date,
  location text,
  subject text not null,
  facts text not null,
  evidence text,
  status text not null default 'Nouveau' check (status in ('Nouveau','En examen','Clos')),
  created_at timestamptz not null default now()
);

-- Création automatique du profil : aucun nouvel inscrit ne peut devenir PCE.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = '' as $$
declare
  v_username text;
  v_department text;
begin
  v_username := coalesce(nullif(trim(new.raw_user_meta_data ->> 'username'), ''), split_part(new.email, '@', 1));
  v_department := coalesce(nullif(trim(new.raw_user_meta_data ->> 'department'), ''), 'Personnel');
  insert into public.profiles (id,email,username,department,role)
  values (new.id,new.email,v_username,v_department,'PERSONNEL')
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_profile on auth.users;
create trigger on_auth_user_created_profile after insert on auth.users
for each row execute procedure public.handle_new_user();

-- Fonction de contrôle de rôle, sans récursion des règles RLS.
create or replace function public.is_current_user_pce()
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'PCE');
$$;
revoke all on function public.is_current_user_pce() from public, anon;
grant execute on function public.is_current_user_pce() to authenticated;

alter table public.profiles enable row level security;
drop policy if exists profiles_read_self_or_pce on public.profiles;
create policy profiles_read_self_or_pce on public.profiles for select to authenticated
using (id = (select auth.uid()) or (select public.is_current_user_pce()));
grant select on public.profiles to authenticated;
revoke insert, update, delete on public.profiles from anon, authenticated;

-- Transfert atomique de la PCE : seul le titulaire actuel peut l'effectuer.
create or replace function public.transfer_pce(target_user uuid)
returns void language plpgsql security definer set search_path = '' as $$
declare caller_id uuid := auth.uid();
begin
  if caller_id is null then raise exception 'Authentification requise'; end if;
  perform pg_advisory_xact_lock(hashtext('scp73_unique_pce')::bigint);
  if not exists (select 1 from public.profiles where id = caller_id and role = 'PCE') then
    raise exception 'Seul le PCE actuel peut transférer la Présidence';
  end if;
  if not exists (select 1 from public.profiles where id = target_user) then
    raise exception 'Compte destinataire introuvable';
  end if;
  if target_user = caller_id then raise exception 'Ce compte détient déjà la Présidence'; end if;
  update public.profiles set role = 'PERSONNEL' where id = caller_id;
  update public.profiles set role = 'PCE' where id = target_user;
end;
$$;
revoke all on function public.transfer_pce(uuid) from public, anon;
grant execute on function public.transfer_pce(uuid) to authenticated;

-- Signalements : création par un membre connecté, lecture par le PCE uniquement.
alter table public.reports enable row level security;
drop policy if exists reports_insert_authenticated on public.reports;
create policy reports_insert_authenticated on public.reports for insert to authenticated
with check (reporter_id = (select auth.uid()));
drop policy if exists reports_read_pce on public.reports;
create policy reports_read_pce on public.reports for select to authenticated
using ((select public.is_current_user_pce()));
grant select, insert on public.reports to authenticated;
revoke update, delete on public.reports from anon, authenticated;

-- Changement d'état réservé au PCE, sans autoriser une modification directe de la table.
create or replace function public.set_report_status(target_report uuid, new_status text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if auth.uid() is null then raise exception 'Authentification requise'; end if;
  if not public.is_current_user_pce() then raise exception 'Accès réservé au PCE'; end if;
  if new_status not in ('Nouveau','En examen','Clos') then raise exception 'État non autorisé'; end if;
  update public.reports set status = new_status where id = target_report;
  if not found then raise exception 'Signalement introuvable'; end if;
end;
$$;
revoke all on function public.set_report_status(uuid,text) from public, anon;
grant execute on function public.set_report_status(uuid,text) to authenticated;

-- APRÈS avoir créé le premier compte et confirmé son adresse, exécuter séparément :
-- update public.profiles set role = 'PCE' where email = 'adresse-du-premier-pce@exemple.fr';
-- Cette promotion initiale est manuelle et ne doit être faite qu'une seule fois.
