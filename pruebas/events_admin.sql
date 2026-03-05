-- =========================
-- 1) Tabla independiente: events (directorio tipo sobotz)
-- =========================
create table if not exists public.events (
  id uuid primary key default gen_random_uuid(),

  name text not null,
  start_at timestamptz not null,
  end_at timestamptz,
  timezone text default 'America/Mexico_City',
  city text,
  venue text,
  address text,
  categories text[] default '{}'::text[],
  official_url text,
  description text,

  poster_url text,
  registration_url text,
  rules_url text,
  contact_email text,
  contact_phone text,
  fee text,
  country_code text,
  tags text[] default '{}'::text[],
  is_public boolean default true,

  created_at timestamptz not null default now()
);

create index if not exists events_start_at_idx on public.events (start_at);
create index if not exists events_public_start_at_idx on public.events (is_public, start_at);

-- =========================
-- 2) RLS: público solo lectura
-- =========================
alter table public.events enable row level security;

drop policy if exists "events_public_read" on public.events;
create policy "events_public_read"
on public.events
for select
to anon, authenticated
using (is_public = true);

-- =========================
-- 3) ADMIN por código via RPC (bypassa RLS)
--    Cambia el código aquí:
-- =========================
-- ⚠️ CAMBIA ESTE CÓDIGO
-- Ejemplo: 'APEX-ADMIN-1234'
create or replace function public.admin_check_code(p_code text)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
begin
  -- 🔐 cambia la cadena por tu admin code
  return p_code = 'CHANGE_ME_ADMIN_CODE';
end;
$$;

create or replace function public.admin_list_events(p_code text)
returns setof public.events
language plpgsql
security definer
set search_path = public
as $$
begin
  perform set_config('row_security','off', true);
  if not public.admin_check_code(p_code) then
    raise exception 'bad_code';
  end if;

  return query
    select *
    from public.events
    order by start_at asc nulls last, created_at desc;
end;
$$;

create or replace function public.admin_upsert_event(p_code text, p_event jsonb)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_id uuid;
  v_categories text[];
  v_tags text[];
begin
  perform set_config('row_security','off', true);
  if not public.admin_check_code(p_code) then
    raise exception 'bad_code';
  end if;

  v_id := coalesce(nullif(p_event->>'id','')::uuid, gen_random_uuid());

  select coalesce(array_agg(x), '{}'::text[])
    into v_categories
  from (
    select jsonb_array_elements_text(coalesce(p_event->'categories','[]'::jsonb)) as x
  ) s;

  select coalesce(array_agg(x), '{}'::text[])
    into v_tags
  from (
    select jsonb_array_elements_text(coalesce(p_event->'tags','[]'::jsonb)) as x
  ) s;

  insert into public.events(
    id, name, start_at, end_at, timezone,
    city, venue, address, categories, tags,
    description, official_url, poster_url,
    registration_url, rules_url,
    contact_email, contact_phone, fee, country_code,
    is_public
  ) values (
    v_id,
    coalesce(p_event->>'name',''),
    (p_event->>'start_at')::timestamptz,
    nullif(p_event->>'end_at','')::timestamptz,
    coalesce(nullif(p_event->>'timezone',''), 'America/Mexico_City'),

    nullif(p_event->>'city',''),
    nullif(p_event->>'venue',''),
    nullif(p_event->>'address',''),
    v_categories,
    v_tags,

    nullif(p_event->>'description',''),
    nullif(p_event->>'official_url',''),
    nullif(p_event->>'poster_url',''),

    nullif(p_event->>'registration_url',''),
    nullif(p_event->>'rules_url',''),

    nullif(p_event->>'contact_email',''),
    nullif(p_event->>'contact_phone',''),
    nullif(p_event->>'fee',''),
    nullif(p_event->>'country_code',''),

    coalesce((p_event->>'is_public')::boolean, true)
  )
  on conflict (id) do update set
    name = excluded.name,
    start_at = excluded.start_at,
    end_at = excluded.end_at,
    timezone = excluded.timezone,
    city = excluded.city,
    venue = excluded.venue,
    address = excluded.address,
    categories = excluded.categories,
    tags = excluded.tags,
    description = excluded.description,
    official_url = excluded.official_url,
    poster_url = excluded.poster_url,
    registration_url = excluded.registration_url,
    rules_url = excluded.rules_url,
    contact_email = excluded.contact_email,
    contact_phone = excluded.contact_phone,
    fee = excluded.fee,
    country_code = excluded.country_code,
    is_public = excluded.is_public;

  return v_id;
end;
$$;

create or replace function public.admin_delete_event(p_code text, p_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  perform set_config('row_security','off', true);
  if not public.admin_check_code(p_code) then
    raise exception 'bad_code';
  end if;

  delete from public.events where id = p_id;
end;
$$;

grant execute on function public.admin_check_code(text) to anon, authenticated;
grant execute on function public.admin_list_events(text) to anon, authenticated;
grant execute on function public.admin_upsert_event(text, jsonb) to anon, authenticated;
grant execute on function public.admin_delete_event(text, uuid) to anon, authenticated;
