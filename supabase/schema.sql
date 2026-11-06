-- RJ em Foco: cole TUDO no SQL Editor do Supabase e clique em Run.

create table public.admins (user_id uuid primary key);

create table public.complaints (
  id uuid primary key default gen_random_uuid(),
  author_id uuid not null default auth.uid(),
  author_name text not null check (char_length(author_name) between 2 and 40),
  title text not null check (char_length(title) between 5 and 90),
  body text not null check (char_length(body) between 10 and 2000),
  category text not null check (char_length(category) between 3 and 80),
  neighborhood text not null check (char_length(neighborhood) between 2 and 60),
  location text check (char_length(location) <= 120),
  photo_url text,
  status text not null default 'Registrada'
    check (status in ('Registrada','Em análise','Encaminhada','Em andamento','Resolvida')),
  hidden boolean not null default false,
  created_at timestamptz not null default now(),
  -- bloqueia e-mails e telefones no texto (proteção de dados pessoais)
  constraint no_pii check (
    (title || ' ' || body || ' ' || coalesce(location,'')) !~* '[a-z0-9._+-]+@[a-z0-9-]+\.[a-z.]+'
    and (title || ' ' || body || ' ' || coalesce(location,'')) !~ '(\(?\d{2}\)?\s?)?9?\d{4}[-\s]?\d{4}')
);

create table public.updates (
  id uuid primary key default gen_random_uuid(),
  complaint_id uuid not null references public.complaints(id) on delete cascade,
  status text not null,
  note text not null check (char_length(note) between 3 and 500),
  created_at timestamptz not null default now()
);

create table public.reports (
  id uuid primary key default gen_random_uuid(),
  complaint_id uuid not null references public.complaints(id) on delete cascade,
  reporter_id uuid not null default auth.uid(),
  reason text not null check (char_length(reason) <= 80),
  created_at timestamptz not null default now(),
  unique (complaint_id, reporter_id)
);

create or replace function public.is_admin() returns boolean
language sql security definer set search_path = public stable
as $$ select exists (select 1 from public.admins where user_id = auth.uid()) $$;

-- Anti-spam: no máximo 5 reclamações por hora por visitante
create or replace function public.rate_limit() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if (select count(*) from public.complaints
      where author_id = new.author_id and created_at > now() - interval '1 hour') >= 5 then
    raise exception 'Limite de 5 reclamações por hora. Tente mais tarde.';
  end if;
  return new;
end $$;
create trigger complaints_rate before insert on public.complaints
  for each row execute function public.rate_limit();

-- Somente administradores mudam status / ocultam (visitantes não conseguem)
create or replace function public.admin_update(p_id uuid, p_status text, p_note text, p_hidden boolean)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Acesso negado'; end if;
  update public.complaints set status = p_status, hidden = p_hidden where id = p_id;
  if p_note is not null and char_length(p_note) >= 3 then
    insert into public.updates (complaint_id, status, note) values (p_id, p_status, p_note);
  end if;
end $$;

alter table public.admins enable row level security;
alter table public.complaints enable row level security;
alter table public.updates enable row level security;
alter table public.reports enable row level security;

create policy "admin vê a si mesmo" on public.admins for select using (user_id = auth.uid());

create policy "ler publicadas" on public.complaints for select
  using (not hidden or author_id = auth.uid() or public.is_admin());
create policy "publicar como si mesmo" on public.complaints for insert
  with check (author_id = auth.uid() and status = 'Registrada' and hidden = false);
create policy "autor edita a sua" on public.complaints for update
  using (author_id = auth.uid()) with check (author_id = auth.uid());
create policy "autor ou admin exclui" on public.complaints for delete
  using (author_id = auth.uid() or public.is_admin());

-- Autor só edita o conteúdo, nunca status, ocultação ou autoria
revoke update on public.complaints from anon, authenticated;
grant update (title, body, category, neighborhood, location, photo_url) on public.complaints to authenticated;

create policy "ler atualizações" on public.updates for select using (true);
-- (sem policy de insert: só a função admin_update escreve em updates)

create policy "denunciar" on public.reports for insert with check (reporter_id = auth.uid());
create policy "admin lê denúncias" on public.reports for select using (public.is_admin());

-- Fotos: bucket público para leitura, máx. 2 MB, só imagens, cada visitante só na própria pasta
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('photos','photos', true, 2097152, array['image/jpeg','image/png','image/webp'])
on conflict (id) do nothing;

create policy "enviar foto na própria pasta" on storage.objects for insert to authenticated
  with check (bucket_id = 'photos' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "apagar a própria foto" on storage.objects for delete to authenticated
  using (bucket_id = 'photos' and (storage.foldername(name))[1] = auth.uid()::text);

-- Tempo real
alter publication supabase_realtime add table public.complaints;
