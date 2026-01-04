package main

const CHECK_PUBLIC_IPS_TABLE_EXISTENCE_SQL = `
select exists (
  select 1
  from information_schema.tables
  where table_schema = $1
  and table_name = $2
);
`

const DB_SETUP_RESPONSE = `
Please run this sql to create the ips table in schema public:
create table public.ips (
  id serial not null,
  ip character varying(45) not null,
  score integer null default 0,
  last_seen timestamp without time zone null default CURRENT_TIMESTAMP,
  blocked boolean null default false,
  created_at timestamp without time zone null default CURRENT_TIMESTAMP,
  constraint ips_pkey primary key (id),
  constraint ips_ip_key unique (ip)
) TABLESPACE pg_default;
`

const INSERT_PUBLIC_IP_SQL = `
insert into public.ips (ip, score, blocked, last_seen)
values ($1, $2, $3, now())
on conflict (ip) do update
set score = public.ips.score + 1,
last_seen = now(),
blocked = true;
`

const CHECK_PUBLIC_IP_EXISTENCE_SQL = `
select exists (
  select 1
  from public.ips
  offset $1
)
`
