-- LAB ONLY. Supabase/Postgres-compatible contract sketch; not canonical migration.
create table mvp_c_price_observation_lab (
  id uuid primary key,
  tenant_id uuid not null,
  bar_id uuid not null,
  ingredient_id uuid not null,
  invoice_id text not null,
  invoice_line_id text not null,
  supplier_id text not null,
  observed_at timestamptz not null,
  paid_minor bigint not null check (paid_minor >= 0),
  currency char(3) not null,
  purchased_ml numeric not null check (purchased_ml > 0),
  unit_cost_minor_per_ml numeric not null check (unit_cost_minor_per_ml >= 0),
  source_object text not null,
  processing_key text not null,
  created_at timestamptz not null default now(),
  unique (tenant_id, bar_id, processing_key)
);
alter table mvp_c_price_observation_lab enable row level security;
-- Deliberately no permissive policy in lab: RLS defaults deny until canonical auth contract is proven.
