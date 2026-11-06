-- EcoLoop GitHub Pages + Supabase Auth; run once in Supabase SQL Editor.
-- Does not delete existing legacy tables.
create extension if not exists pgcrypto;
create table if not exists public.ecoloop_profiles (
 user_id uuid primary key references auth.users(id) on delete cascade,
 public_id text not null check(public_id ~ '^[0-9]{5,20}$'),
 role text not null check(role in ('student','merchant')),
 name text not null check(length(trim(name)) between 2 and 100),
 created_at timestamptz not null default now(),
 unique(public_id,role)
);
create table if not exists public.ecoloop_codes (
 code text primary key check(code ~ '^[0-9]{6}$'),
 student_user_id uuid not null references public.ecoloop_profiles(user_id) on delete cascade,
 expires_at timestamptz not null,
 used_at timestamptz,
 created_at timestamptz not null default now()
);
create index if not exists eco_codes_student on public.ecoloop_codes(student_user_id);
create table if not exists public.ecoloop_transactions (
 id bigint generated always as identity primary key,
 student_user_id uuid not null references public.ecoloop_profiles(user_id),
 merchant_user_id uuid not null references public.ecoloop_profiles(user_id),
 code text not null unique,
 created_at timestamptz not null default now()
);
create index if not exists eco_tx_student on public.ecoloop_transactions(student_user_id,created_at desc);
create index if not exists eco_tx_merchant on public.ecoloop_transactions(merchant_user_id,created_at desc);
alter table public.ecoloop_profiles enable row level security;
alter table public.ecoloop_codes enable row level security;
alter table public.ecoloop_transactions enable row level security;
revoke all on public.ecoloop_profiles,public.ecoloop_codes,public.ecoloop_transactions from anon,authenticated;
grant select on public.ecoloop_profiles to authenticated;
drop policy if exists "ecoloop_self_profile" on public.ecoloop_profiles;
create policy "ecoloop_self_profile" on public.ecoloop_profiles for select to authenticated using (user_id=(select auth.uid()));
create or replace function public.ecoloop_register_profile() returns trigger language plpgsql security definer set search_path = '' as $$
declare rid text; rrole text; rname text;
begin
 rid:=new.raw_user_meta_data->>'public_id';rrole:=new.raw_user_meta_data->>'role';rname:=trim(coalesce(new.raw_user_meta_data->>'name',''));
 if rid is null or rid !~ '^[0-9]{5,20}$' or rrole not in ('student','merchant') or length(rname) not between 2 and 100 then raise exception 'Invalid EcoLoop registration';end if;
 if new.email is distinct from (rrole||'-'||rid||'@accounts.ecoloop.invalid') then raise exception 'Invalid account email';end if;
 insert into public.ecoloop_profiles(user_id,public_id,role,name) values(new.id,rid,rrole,rname);
 return new;
end $$;
drop trigger if exists ecolo_profile_created on auth.users;
create trigger ecolo_profile_created after insert on auth.users for each row execute function public.ecoloop_register_profile();
create or replace function public.ecoloop_dashboard() returns jsonb language plpgsql security definer set search_path = '' as $$
declare me public.ecoloop_profiles%rowtype; hist jsonb; count_all integer; today_count integer; active jsonb;
begin
 select * into me from public.ecoloop_profiles where user_id=auth.uid();if not found then raise exception 'Login required';end if;
 if me.role='student' then
  select count(*) into count_all from public.ecoloop_transactions where student_user_id=me.user_id;
  select coalesce(jsonb_agg(jsonb_build_object('created_at',t.created_at,'merchant_id',p.public_id) order by t.created_at desc),'[]'::jsonb) into hist from (select * from public.ecoloop_transactions where student_user_id=me.user_id order by created_at desc limit 200)t join public.ecoloop_profiles p on p.user_id=t.merchant_user_id;
  select jsonb_build_object('code',code,'expires_at',expires_at) into active from public.ecoloop_codes where student_user_id=me.user_id and used_at is null and expires_at>now() order by created_at desc limit 1;
  return jsonb_build_object('stats',jsonb_build_object('points',count_all*100,'cups',count_all),'transactions',hist,'activeCode',active);
 else
  select count(*) into today_count from public.ecoloop_transactions where merchant_user_id=me.user_id and (created_at at time zone 'Asia/Bangkok')::date=(now() at time zone 'Asia/Bangkok')::date;
  select coalesce(jsonb_agg(jsonb_build_object('created_at',t.created_at,'student_id',p.public_id) order by t.created_at desc),'[]'::jsonb) into hist from (select * from public.ecoloop_transactions where merchant_user_id=me.user_id order by created_at desc limit 200)t join public.ecoloop_profiles p on p.user_id=t.student_user_id;
  return jsonb_build_object('stats',jsonb_build_object('today',today_count),'transactions',hist);
 end if;
end $$;
create or replace function public.ecoloop_new_code() returns jsonb language plpgsql security definer set search_path = '' as $$
declare me public.ecoloop_profiles%rowtype; c text; exp timestamptz; i int;
begin
 select * into me from public.ecoloop_profiles where user_id=auth.uid();if not found or me.role<>'student' then raise exception 'Student account required';end if;
 delete from public.ecoloop_codes where student_user_id=me.user_id and used_at is null;
 exp:=now()+interval '60 seconds';
 for i in 1..20 loop
  c:=lpad((floor(random()*1000000))::int::text,6,'0');
  begin insert into public.ecoloop_codes(code,student_user_id,expires_at) values(c,me.user_id,exp);return jsonb_build_object('code',c,'expires_at',exp);exception when unique_violation then null;end;
 end loop;
 raise exception 'Could not create code';
end $$;
create or replace function public.ecoloop_lookup_code(p_code text) returns jsonb language plpgsql security definer set search_path = '' as $$
declare me public.ecoloop_profiles%rowtype; sid text;
begin
 select * into me from public.ecoloop_profiles where user_id=auth.uid();if not found or me.role<>'merchant' then raise exception 'Merchant account required';end if;
 select p.public_id into sid from public.ecoloop_codes c join public.ecoloop_profiles p on p.user_id=c.student_user_id where c.code=p_code and c.used_at is null and c.expires_at>now();
 if sid is null then raise exception 'รหัสไม่ถูกต้องหรือหมดอายุ';end if;
 return jsonb_build_object('student_id',sid);
end $$;
create or replace function public.ecoloop_confirm_code(p_code text,p_observed boolean) returns jsonb language plpgsql security definer set search_path = '' as $$
declare me public.ecoloop_profiles%rowtype; student uuid;
begin
 select * into me from public.ecoloop_profiles where user_id=auth.uid();if not found or me.role<>'merchant' then raise exception 'Merchant account required';end if;
 if p_observed is distinct from true then raise exception 'Must verify reusable cup';end if;
 update public.ecoloop_codes set used_at=now() where code=p_code and used_at is null and expires_at>now() returning student_user_id into student;
 if student is null then raise exception 'รหัสไม่ถูกต้อง หมดอายุ หรือถูกใช้แล้ว';end if;
 insert into public.ecoloop_transactions(student_user_id,merchant_user_id,code) values(student,me.user_id,p_code);
 return jsonb_build_object('ok',true,'points',100);
end $$;
revoke all on function public.ecoloop_dashboard(),public.ecoloop_new_code(),public.ecoloop_lookup_code(text),public.ecoloop_confirm_code(text,boolean) from public,anon;
grant execute on function public.ecoloop_dashboard(),public.ecoloop_new_code(),public.ecoloop_lookup_code(text),public.ecoloop_confirm_code(text,boolean) to authenticated;
