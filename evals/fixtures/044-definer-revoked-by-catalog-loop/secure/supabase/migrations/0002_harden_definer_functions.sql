-- Hardening: no SECURITY DEFINER function of the public schema is callable through the Data API.
do $$
declare
  fn record;
begin
  for fn in
    select p.oid::regprocedure as regproc
    from pg_proc p
    join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public'
      and p.prosecdef
  loop
    execute format('revoke all privileges on function %s from public', fn.regproc);
    execute format('revoke all privileges on function %s from anon', fn.regproc);
    execute format('revoke all privileges on function %s from authenticated', fn.regproc);
    execute format('grant execute on function %s to service_role', fn.regproc);
  end loop;
end $$;
