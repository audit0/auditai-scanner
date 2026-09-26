/**
 * The read-only query a user runs in their own SQL editor to get a snapshot of what their database
 * lets people do (ADR-005). It is the product's front door, so it is written to be read by the person
 * who runs it: every part says what it reads, and nothing in it writes, changes or reads a row of data.
 *
 * Only catalog metadata leaves the database: table and column names, whether RLS is on, the policies
 * with their roles and conditions, who may execute which function, the storage buckets. The source of
 * a function is included only for SECURITY DEFINER functions — the ones that run with more rights than
 * their caller and so are the only ones whose body the rules judge. For every other function the
 * query sends whether its body reads the caller's identity and the names of the tables it changes.
 *
 * Grants are read from the ACLs in pg_class and pg_proc, not from information_schema: the
 * information_schema views list only grants to roles the current user belongs to, so the same query
 * run as a role outside anon (the Supabase MCP server in read-only mode, a monitoring role) would
 * report no grants and every function as uncallable. The ACLs read the same under any role, and they
 * are per function, so overloads no longer share their grants. The only privilege a function's ACL
 * holds is the right to run it, so its entries need no filter by kind. `columnGrants` are the
 * column-level privileges of the API roles (`grant update (v) on t to authenticated`), from attacl.
 *
 * `apiSettings` are the settings of `authenticator`, the role the Data API logs in as, that decide
 * whether an UPDATE or DELETE without WHERE is refused: the libraries it preloads (Supabase preloads
 * safeupdate), `safeupdate.*`, which the project owner may switch off, and a PostgREST pre-request
 * function, which may switch it off for each request. Most specific first: this database and that
 * role, the role, this database, every database and role, then the server's own `safeupdate.enabled`
 * (ALTER SYSTEM, postgresql.conf) as this session sees it. pg_db_role_setting is a catalog every role
 * reads; the server's `session_preload_libraries` is not (it needs pg_read_all_settings), so it is
 * left out, and a role without a preload setting of its own counts as not refusing.
 *
 * `changes` is sent for functions that are not SECURITY DEFINER, triggers included: the names after
 * UPDATE, DELETE FROM, MERGE INTO and TRUNCATE in the definition, comments removed, and `*` when it runs dynamic
 * SQL (EXECUTE) at all. Such a function runs with the caller's rights, and when it writes without
 * reading a column no SELECT policy limits it.
 *
 * The output is compact JSON (no jsonb_pretty) because it is pasted by hand. `evals/realworld/
 * schema-probe/live-snapshot.sql` is a copy kept for the measurement scripts; a test keeps them equal.
 */
export const SNAPSHOT_QUERY = `-- Audit AI: a read-only snapshot of what your database lets people do.
-- It reads names and rules: tables, whether row level security is on, policies and their
-- conditions, who may run which function, storage buckets, and the source code of SECURITY DEFINER
-- functions (the ones that run with their owner's rights), which tables each view selects from and
-- whether it runs with the caller's rights, the names of the tables other functions
-- change, and whether the API refuses an update or delete without a filter (safeupdate). It writes
-- nothing, changes nothing, and reads no row of your data. Run it, look at the result, then decide
-- whether to paste it.
select jsonb_build_object(
  'snapshotVersion', 1,
  'takenAt', now(),
  'postgres', current_setting('server_version'),
  'tables', (
    select coalesce(jsonb_agg(jsonb_build_object(
      'schema', n.nspname, 'name', c.relname, 'rlsEnabled', c.relrowsecurity, 'rlsForced', c.relforcerowsecurity,
      'kind', case c.relkind when 'r' then 'table' when 'v' then 'view' when 'm' then 'matview' when 'p' then 'partitioned' else c.relkind::text end,
      'securityInvoker', case when c.relkind = 'v' then coalesce((select lower(o.option_value) in ('on','true','t','yes','y','1')
                                                                   from pg_options_to_table(c.reloptions) o
                                                                   where o.option_name = 'security_invoker' limit 1), false)
                              when c.relkind = 'm' then false end,
      'sources', case when c.relkind in ('v','m') then
                   (select coalesce(jsonb_agg(distinct case when sn.nspname = 'public' then sc.relname else sn.nspname || '.' || sc.relname end), '[]'::jsonb)
                    from pg_rewrite rw
                    join pg_depend d on d.classid = 'pg_rewrite'::regclass and d.objid = rw.oid and d.refclassid = 'pg_class'::regclass
                    join pg_class sc on sc.oid = d.refobjid
                    join pg_namespace sn on sn.oid = sc.relnamespace
                    where rw.ev_class = c.oid and sc.oid <> c.oid and sc.relkind in ('r','p','v','m','f')) end,
      'columns', (select coalesce(jsonb_agg(jsonb_build_object(
                    'name', a.attname, 'type', format_type(a.atttypid, a.atttypmod),
                    'notNull', a.attnotnull,
                    'hasDefault', (a.atthasdef or a.attidentity <> '' or a.attgenerated <> ''),
                    'references', (select jsonb_build_object('table',
                                       case when rn.nspname = 'public' then rc.relname else rn.nspname || '.' || rc.relname end,
                                       'column', ra.attname)
                                   from pg_constraint k
                                   join pg_class rc on rc.oid = k.confrelid
                                   join pg_namespace rn on rn.oid = rc.relnamespace
                                   join pg_attribute ra on ra.attrelid = k.confrelid and ra.attnum = k.confkey[1]
                                   where k.conrelid = c.oid and k.contype = 'f' and k.conkey[1] = a.attnum
                                   limit 1)
                  ) order by a.attnum), '[]'::jsonb)
                  from pg_attribute a where a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped),
      'grants', (select coalesce(jsonb_agg(distinct jsonb_build_object(
                   'grantee', case when a.grantee = 0 then 'PUBLIC' else pg_get_userbyid(a.grantee) end,
                   'privilege', a.privilege_type)), '[]'::jsonb)
                 from aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
                 where (a.grantee = 0 or pg_get_userbyid(a.grantee) in ('anon','authenticated','service_role'))
                   and a.privilege_type <> 'MAINTAIN'),
      'columnGrants', (select coalesce(jsonb_agg(distinct jsonb_build_object(
                         'grantee', case when x.grantee = 0 then 'PUBLIC' else pg_get_userbyid(x.grantee) end,
                         'privilege', x.privilege_type)), '[]'::jsonb)
                       from pg_attribute ca cross join lateral aclexplode(ca.attacl) x
                       where ca.attrelid = c.oid and ca.attnum > 0 and not ca.attisdropped and ca.attacl is not null
                         and (x.grantee = 0 or pg_get_userbyid(x.grantee) in ('anon','authenticated')))
    ) order by n.nspname, c.relname), '[]'::jsonb)
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where c.relkind in ('r','p','v','m') and n.nspname in ('public','storage')
  ),
  'policies', (
    select coalesce(jsonb_agg(jsonb_build_object(
      'schema', p.schemaname, 'table', p.tablename, 'name', p.policyname,
      'permissive', p.permissive, 'roles', p.roles, 'command', p.cmd,
      'using', p.qual, 'withCheck', p.with_check) order by p.schemaname, p.tablename, p.policyname), '[]'::jsonb)
    from pg_policies p where p.schemaname in ('public','storage')
  ),
  'functions', (
    select coalesce(jsonb_agg(jsonb_build_object(
      'schema', n.nspname, 'name', pr.proname,
      'securityDefiner', pr.prosecdef, 'returns', pg_get_function_result(pr.oid),
      'arguments', pg_get_function_arguments(pr.oid),
      'identity', pg_get_function_identity_arguments(pr.oid),
      'body', case when pr.prosecdef then left(coalesce(pr.prosrc, ''), 8000) else null end,
      'readsCaller', coalesce(pr.prosrc, '') ~* 'auth\\.(uid|jwt|email)\\s*\\(|current_setting\\s*\\(\\s*''request\\.jwt',
      'executeGrants', (select coalesce(jsonb_agg(distinct case when a.grantee = 0 then 'PUBLIC' else pg_get_userbyid(a.grantee) end), '[]'::jsonb)
                        from aclexplode(coalesce(pr.proacl, acldefault('f', pr.proowner))) a
                        where a.grantee = 0 or pg_get_userbyid(a.grantee) in ('anon','authenticated','service_role')),
      'changes', case when d.def is null then null else
                   (select coalesce(jsonb_agg(distinct regexp_replace(m[1], '\\s+', '', 'g')), '[]'::jsonb)
                    from regexp_matches(d.def, '\\m(?:update|delete\\s+from|merge\\s+into|truncate(?:\\s+table)?)\\s+(?:only\\s+)?((?:"[^"]+"|[[:alpha:]_][[:alnum:]_$]*)(?:\\s*\\.\\s*(?:"[^"]+"|[[:alpha:]_][[:alnum:]_$]*))?)', 'gi') m)
                   || case when d.def ~* '\\mexecute\\M' then '["*"]'::jsonb else '[]'::jsonb end
                 end
    ) order by n.nspname, pr.proname), '[]'::jsonb)
    from pg_proc pr join pg_namespace n on n.oid = pr.pronamespace
    cross join lateral (select case when pr.prosecdef then null
                                    else regexp_replace(pg_get_functiondef(pr.oid), '/\\*([^*]|\\*+[^*/])*\\*+/|--[^\\n]*', ' ', 'g') end as def) d
    where n.nspname = 'public' and pr.prokind = 'f'
  ),
  'apiSettings', (
    select coalesce(jsonb_agg(x.setting order by x.rank), '[]'::jsonb)
    from (select c.setting, case when s.setrole <> 0 and s.setdatabase <> 0 then 0 when s.setrole <> 0 then 1
                                 when s.setdatabase <> 0 then 2 else 3 end as rank
          from pg_db_role_setting s cross join lateral unnest(s.setconfig) as c(setting)
          where s.setdatabase in (0, (select oid from pg_database where datname = current_database()))
            and s.setrole in (0, coalesce((select oid from pg_roles where rolname = 'authenticator'), 0))
            and (c.setting like 'session_preload_libraries=%' or c.setting like 'safeupdate.%'
                 or c.setting like 'pgrst.db_pre_request=%')
          union all
          select 'safeupdate.enabled=' || current_setting('safeupdate.enabled', true), 4) x
    where x.setting is not null
  ),
  'buckets', (select coalesce(jsonb_agg(jsonb_build_object('id', b.id, 'public', b.public) order by b.id), '[]'::jsonb)
              from storage.buckets b)
) as snapshot;
`;

const BUCKETS = `  'buckets', (select coalesce(jsonb_agg(jsonb_build_object('id', b.id, 'public', b.public) order by b.id), '[]'::jsonb)
              from storage.buckets b)`;

/**
 * The same query for the night watch, run as a role that holds no privilege at all. Everything it
 * reads is the catalog, which every role may read; only storage.buckets is a table, and granting the
 * watch role access to it would be the one grant the role otherwise does not need. Buckets feed only
 * leads, so the watch goes without them and says so.
 */
export const WATCH_SNAPSHOT_QUERY = SNAPSHOT_QUERY.replace(BUCKETS, "  'buckets', '[]'::jsonb");
