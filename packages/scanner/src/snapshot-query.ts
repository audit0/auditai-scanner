/**
 * The read-only query a user runs in their own SQL editor to get a snapshot of what their database
 * lets people do (ADR-005). It is the product's front door, so it is written to be read by the person
 * who runs it: every part says what it reads, and nothing in it writes, changes or reads a row of data.
 *
 * Only catalog metadata leaves the database: table and column names, whether RLS is on, the policies
 * with their roles and conditions, who may execute which function, the storage buckets. The source of
 * a function is included only for SECURITY DEFINER functions — the ones that run with more rights than
 * their caller and so are the only ones whose body the rules judge. For every other function the
 * query sends one boolean: whether its body reads the caller's identity.
 *
 * Grants are read from the ACLs in pg_class and pg_proc, not from information_schema: the
 * information_schema views list only grants to roles the current user belongs to, so the same query
 * run as a role outside anon (the Supabase MCP server in read-only mode, a monitoring role) would
 * report no grants and every function as uncallable. The ACLs read the same under any role, and they
 * are per function, so overloads no longer share their grants. The only privilege a function's ACL
 * holds is the right to run it, so its entries need no filter by kind.
 *
 * The output is compact JSON (no jsonb_pretty) because it is pasted by hand. `evals/realworld/
 * schema-probe/live-snapshot.sql` is a copy kept for the measurement scripts; a test keeps them equal.
 */
export const SNAPSHOT_QUERY = `-- Audit AI: a read-only snapshot of what your database lets people do.
-- It reads names and rules: tables, whether row level security is on, policies and their
-- conditions, who may run which function, storage buckets, and the source code of SECURITY DEFINER
-- functions (the ones that run with their owner's rights). It writes nothing, changes nothing,
-- and reads no row of your data. Run it, look at the result, then decide whether to paste it.
select jsonb_build_object(
  'snapshotVersion', 1,
  'takenAt', now(),
  'postgres', current_setting('server_version'),
  'tables', (
    select coalesce(jsonb_agg(jsonb_build_object(
      'schema', n.nspname, 'name', c.relname, 'rlsEnabled', c.relrowsecurity, 'rlsForced', c.relforcerowsecurity,
      'kind', case c.relkind when 'r' then 'table' when 'v' then 'view' when 'm' then 'matview' when 'p' then 'partitioned' else c.relkind::text end,
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
                   and a.privilege_type <> 'MAINTAIN')
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
                        where a.grantee = 0 or pg_get_userbyid(a.grantee) in ('anon','authenticated','service_role'))
    ) order by n.nspname, pr.proname), '[]'::jsonb)
    from pg_proc pr join pg_namespace n on n.oid = pr.pronamespace
    where n.nspname = 'public' and pr.prokind = 'f'
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
