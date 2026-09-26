import { describe, expect, it } from "vitest";
import { formatSpecifiers, paramsReachingExecute } from "./sql-dynamic.js";

const text = (...names: string[]) => names.map((name) => ({ name, type: "text" }));

describe("paramsReachingExecute", () => {
  it("finds a parameter glued into EXECUTE with ||", () => {
    const body = `begin
  return query execute 'select * from public.orders where status = ''' || p_status || '''';
end`;
    expect(paramsReachingExecute(body, text("p_status"))).toEqual(["p_status"]);
  });

  it("finds a parameter passed to format through %s, and not the one behind %L", () => {
    const body = `begin
  execute format('select count(*) from %s where owner = %L', p_table, p_owner) into n;
end`;
    expect(paramsReachingExecute(body, text("p_table", "p_owner"))).toEqual(["p_table"]);
  });

  it("follows positional format specifiers", () => {
    const body = `begin execute format('select %2$s from t where a = %1$L', p_a, p_b); end`;
    expect(paramsReachingExecute(body, text("p_a", "p_b"))).toEqual(["p_b"]);
  });

  it("finds a statement the caller passes whole", () => {
    expect(paramsReachingExecute("begin execute query; end", text("query"))).toEqual(["query"]);
  });

  it("follows a local variable built from the parameter", () => {
    const body = `declare v_sql text;
begin
  v_sql := 'select * from public.orders where 1 = 1';
  v_sql := v_sql || ' and status = ''' || p_status || '''';
  return query execute v_sql;
end`;
    expect(paramsReachingExecute(body, text("p_status"))).toEqual(["p_status"]);
  });

  it("reads FOR ... IN EXECUTE and OPEN ... FOR EXECUTE", () => {
    const loop = `begin for r in execute 'select * from ' || p_t loop return next r; end loop; end`;
    expect(paramsReachingExecute(loop, text("p_t"))).toEqual(["p_t"]);
    const cursor = `begin open c for execute 'select * from t order by ' || p_sort; end`;
    expect(paramsReachingExecute(cursor, text("p_sort"))).toEqual(["p_sort"]);
  });

  it("stays silent when the value goes through USING", () => {
    const body = `begin
  return query execute 'select * from public.orders where status = $1' using p_status;
end`;
    expect(paramsReachingExecute(body, text("p_status"))).toEqual([]);
  });

  it("stays silent on quote_literal, quote_ident, quote_nullable and format %I / %L", () => {
    const body = `begin
  execute 'select * from ' || quote_ident(p_t) || ' where a = ' || quote_literal(p_a)
    || ' and b = ' || quote_nullable(p_b);
  execute format('delete from %I where c = %L', p_t, p_c);
end`;
    expect(paramsReachingExecute(body, text("p_t", "p_a", "p_b", "p_c"))).toEqual([]);
  });

  it("stays silent on a variable built only from quoted parts", () => {
    const body = `declare v_sql text;
begin
  v_sql := format('select * from %I', p_t);
  execute v_sql;
end`;
    expect(paramsReachingExecute(body, text("p_t"))).toEqual([]);
  });

  it("ignores parameters that cannot carry SQL text", () => {
    const body = `begin execute 'select * from t where id = ''' || p_id || ''' limit ' || p_n; end`;
    const params = [
      { name: "p_id", type: "uuid" },
      { name: "p_n", type: "integer" },
    ];
    expect(paramsReachingExecute(body, params)).toEqual([]);
  });

  it("ignores a text parameter cast to a type that cannot carry SQL", () => {
    const body = `begin
  execute 'select * from ' || p_t::regclass || ' limit ' || p_n::int;
end`;
    expect(paramsReachingExecute(body, text("p_t", "p_n"))).toEqual([]);
  });

  it("treats a parameter checked against a list of literals as an allow-list", () => {
    const body = `begin
  if p_col not in ('created_at', 'amount') then raise exception 'bad column'; end if;
  if p_dir <> all (array['asc', 'desc']) then raise exception 'bad direction'; end if;
  return query execute 'select * from t order by ' || p_col || ' ' || p_dir;
end`;
    expect(paramsReachingExecute(body, text("p_col", "p_dir"))).toEqual([]);
  });

  it("ignores EXECUTE inside string literals and trigger or grant statements", () => {
    const body = `begin
  raise notice 'execute ' || p_x;
  execute 'create trigger t after insert on x for each row execute function f()';
  execute 'grant execute on function f() to anon';
end`;
    expect(paramsReachingExecute(body, text("p_x"))).toEqual([]);
  });

  it("reads a parameter in a format string built at run time as unsafe", () => {
    const body = `begin execute format(v_template, p_x); end`;
    expect(paramsReachingExecute(body, text("p_x"))).toEqual(["p_x"]);
  });

  it("counts varchar, jsonb and text arrays as text", () => {
    const body = `begin execute 'select ' || p_a || p_b || p_c; end`;
    const params = [
      { name: "p_a", type: "character varying(40)" },
      { name: "p_b", type: "jsonb" },
      { name: "p_c", type: "text[]" },
    ];
    expect(paramsReachingExecute(body, params)).toEqual(["p_a", "p_b", "p_c"]);
  });

  it("survives malformed input", () => {
    expect(paramsReachingExecute("begin execute format('%s', ", text("p"))).toEqual([]);
    expect(paramsReachingExecute("execute", text("p"))).toEqual([]);
    expect(paramsReachingExecute("", [])).toEqual([]);
    expect(paramsReachingExecute("begin execute 'x' || (p; end", text("p"))).toEqual(["p"]);
  });
});

describe("formatSpecifiers", () => {
  it("numbers conversions and skips %%", () => {
    expect([...formatSpecifiers("%s %% %I %L")]).toEqual([
      [1, "s"],
      [2, "I"],
      [3, "L"],
    ]);
  });

  it("reads positions and widths", () => {
    // A plain %s after %1$s takes argument 2, which %2$I already quotes: it lands unquoted too.
    expect([...formatSpecifiers("%2$I %1$-10s %s")]).toEqual([
      [2, "s"],
      [1, "s"],
    ]);
    expect([...formatSpecifiers("%2$I %1$-10s")]).toEqual([
      [2, "I"],
      [1, "s"],
    ]);
    expect([...formatSpecifiers("%*s")]).toEqual([[2, "s"]]);
  });

  it("keeps %s when a position is used both ways", () => {
    expect(formatSpecifiers("%1$I %1$s").get(1)).toBe("s");
  });
});
