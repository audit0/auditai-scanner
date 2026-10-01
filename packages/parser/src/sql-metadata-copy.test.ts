import { describe, expect, it } from "vitest";
import { metadataCopiesIn } from "./sql-metadata-copy.js";

describe("metadataCopiesIn", () => {
  it("reads INSERT ... VALUES with coalesce, casts and arrays", () => {
    const body = `begin
  insert into public.profiles (id, email, role, user_types, full_name)
  values (new.id, new.email, coalesce((new.raw_user_meta_data ->> 'role')::public.user_role, 'student'::public.user_role),
          array[new.raw_user_meta_data ->> 'user_type'], new.raw_user_meta_data ->> 'full_name');
  return new;
end`;
    expect(metadataCopiesIn(body)).toEqual([
      { table: "profiles", column: "role", key: "role" },
      { table: "profiles", column: "user_types", key: "user_type" },
      { table: "profiles", column: "full_name", key: "full_name" },
    ]);
  });

  it("follows a local variable and reads INSERT ... SELECT and UPDATE ... SET", () => {
    const body = `declare v_role text;
begin
  v_role := coalesce(new.raw_user_meta_data ->> 'role', 'member');
  insert into profiles (id, role) select new.id, v_role;
  update public.members set salon_id = (new.raw_user_meta_data ->> 'salon_id')::uuid where user_id = new.id;
  return new;
end`;
    expect(metadataCopiesIn(body)).toEqual([
      { table: "profiles", column: "role", key: "role" },
      { table: "members", column: "salon_id", key: "salon_id" },
    ]);
  });

  it("stays silent on an allow-list, a constant, or an expression that changes the value", () => {
    const body = `begin
  insert into profiles (id, role, plan, name)
  values (new.id,
    case when new.raw_user_meta_data ->> 'role' in ('student', 'teacher') then new.raw_user_meta_data ->> 'role' else 'student' end,
    'free',
    (new.raw_user_meta_data ->> 'first') || ' ' || (new.raw_user_meta_data ->> 'last'));
  return new;
end`;
    expect(metadataCopiesIn(body)).toEqual([]);
  });

  it("survives malformed input", () => {
    expect(
      metadataCopiesIn("insert into profiles (role) values (new.raw_user_meta_data ->>"),
    ).toEqual([]);
    expect(metadataCopiesIn("raw_user_meta_data")).toEqual([]);
    expect(metadataCopiesIn("")).toEqual([]);
  });
});

describe("metadataCopiesIn, further shapes", () => {
  it("reads a variable holding the whole metadata object, and any COALESCE argument", () => {
    const body = `declare v_meta jsonb;
begin
  v_meta := new.raw_user_meta_data;
  insert into profiles (id, user_types) values (new.id, array[coalesce(v_meta ->> 'user_type', 'client')]::text[]);
  insert into staff (id, role) values (new.id, coalesce(nullif(new.raw_app_meta_data ->> 'role', ''), nullif(new.raw_user_meta_data ->> 'role', ''), 'member'));
  return new;
end`;
    expect(metadataCopiesIn(body)).toEqual([
      { table: "profiles", column: "user_types", key: "user_type" },
      { table: "staff", column: "role", key: "role" },
    ]);
  });
});

describe("metadataCopiesIn, declarations", () => {
  it("reads a variable declared with a type before :=", () => {
    const body = `declare
  v_meta jsonb := new.raw_user_meta_data;
  v_role public.user_role := (v_meta ->> 'role')::public.user_role;
begin
  insert into profiles (id, role) values (new.id, v_role);
  return new;
end`;
    expect(metadataCopiesIn(body)).toEqual([{ table: "profiles", column: "role", key: "role" }]);
  });
});
