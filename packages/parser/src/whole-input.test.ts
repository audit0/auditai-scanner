import ts from "typescript";
import { describe, expect, it } from "vitest";
import { parseSource } from "./ast.js";
import { isWholeInput, type WholeContext, wholeParamNames } from "./whole-input.js";

/** `body`, `formData` and `rows` hold whole request objects; `req` is the request. */
const cx: WholeContext = {
  wholeName: (n) => n === "body" || n === "formData" || n === "rows",
  requestBody: (c) =>
    ts.isPropertyAccessExpression(c.expression) &&
    ts.isIdentifier(c.expression.expression) &&
    c.expression.expression.text === "req" &&
    /^(json|formData|text)$/.test(c.expression.name.text),
  requestName: (n) => n === "req",
  // Only `allowList` resolves to an object schema here; `schema` is unknown, as an imported
  // name we cannot read would be.
  strippingSchema: (e) => ts.isIdentifier(e) && e.text === "allowList",
};

function expr(code: string): ts.Expression {
  const sf = parseSource("x.ts", `const x = ${code};`);
  const stmt = sf.statements[0];
  if (!stmt || !ts.isVariableStatement(stmt)) throw new Error("not a variable statement");
  const init = stmt.declarationList.declarations[0]?.initializer;
  if (!init) throw new Error("no initializer");
  return init;
}

const whole = (code: string): boolean => isWholeInput(expr(code), cx);

describe("isWholeInput", () => {
  it("treats the request object and copies of it as whole", () => {
    expect(whole("body")).toBe(true);
    expect(whole("await req.json()")).toBe(true);
    expect(whole("{ ...body, owner_id: user.id }")).toBe(true);
    expect(whole("Object.fromEntries(formData)")).toBe(true);
    // An unresolvable schema keeps the payload whole: it may pass every key through.
    expect(whole("schema.parse(await req.json())")).toBe(true);
    expect(whole("parseBody(req)")).toBe(true);
    expect(whole("body.profile")).toBe(true);
    expect(whole("[body]")).toBe(true);
    expect(whole("cond ? body : {}")).toBe(true);
  });

  it("does not treat a parse through a schema of this project as whole", () => {
    expect(whole("allowList.parse(await req.json())")).toBe(false);
    expect(whole("allowList.safeParse(body).data")).toBe(false);
    expect(whole("allowList.parse(body)")).toBe(false);
  });

  it("does not treat an allow-list of explicit fields as whole", () => {
    expect(whole("{ name: body.name, owner_id: user.id }")).toBe(false);
    expect(whole("[{ email: body.email }]")).toBe(false);
    expect(whole('formData.get("id")')).toBe(false);
    expect(whole("user")).toBe(false);
  });

  it("keeps elements through filter/slice, and a map callback that returns or spreads them", () => {
    expect(whole("rows.filter((r) => r.ok)")).toBe(true);
    expect(whole("rows.map((r) => r)")).toBe(true);
    expect(whole("rows.map((r) => ({ ...r, owner_id: user.id }))")).toBe(true);
    expect(whole("rows.map(normalize)")).toBe(true);
  });

  it("does not treat a map callback that rebuilds explicit fields as whole (ai-chatbot, DeskcommCRM)", () => {
    expect(
      whole(
        "rows.map((m) => ({ id: generateUUID(), chat_id: id, role: m.role, content: format(m), created_at: now }))",
      ),
    ).toBe(false);
    expect(
      whole(`rows.map((m) => {
        const messageId = generateUUID();
        return { id: messageId, chat_id: id, role: m.role };
      })`),
    ).toBe(false);
    expect(whole("ids.map((id) => ({ id }))")).toBe(false);
  });
});

describe("wholeParamNames", () => {
  function param(code: string): ts.BindingName {
    const sf = parseSource("x.ts", `function f(${code}) {}`);
    const fn = sf.statements[0];
    if (!fn || !ts.isFunctionDeclaration(fn)) throw new Error("not a function");
    const p = fn.parameters[0];
    if (!p) throw new Error("no parameter");
    return p.name;
  }

  it("maps an object literal argument onto a destructured parameter property by property", () => {
    expect(
      wholeParamNames(
        param("{ chatId, messages }"),
        expr("{ chatId: id, messages: body.messages }"),
        cx,
      ),
    ).toEqual(["messages"]);
    expect(wholeParamNames(param("{ chatId, messages }"), expr("{ ...body }"), cx)).toEqual([
      "chatId",
      "messages",
    ]);
  });

  it("binds a plain parameter whole only when the argument is whole", () => {
    expect(wholeParamNames(param("user"), expr("body"), cx)).toEqual(["user"]);
    expect(wholeParamNames(param("row"), expr("{ name: body.name }"), cx)).toEqual([]);
  });
});
