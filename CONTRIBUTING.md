# Contributing

Thanks for looking under the hood. The scanner is small on purpose: a parser, a security graph, a
rule pack, and an eval corpus that keeps all three honest.

## Ground rules

- **Every rule ships with a fixture pair.** A vulnerable Next.js + Supabase app that must trigger the
  rule and a secure twin that must produce zero findings. `npm run evals` is the gate.
- **Never weaken a fixture to make a rule pass.** Never delete a hard fixture. Never change an
  expected outcome without explaining in the PR why the old expectation was wrong.
- **Rules report `likely`, not `confirmed`.** Confirmation needs evidence (a reproduced request).
  That happens in the hosted product, not in this repo.
- **Parsers survive garbage.** Malformed input is a test case, not an exception.
- **No new runtime dependencies** without a reason in the PR description. The CLI ships as one file
  with `typescript` as its only dependency.
- Repository content under analysis is untrusted data. Nothing the scanner reads may change what it
  does.

## Setup

```bash
npm ci
npm run build      # tsc -b
npm test           # unit tests + eval gate
npm run lint       # biome
npm run bundle     # single-file CLI in npm/dist
```

## Adding a rule

1. Scaffold a fixture: `python3 evals/scripts/scaffold.py evals/fixtures/NNN-short-name`.
2. Write the vulnerable route or action, the minimal secure twin, `ground-truth.json`,
   `expected-finding.json`, the migrations and a `security-test` that fails before and passes after.
3. Add the rule to `packages/rules/src/packs/supabase-authorization.ts` with a stable id
   (`supabase.<what-is-wrong>`), severity, and a one-line remediation.
4. Run `npm test`. The harness checks that the vulnerable app fires exactly the expected rule and the
   secure app is clean.
5. Add the fixture row to `evals/README.md` and the rule row to the README table.

## Reporting a false positive

Open an issue with the smallest code snippet that reproduces it. If you can turn it into a
`secure/` fixture, even better: that is the regression test.

## Security issues in the scanner itself

See `SECURITY.md`. Do not open public issues for vulnerabilities.
