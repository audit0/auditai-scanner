# Evals

Every rule change is measured against this corpus before release. See `docs/EVALS.md` for the
methodology. Run the gate with `npm run evals`.

Each fixture is a pair of runnable Next.js + Supabase apps: `vulnerable/` must fire exactly the
expected rule, `secure/` must produce zero findings. The harness in `harness/fixtures.test.ts`
enforces both.

```
NNN-short-name/
  README.md
  ground-truth.json         what is true about this fixture
  expected-finding.json     what the scanner must report (and must not report)
  supabase/migrations/      schema + RLS shared by both variants (or per variant)
  security-test/            the DENY/ALLOW regression test the hosted product runs in a sandbox
  vulnerable/               Next.js app with the bug
  secure/                   same app, minimal correct fix
```

New fixture: `python3 evals/scripts/scaffold.py evals/fixtures/NNN-name` creates both shells.

Rules of the corpus: never alter expected outcomes to make a rule pass, never remove a difficult
fixture, never weaken a security assertion.

The fixture list with the rule each one exercises is in the root README.
