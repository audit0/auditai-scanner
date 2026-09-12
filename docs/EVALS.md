# Evals

## Purpose

Every model, prompt, rule and router change must be measured.

## Initial corpus

Target: 50 curated cases.

- 10 authorization;
- 10 BOLA/IDOR;
- 10 Supabase RLS;
- 5 multi-tenancy;
- 5 authentication;
- 5 injection;
- 5 SSRF/webhook/file.

## Each fixture contains

```text
fixture/
  vulnerable/
  secure/
  ground-truth.json
  expected-finding.json
  security-test/
```

## Ground truth

Must specify:

- vulnerability exists;
- vulnerability class;
- severity;
- vulnerable path;
- expected secure behavior;
- acceptable fixes.

## Metrics

### Detection Recall

TP / (TP + FN)

### Finding Precision

TP / (TP + FP)

### False Positive Share

FP / all findings

### Fix Acceptance Proxy

Valid minimal fixes / proposed fixes

### Verified Fix Rate

Verified fixes / attempted fixes

### Regression Safety

Fixes passing original tests / applied fixes

## Blocking target

Blocking precision matters more than broad recall in v0.

We prefer:

5 important true findings

over:

100 noisy findings.

## Model comparison

For every eval release compare:

- deterministic only;
- deterministic + Opus;
- deterministic + Opus + Fable escalation.

Fable is enabled only where measured improvement justifies cost.

## No eval cheating

Never:

- alter expected outcome to make model pass;
- remove difficult fixture;
- weaken security assertion;
- leak expected answer into model context.

## Real-world labeled sample

Fixtures measure recall on bugs we planted. Precision on code nobody planted is measured separately: a scan over public Next.js + Supabase repositories found through GitHub search, after which a person reads the code behind every finding and gives it one label.

- `real`: an attacker in one tenant or user can reach another's data or a privileged action, or the finding names a control that is genuinely missing (for example a SECURITY DEFINER function that anon can execute).
- `false_positive`: a control exists that the rule missed (an ownership check in code, RLS enabled through dynamic SQL, a credential check the rule does not recognize), or the data is public by design and the code or policy says so.
- `unsure`: reading the code cannot settle it; the reason says what is missing.

Precision is `real / (real + false_positive)`, per rule and overall; unsure labels are reported as a share but never enter the figure. The sample is not random (GitHub search), the labels come from reading code rather than running attacks, and a label can be wrong. The repositories, the findings and the labels stay in the private repository: they name third-party projects and some findings may be real vulnerabilities. Only the per-rule counts are published, on https://auditai.sh/stats under "Hand-labeled sample".

When the scanner changes, the labels stay fixed and the published figures cover only the labeled findings the new build still reports (`node evals/realworld/summarize.mjs --results <dir> --commit <sha> --date <day>`); the sample records the results directory it is based on, and a finding labeled real must never disappear. Because those fixes were made while looking at the labels, such a figure is not a blind measurement; a fresh, unlabeled sample is required for that.
