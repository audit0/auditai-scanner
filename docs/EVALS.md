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
