# Public benchmark snapshot

> This is a development snapshot, not a survey of the agent-skill ecosystem and not stable-v1
> evidence.

The checked-in Windows result dated 2026-07-16 exercises a small, versioned corpus containing
synthetic defects, multilingual benign fixtures, hostile fixtures, functional scenarios, and two
separately licensed upstream skill-creator snapshots. It is designed to make regressions visible,
not to estimate how often defects occur in the wild.

| Metric | Development result | Denominator |
| --- | ---: | ---: |
| Highlighted precision | 100% | 4 highlighted findings |
| Benign false-positive rate | 0% | 6 benign cases |
| Static completion | 100% | 15 supported cases |
| Causal classification accuracy | 100% | 10 scenarios |
| Reproduction consistency | 90% | 10 scenarios |
| Containment and canary checks | 100% | 13 checks |
| Fault-injection checks | 100% | 8 checks |
| Public functional checks | 100% | 9 scenarios |

The corresponding result file is
[`benchmarks/results/0.1.0.dev0-windows.json`](../benchmarks/results/0.1.0.dev0-windows.json).
The result's maximum supported promotion stage is `public_preview_candidate`.

## Missing external evidence

The snapshot does not provide independently attested Windows, macOS, and Linux release artifacts,
a rotating held-out evaluation, private design-partner alpha outcomes, a completed remediation
period, public-preview completion, or protected release-evidence attestation. Those limitations
remain explicit release blockers.

## Reproduce the public candidate gate

```console
python scripts/run_benchmark.py \
  --manifest benchmarks/public/v1/manifest.json \
  --causal benchmarks/public/v1/causal.json \
  --known-escapes security/known-sandbox-escapes.json \
  --junit validation.xml \
  --platform windows \
  --public-gate \
  --output public-benchmark-windows.json
```

Read [Benchmarks and provenance](BENCHMARKS_AND_PROVENANCE.md) before comparing or extending the
corpus.
