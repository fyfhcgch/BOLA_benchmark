# BOLA Benchmark

Public artifact for the paper **“A Benchmark and Empirical Evaluation of
Object-Level Authorization (BOLA) Detection in Web Applications”**.

The repository contains the benchmark annotations, the capture / replay /
judging pipeline, the containerized testbeds, and every processed result file
used in the paper. The manuscript itself is **not** part of this repository
while it is under review.

## What is inside

| Directory | Contents |
|---|---|
| `bench/` | Label statistics, manifest (per-file sha256), plotting, reliability (κ) scoring |
| `baselines/` | OWASP ZAP Access Control runs, aggregation, failure-mode attribution, random lower bound |
| `pipeline/` | Capture → API recovery → parameter/owner inference → replay → judging |
| `systems/` | `mock` (self-built Flask shop + secure twin), `crapi`, `vampi`; image digests in `IMAGE_DIGESTS.md` |
| `results/` | Raw runs, `processed/metrics.csv`, per-system JSON, `bench_manifest.json` |
| `tests/` | Unit tests for object-instance keys, metric layer, label consistency |
| `docs/` | Labeling specification, pilot findings, ablation notes |

## Dataset at a glance

- 3 vulnerable applications (Python/Flask, Java/Go, Python/Flask API-only)
- 107 object-instance-level labels (`mock` 50, `crAPI` 45, `VAmPI` 12)
- 45 safe controls attributed to five causes (ownership check, public resource,
  method not allowed, no owner evidence, identifier ignored)
- 1 whole-system clean control (same code as `mock`, only `MOCK_POLICY` switched)
  with 50 safe instances
- 1,026 replay cases (354 / 354 / 282 / 36)
- Label unit: `(method, path_template, object_ids)`

## Quick start

```bash
make setup                  # python venv + esprima
make serve                  # terminal 1: self-built mock shop (port 8765)
python3 systems/mock/app_secure.py   # optional: secure twin (port 8766)
make run                    # terminal 2: full pipeline on mock

# real testbeds
docker compose -f systems/crapi/docker-compose.yml up -d && python3 systems/crapi/seed.py
python3 -m pipeline.run --system crapi
docker compose -f systems/vampi/docker-compose.yml up -d && python3 systems/vampi/seed.py
python3 -m pipeline.run --system vampi

make test                   # unit tests
```

## Reproducing the reported numbers

```bash
make bench-stats            # tables + results/processed/bench_manifest.json (sha256)
make bench-figure           # benchmark composition figure
make result-figures         # RQ1 and failure-mode figures
make zap-aggregate          # baseline table from baselines/zap/*/summary.json
make random-baseline        # chance-level F1 with 95% CI
make ablate-all && make ablate-report
```

All numbers in the paper are computed from `results/processed/` and
`baselines/zap/`; none are transcribed by hand.

## Reproducibility fingerprints

Two fingerprints must be cited together, because a rebuilt testbed changes
object identifiers (UUID / VIN / NanoID):

1. `results/processed/bench_manifest.json` — per-label-file sha256 + `bench_version`
2. `systems/IMAGE_DIGESTS.md` — container image digests for crAPI and VAmPI

## License

- Code (`bench/`, `baselines/`, `pipeline/`, `systems/`, `tests/`): MIT, see `LICENSE`.
- Annotations, result files and documentation: CC BY 4.0, see `DATA_LICENSE.md`.

## Citation

While the paper is under review, please cite the artifact by its tag:

```bibtex
@misc{bola_benchmark_v1,
  title  = {BOLA Benchmark: annotations, pipeline and results},
  author = {Xie, Shaosong},
  year   = {2026},
  note   = {Version bench-v1.0},
  url    = {https://github.com/fyfhcgch/BOLA_benchmark}
}
```

## Scope and ethics

All experiments run against open-source applications deployed locally in an
isolated Docker network. No production system, third-party service, or real
user data was accessed, and no public host was scanned. Write-type tests have
real side effects, so every case carries setup/teardown; `mock` and `clean`
expose an explicit reset endpoint.
