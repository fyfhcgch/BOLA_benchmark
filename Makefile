VENV := .venv
PY   := $(VENV)/bin/python

.PHONY: setup serve run run-crapi run-vampi test clean \
        bench-stats bench-figure result-figures zap-aggregate random-baseline \
        failure-modes ablate-all ablate-report

setup:
	python3 -m venv --system-site-packages $(VENV)
	$(VENV)/bin/pip install -q esprima

serve:
	$(PY) systems/mock/app.py

run:
	$(PY) -m pipeline.run --system mock

run-crapi:
	$(PY) -m pipeline.run --system crapi

run-vampi:
	$(PY) -m pipeline.run --system vampi

test:
	$(PY) -m pytest -q

bench-stats:
	$(PY) bench/stats.py
	$(PY) bench/stats.py --manifest results/processed/bench_manifest.json

bench-figure:
	$(PY) bench/plot_benchmark.py

result-figures: failure-modes
	$(PY) bench/plot_results.py

zap-aggregate:
	$(PY) baselines/zap/aggregate.py

random-baseline:
	$(PY) baselines/random_baseline.py

failure-modes:
	$(PY) baselines/zap/failure_modes.py

ablate-all:
	$(PY) -m pipeline.run --system mock --no-ast --tag no_ast
	$(PY) -m pipeline.run --system crapi --skip-crawl --no-ast --tag no_ast
	$(PY) -m pipeline.run --system vampi --no-ast --tag no_ast
	$(PY) -m pipeline.run --system mock --no-infer-owner --tag no_owner
	$(PY) -m pipeline.run --system crapi --skip-crawl --no-infer-owner --tag no_owner
	$(PY) -m pipeline.run --system vampi --no-infer-owner --tag no_owner
	$(PY) -m pipeline.run --system mock --judge similarity --tag sim_suppress
	$(PY) -m pipeline.run --system crapi --skip-crawl --judge similarity --tag sim_suppress
	$(PY) -m pipeline.run --system vampi --judge similarity --tag sim_suppress
	$(PY) -m pipeline.run --system mock --no-write-check --tag writecheck_off
	$(PY) -m pipeline.run --system crapi --skip-crawl --no-write-check --tag writecheck_off
	$(PY) -m pipeline.run --system vampi --no-write-check --tag writecheck_off
	$(PY) -m pipeline.run --system mock --owner-key-only --tag keyonly
	$(PY) -m pipeline.run --system crapi --skip-crawl --owner-key-only --tag keyonly
	$(PY) -m pipeline.run --system vampi --owner-key-only --tag keyonly

ablate-report:
	$(PY) bench/ablation_report.py --csv results/processed/metrics.csv

clean:
	rm -rf results/raw pipeline/__pycache__
