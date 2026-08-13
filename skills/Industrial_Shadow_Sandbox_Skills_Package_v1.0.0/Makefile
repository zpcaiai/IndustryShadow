PYTHON ?= python
PYTHON_ABS := $(shell $(PYTHON) -c 'import sys; print(sys.executable)' 2>/dev/null)
PYTHONPATH := backend/src:services/simulator/src:services/collector/src:services/edge-gateway/src
PYTHON_ENV := PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=$(PYTHONPATH)
DB ?= .runtime/shadow-sandbox.db
COMPOSE_CONTRACT_ENV := SHADOW_DEV_DB_PASSWORD=contract-validation-only \
	SHADOW_INTERNAL_SERVICE_TOKEN=contract-validation-not-a-secret-000000000000 \
	SHADOW_SIMULATOR_DIGEST=0000000000000000000000000000000000000000000000000000000000000000 \
	SHADOW_SIMULATOR_BUILD_DIGEST=sha256:0000000000000000000000000000000000000000000000000000000000000000 \
	SHADOW_SIMULATOR_CERTIFICATE_FINGERPRINT=0000000000000000000000000000000000000000000000000000000000000000 \
	SHADOW_NODE_ALLOWLIST=contract-validation-node \
	SHADOW_TRUSTED_RUN_CONTEXT=contract-validation

.PHONY: install-locked bootstrap migrate test lint typecheck python-audit sbom schemas client-contract demo evidence validate postgres-test postgres-restore-test web-test web-e2e web-build web-audit deploy-validate container-smoke measured-benchmark smoke production-gate clean-runtime

install-locked:
	$(PYTHON_ABS) -m pip install --require-hashes -r backend/requirements.lock

bootstrap:
	@mkdir -p .runtime artifacts docs/evidence
	$(PYTHON_ENV) $(PYTHON_ABS) -m shadow_sandbox.cli init --database $(DB)

migrate: bootstrap
	$(PYTHON_ENV) $(PYTHON_ABS) -m shadow_sandbox.cli migrate --database $(DB)

test:
	$(PYTHON_ENV) $(PYTHON_ABS) -m pytest -q

lint:
	$(PYTHON_ENV) $(PYTHON_ABS) -m ruff check backend/src services tests tools

typecheck:
	$(PYTHON_ENV) $(PYTHON_ABS) -m pyright backend/src services

python-audit:
	$(PYTHON_ABS) -m pip_audit --strict --disable-pip --require-hashes -r backend/requirements.lock
	$(PYTHON_ABS) -m pip_audit --strict --disable-pip --require-hashes -r backend/requirements.runtime.lock

sbom:
	@mkdir -p artifacts
	$(PYTHON_ABS) tools/build_runtime_sbom.py --output artifacts/python-runtime-sbom.cdx.json

validate:
	$(PYTHON_ENV) $(PYTHON_ABS) tools/validate_implementation.py
	cd implement-industrial-shadow-sandbox && $(PYTHON_ABS) scripts/validate_batch_contracts.py

postgres-test:
	$(PYTHON_ENV) $(PYTHON_ABS) tools/validate_postgresql.py

postgres-restore-test:
	$(PYTHON_ENV) $(PYTHON_ABS) tools/validate_local_postgresql_restore.py

web-test:
	cd web && npm test

web-e2e:
	cd web && npm run test:e2e

web-build:
	cd web && npm run build

web-audit:
	npm --prefix web audit --audit-level=moderate --registry=https://registry.npmjs.org

deploy-validate:
	$(COMPOSE_CONTRACT_ENV) docker compose -f deploy/compose/compose.yaml config -q
	kubectl kustomize deploy/production >/dev/null

container-smoke:
	$(PYTHON_ABS) tools/validate_container_runtime.py --build

schemas:
	$(PYTHON_ENV) $(PYTHON_ABS) -m shadow_sandbox.cli schemas --output schemas

client-contract:
	$(PYTHON_ENV) $(PYTHON_ABS) tools/generate_frontend_client.py --check

demo: bootstrap
	$(PYTHON_ENV) $(PYTHON_ABS) -m shadow_sandbox.cli demo --database $(DB) --output artifacts/demo

evidence:
	$(PYTHON_ENV) $(PYTHON_ABS) tools/build_evidence.py

measured-benchmark:
	$(PYTHON_ENV) $(PYTHON_ABS) tools/production_gate.py benchmark_local --output artifacts/measured-benchmark/gate-evidence.json --summary artifacts/measured-benchmark/summary.json

smoke:
	$(PYTHON_ENV) $(PYTHON_ABS) tools/validate_implementation.py
	cd implement-industrial-shadow-sandbox && $(PYTHON_ABS) scripts/validate_batch_contracts.py
	$(PYTHON_ENV) $(PYTHON_ABS) -m ruff check backend/src services tests tools
	$(PYTHON_ENV) $(PYTHON_ABS) -m pyright backend/src services
	$(MAKE) python-audit PYTHON=$(PYTHON_ABS)
	$(MAKE) sbom PYTHON=$(PYTHON_ABS)
	$(PYTHON_ENV) $(PYTHON_ABS) -m pytest -q
	cd web && npm test
	cd web && npm run test:e2e
	cd web && npm run build
	npm --prefix web audit --audit-level=moderate --registry=https://registry.npmjs.org
	$(COMPOSE_CONTRACT_ENV) docker compose -f deploy/compose/compose.yaml config -q
	kubectl kustomize deploy/production >/dev/null
	$(PYTHON_ABS) tools/validate_container_runtime.py --build
	$(PYTHON_ENV) $(PYTHON_ABS) -m shadow_sandbox.cli schemas --output schemas
	$(PYTHON_ENV) $(PYTHON_ABS) tools/generate_frontend_client.py --check
	$(PYTHON_ENV) $(PYTHON_ABS) -m shadow_collector.runner --help >/dev/null
	$(PYTHON_ENV) $(PYTHON_ABS) -m shadow_sandbox.worker --help >/dev/null
	$(PYTHON_ENV) $(PYTHON_ABS) -m shadow_sandbox.cli init --database .runtime/smoke.db
	$(PYTHON_ENV) $(PYTHON_ABS) -m shadow_sandbox.cli demo --database .runtime/smoke.db --output artifacts/demo-smoke
	$(PYTHON_ENV) $(PYTHON_ABS) tools/production_gate.py benchmark_local --output artifacts/measured-benchmark/smoke-gate-evidence.json --summary artifacts/measured-benchmark/smoke-summary.json

production-gate:
	@test -n "$(GATE)" || (echo "GATE is required" && exit 2)
	@test -n "$(OUTPUT)" || (echo "OUTPUT is required" && exit 2)
	$(PYTHON_ENV) $(PYTHON_ABS) tools/production_gate.py $(GATE) --output $(OUTPUT)

clean-runtime:
	@echo "Refusing to remove runtime data automatically; delete .runtime explicitly if intended."
