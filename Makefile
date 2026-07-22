.PHONY: test demo workflow-demo codex-demo schemas check-schemas reports check-reports clean-install evaluate evaluate-all ablate compile secret-scan dependency-check release-audit verify

test:
	PYTHONPATH=src python3 -m unittest discover -s tests -v

demo:
	PYTHONPATH=src python3 -m agentsec demo --pretty

workflow-demo:
	PYTHONPATH=src python3 -m agentsec workflow-demo --pretty

codex-demo:
	PYTHONPATH=src python3 -m agentsec codex-demo --pretty

schemas:
	PYTHONPATH=src python3 tools/generate_schemas.py

check-schemas:
	PYTHONPATH=src python3 tools/generate_schemas.py --check

reports:
	PYTHONPATH=src python3 tools/write_release_reports.py

check-reports:
	PYTHONPATH=src python3 tools/write_release_reports.py --check

clean-install:
	python3 tools/verify_clean_install.py

evaluate:
	PYTHONPATH=src python3 -m agentsec evaluate --mode deterministic --pretty

evaluate-all:
	PYTHONPATH=src python3 -m agentsec evaluate --mode unprotected
	PYTHONPATH=src python3 -m agentsec evaluate --mode telemetry_only
	PYTHONPATH=src python3 -m agentsec evaluate --mode static_allowlist
	PYTHONPATH=src python3 -m agentsec evaluate --mode sink_without_provenance
	PYTHONPATH=src python3 -m agentsec evaluate --mode provenance_without_authority
	PYTHONPATH=src python3 -m agentsec evaluate --mode deterministic
	PYTHONPATH=src python3 -m agentsec evaluate --mode codex_shadow
	PYTHONPATH=src python3 -m agentsec evaluate --mode semantic_hold

ablate:
	PYTHONPATH=src python3 -m agentsec ablate --pretty

compile:
	PYTHONPYCACHEPREFIX=/tmp/agentsec-pycache python3 -m compileall -q src tests tools

secret-scan:
	python3 tools/scan_secrets.py

dependency-check:
	python3 -m pip check

release-audit: check-schemas check-reports test clean-install compile secret-scan dependency-check
	PYTHONPATH=src python3 tools/release_audit.py

verify: release-audit workflow-demo codex-demo evaluate-all ablate
