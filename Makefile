# Pacioli Makefile
# =============================================================================
# Targets (this Makefile is for the scanner repo itself, NOT for consumers):
#   make help        - Print the target list
#   make test        - Run pytest (35 tests across 4 files)
#   make lint        - shellcheck + py_compile
#   make selftest    - Safety invariant self-test (read-only guard)
#   make install     - Install scanner deps
#   make clean       - Remove build artifacts
#
# For CONSUMING the scanner from a Terraform repo, see the wrapper Makefile
# in `examples/Makefile.consumer` (copy it as `Makefile.pacioli` into your
# Terraform repo, set `PACIOLI_DIR` to point at this checkout).
# =============================================================================

.PHONY: help test lint selftest install clean

SCANNER_DIR := scanner

help:
	@echo "Pacioli scanner targets (this Makefile is for the scanner repo):"
	@echo "  make test            - Run pytest ($(SCANNER_DIR)/tests)"
	@echo "  make lint            - shellcheck + py_compile"
	@echo "  make selftest        - Safety invariant self-test"
	@echo "  make install         - pip install -r requirements + pytest + pyyaml"
	@echo "  make clean           - Remove __pycache__ and test artifacts"
	@echo ""
	@echo "For consuming Pacioli from a Terraform repo, see:"
	@echo "  examples/Makefile.consumer"
	@echo ""
	@echo "Documentation:"
	@echo "  docs/INDEX.md        - Master table of contents"
	@echo "  docs/OPERATOR_GUIDE.md"
	@echo "  docs/DEVELOPER_GUIDE.md"
	@echo "  docs/CONSUMING_GUIDE.md"

test:
	cd $(SCANNER_DIR) && PYTHONPATH=. pytest tests/ -v

lint:
	@echo "-- shellcheck --"
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck $(SCANNER_DIR)/lib/common.sh && \
		shellcheck $(SCANNER_DIR)/lib/safety.sh && \
		shellcheck $(SCANNER_DIR)/scan.sh && \
		shellcheck $(SCANNER_DIR)/scan_audit.sh && \
		shellcheck $(SCANNER_DIR)/scan_baseline_init.sh; \
	else \
		echo "(shellcheck not installed; skipping)"; \
	fi
	@echo "-- python --"
	@python -m py_compile $(SCANNER_DIR)/aggregate.py
	@python -m py_compile $(SCANNER_DIR)/rewrite_sarif_help.py
	@python -m py_compile $(SCANNER_DIR)/checkov_url_overrides.py
	@python -m py_compile $(SCANNER_DIR)/tfstate_to_plan.py
	@python -m py_compile $(SCANNER_DIR)/drift_report.py
	@echo "OK"

selftest:
	@bash $(SCANNER_DIR)/lib/safety.sh

install:
	pip install -r $(SCANNER_DIR)/requirements-pinned.txt
	pip install pytest pyyaml

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ *.egg-info
