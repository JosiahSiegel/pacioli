# Pacioli Makefile
# =============================================================================
# Targets:
#   make test            - Run pytest
#   make lint            - Shell + Python lint
#   make selftest        - Safety invariant self-test
#   make install         - Install scanner deps
#   make clean           - Remove build artifacts
#
# For CONSUMING the scanner from a Terraform repo, see the wrapper Makefile
# pattern in `examples/Makefile.consumer`.
# =============================================================================

.PHONY: help test lint selftest install clean

SCANNER_DIR := scanner

help:
	@echo "Pacioli scanner targets:"
	@echo "  make test            - Run pytest ($(SCANNER_DIR)/tests)"
	@echo "  make lint            - shellcheck + py_compile"
	@echo "  make selftest        - Safety invariant self-test"
	@echo "  make install         - pip install -r requirements"
	@echo "  make clean           - Remove __pycache__ and test artifacts"

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