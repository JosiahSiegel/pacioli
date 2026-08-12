# Pacioli Makefile
# =============================================================================
# Targets (this Makefile is for the scanner repo itself, NOT for consumers):
#   make help        - Print the target list
#   make test        - Run pytest
#   make lint        - ruff check (skips silently if ruff not installed)
#   make selftest    - Safety invariant self-test (read-only guard)
#   make install     - pip install -e .
#   make clean       - Remove local build, dist, and cache artifacts (git-ignored)
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
	@echo "  make lint            - ruff check $(SCANNER_DIR)/"
	@echo "  make selftest        - Safety invariant self-test (python -m scanner.safety)"
	@echo "  make install         - pip install -e ."
	@echo "  make clean           - Remove local build, dist, and cache artifacts"
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
	pytest $(SCANNER_DIR)/tests/ -v

lint:
	@if command -v ruff >/dev/null 2>&1; then \
		ruff check $(SCANNER_DIR)/; \
	else \
		echo "(ruff not installed; skipping)"; \
	fi

selftest:
	python -m scanner.safety

install:
	pip install -e .

clean:
	@echo "Removing local build, dist, and cache artifacts..."
	@rm -rf build dist pacioli.egg-info .pytest_cache .ruff_cache .checkov
	@find scanner -type d -name __pycache__ -prune -exec rm -rf {} +
