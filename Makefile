# Pin the version so that local runs and CI agree on formatting
PRETTIER = npx prettier@3.9.6

.PHONY: check prettier prettier-fix spec-check ste-lint test

check: spec-check ste-lint test

spec-check:
	@scripts/spec-check

ste-lint:
	@scripts/ste-lint

test:
	prove -l t/ci/*.t

prettier:
	@$(PRETTIER) --check --no-error-on-unmatched-pattern '**/*.md' '**/*.json' '**/*.yml' || { echo "Run 'make prettier-fix' to fix formatting"; exit 1; }

prettier-fix:
	$(PRETTIER) --write --no-error-on-unmatched-pattern '**/*.md' '**/*.json' '**/*.yml'
