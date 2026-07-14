# Contributing

Use a focused branch and include tests for behavior changes. Rule IDs, report schemas, CLI commands
and exit meanings are public machine interfaces governed by `docs/STABILITY_POLICY.md`. Do not
remove or repurpose them in v1. A schema change requires an explicit immutable schema version.

Set up and run the local quality gate:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
PYTHONWARNINGS=error::ResourceWarning PYTHONPATH=src \
  .venv/bin/python -m coverage run -m unittest discover -s tests -v
.venv/bin/python -m coverage report --fail-under=75
.venv/bin/ruff check src tests
.venv/bin/mypy src
.venv/bin/python -m build
mcp-tool-card-linter evaluate --corpus evaluation/rule_accuracy_v1.jsonl \
  --min-precision 0.95 --min-recall 0.95
```

Pull requests should explain the threat or interoperability requirement, link primary sources where
applicable, and state test coverage plus remaining limitations. Never put live credentials, private
server URLs, or unredacted customer tool cards in fixtures, issues, or logs.
