# Contributing

Use a focused branch and include tests for behavior changes. Rule IDs and report schema fields are
public machine interfaces: changing or removing them requires a compatibility note and, for the
report schema, a schema-version decision.

Set up and run the local quality gate:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
PYTHONWARNINGS=error::ResourceWarning PYTHONPATH=src \
  .venv/bin/python -m coverage run -m unittest discover -s tests -v
.venv/bin/python -m coverage report --fail-under=80
.venv/bin/ruff check src tests
.venv/bin/mypy src
.venv/bin/python -m build
```

Pull requests should explain the threat or interoperability requirement, link primary sources where
applicable, and state test coverage plus remaining limitations. Never put live credentials, private
server URLs, or unredacted customer tool cards in fixtures, issues, or logs.
