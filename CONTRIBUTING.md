# Contributing to EvidAudit

Thank you for your interest in contributing to **EvidAudit**!

## Development Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Guidelines
- Keep core package dependencies minimal (Python standard library only for `src/evidaudit/`).
- Preserve deterministic behavior and fail-closed defaults in `checker.py` and `audit.py`.
- Add unit tests in `tests/` for any new audit rule, counterfactual transition, or repair helper.
- Run `pytest` and `evidaudit demo` before opening a pull request.

