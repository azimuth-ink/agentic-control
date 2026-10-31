# Contributing

This is a reference implementation of a published specification. The specification text is normative; the code follows it.

## Ground rules

1. **Cite the clause.** Every change to control semantics names the specification clause (section or appendix, e.g. `A.5` or `4.9`) in the commit message and, where it changes behaviour, in a conformance test marked `@spec(...)`.
2. **Tests before fixes.** A behavioural defect is reproduced as a failing conformance or unit test first. The suite is the implementation's verification record.
3. **The code does not reinterpret the text.** Where the specification is ambiguous, pick the conservative reading (fail closed), record the choice in `docs/adr/`, and note it under "Known gaps" in `CHANGELOG.md` so it can be raised against the text.
4. **No new dependencies** without an ADR. `cryptography` is the only runtime dependency.
5. **Keep the scope of a branch small.** One concern per `pr/NN-name` branch, merged with `--no-ff` so the history reads as a sequence of scopes.

## Workflow

```
pip install -e ".[dev]"
pytest
python tools/conformance_report.py --check
```

Both must pass on Python 3.11–3.13 (CI runs all three).

## Marking tests

```python
from conftest import spec

@spec("A.3", "4.4", finding="F2")
def test_something():
    ...
```

`finding` is one of F1–F9 (see `tools/conformance_report.py` for their meaning). The report fails CI if any finding loses its last test.

## Licence

Contributions are accepted under Apache-2.0.
