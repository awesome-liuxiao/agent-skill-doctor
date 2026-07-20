# Contributing to Agent Skill Doctor

Thank you for helping make agent skills easier to diagnose without weakening their security
boundary. Small, reviewable changes are preferred over broad rewrites.

## Good first contributions

- add a synthetic regression fixture for a clearly described failure mode;
- improve an error message without changing the exit policy;
- clarify platform-specific installation or discovery documentation;
- add a test for an existing rule, schema, or report contract; or
- reproduce a public issue using only synthetic or explicitly licensed material.

Look for issues labeled [`good first issue`](https://github.com/awesome-liuxiao/agent-skill-doctor/labels/good%20first%20issue)
or [`help wanted`](https://github.com/awesome-liuxiao/agent-skill-doctor/labels/help%20wanted).

## Development setup

Agent Skill Doctor currently requires Python 3.12.

```console
python -m venv .venv
python -m pip install -r requirements-dev.lock
python -m pip install -e .
```

Run the local quality gate before opening a pull request:

```console
python -m ruff format --check .
python -m ruff check .
python -m mypy src tests scripts
python -m pytest
```

## Pull requests

1. Open or reference an issue when behavior or public contracts will change.
2. Keep untrusted skill content as data; static analysis must not execute it or access the network.
3. Add tests for changed behavior and update schemas or documentation when relevant.
4. State what you ran and any platform coverage you could not provide.
5. Do not call a development result safe, healthy, stable, or root-caused unless the corresponding
   evidence contract permits that claim.

Benchmark additions must be synthetic or carry an explicit redistributable license, pinned source
commit, provenance record, and modification history. Never contribute private prompts, traces,
credentials, customer skills, or identifying local paths.

## Security reports

Do not open a public issue for a suspected containment, credential, signature, or report-content
execution vulnerability. Follow [SECURITY.md](SECURITY.md) and use GitHub private vulnerability
reporting.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
