# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What ARGUS is

ARGUS (Autonomous Recon & Guided Unified Scanner) is a terminal AI agent that drives a
six-phase web-application **reconnaissance** pipeline. It wraps external recon binaries
(subfinder, httpx, nuclei, …), orchestrates them as a LangGraph state machine, and uses a
bring-your-own-LLM "brain" to triage results and write reports. Python 3.11+, Typer/Rich CLI,
LiteLLM for provider-agnostic model calls, Pydantic models throughout.

### Hard project constraints (do not violate)

- **Recon & detection only** — no exploitation, no auth/credential attacks, no general
  host/network scanning. `naabu` is restricted to web ports, `amass` is passive-only,
  `nuclei` is detection-only. New extensions must respect this.
- **No live traffic from the agent during development.** The agreed build depth is "full
  architecture + dry-run": extensions build correct commands and parse real captured sample
  output (see `tests/fixtures/`), but live subprocess execution stays behind the dry-run /
  human-in-the-loop gate. Do not add tests or dev steps that send network traffic.
- **No network calls in the test suite.** API keys live only in the OS keyring, are never
  printed/logged/persisted, and secret findings store **metadata only** (detector, location,
  verified) — never the secret value. See `SecretHit` in `argus/core/models.py`.

## Commands

```bash
pip install -e ".[dev]"     # install from the REPO ROOT (where pyproject.toml lives), not argus/
pytest                       # full suite (offline, no network)
pytest tests/test_scope.py                       # one file
pytest tests/test_scope.py::test_name -x         # one test, stop on first failure
ruff check argus tests       # lint (line-length 100, target py311)
mypy argus                   # type-check (disallow_untyped_defs = true — all defs need types)
```

Running the CLI (installed as `argus`):

```bash
argus config                 # pick provider, store API key in OS keyring, set default model
argus check-tools            # dependency doctor — which recon binaries are installed
argus scan example.com --dry-run          # ad-hoc six-phase run, plan-only (no traffic)
argus run argus/recipes/quick-recon.yaml -t example.com --dry-run
argus sessions list          # checkpointed runs
argus report <run_id>        # re-render a finished run's report
```

`--dry-run` and `--i-am-authorized` are the two flags that bypass the interactive gate; prefer
`--dry-run` for any local exercising of a run.

## Architecture

The CLI is deliberately thin (`argus/cli.py`): arg parsing, banner, the authorization +
live-traffic gates, and pretty output. All real work lives in `argus/core`, `argus/phases`,
and `argus/extensions`.

**Run flow:** `cli._execute_run` resolves scope + model plan, clears the gates, then calls
`agent.execute()` → builds the LangGraph and invokes it under a SQLite checkpointer →
persists artifacts.

### The pipeline (LangGraph state machine)

- `argus/core/graph.py` — wiring: `START → phase1 → gate → (abort | phase2→3→4→5) → triage →
  report → END`. The **gate** is the human-in-the-loop checkpoint *before* the first
  live-traffic phase (Phase 2). A checkpointer persists state so an interrupted run resumes.
- `argus/phases/__init__.py` — the graph nodes. Phases 1–5 all delegate to
  `runner.run_tool_phase(state, n)`; `triage` and `phase6_report` are separate.
- `argus/phases/runner.py` — the phase engine, shared by all five tool phases: derive this
  phase's targets from prior results (`targets_for_phase`), **enforce scope** (`scope.filter`),
  ask the registry for the phase's extensions, run each, merge typed results back into state.
- `argus/core/state.py` — `RunState` is a `TypedDict` (LangGraph-native). Results accumulate
  via an additive `operator.add` reducer so each phase appends without clobbering. `RunConfig`
  is the immutable per-run config. Helper converters (`config_from_state`, `results_from_state`,
  …) rehydrate typed models from the dumped state.

### Extensions — the pluggable tool layer (goose-style)

- `argus/extensions/base.py` — the `Extension` ABC contract. Subclasses set class attrs
  (`name`, `phase`, `required_binary`, `install_hint`) and implement `build_command()` +
  `parse()`. The inherited `run()` handles availability, dry-run, subprocess exec, timeouts,
  and error capture uniformly. **A missing binary is never an error** — `run()` returns
  `ExtensionResult(available=False)` and the phase skips it.
- `argus/extensions/registry.py` — extensions self-register via the `@register` decorator at
  import time. `argus/extensions/__init__.py` eagerly imports `p1_enumeration … p5_vuln` to
  trigger registration. Phases ask the registry (`available_for_phase`) rather than hardcoding
  tools.
- `p1_enumeration.py` … `p5_vuln.py` — one module per phase, each holding that phase's tool
  wrappers. **To add a tool:** subclass `Extension`, decorate with `@register`, put it in the
  right phase module. Add a captured-output fixture to `tests/fixtures/` and a parser test.

### Core services (`argus/core`)

- `models.py` — all typed domain models. Every tool parser returns an `ExtensionResult` (fills
  only the fields relevant to its tool). `Weakness` is the structured triage finding rendered
  into every report format. `Phase` is an `IntEnum` (1–6, order matters).
- `scope.py` — scope enforcement, checked before any tool runs. `Scope.is_in_scope()` /
  `filter()`; out-of-scope always wins. Supports explicit `scope.yaml` and **implicit-scope
  mode** (`Scope.implicit(target)` — the target's registrable domain + subdomains) when no
  scope file is given. `registrable_domain()` uses a curated multi-label-suffix set (offline;
  no PSL fetch).
- `config.py` — provider registry (`PROVIDERS`) + keyring secret storage. Keys go only to the
  OS keyring; non-secret prefs (default model, per-provider defaults, `phase_models`) go to a
  YAML settings file. `load_settings` defensively strips any `api_key` from the file.
- `llm.py` — LiteLLM wrapper (liveness ping, multi-model readiness, model parsing).
- `modelplan.py` — resolves which model(s) a run uses. Three modes: `single`, `per-phase`
  (cheap model for mechanical steps, strong model for triage/reporting — keyed by *role*),
  `ensemble` (triage sent to every model in parallel, findings merged by consensus quorum).
  Precedence: CLI > recipe > settings default.
- `triage.py` — post–Phase-5: converts raw evidence into structured `Weakness` objects.
  Offline/dry-run yields deterministic candidates; a live model enriches with repro steps, safe
  PoC, remediation, and web-researched references.
- `recipe.py` — YAML playbooks (`argus/recipes/*.yaml`): which phases/extensions to run,
  per-extension flags, params. Loaded by `argus run`. `argus scan` builds an ad-hoc `Recipe`.
- `agent.py` — orchestration: assembles `RunConfig`, seeds state (loads `argus_skill.md`
  hints), runs the graph, writes artifacts. Persists `results.json` (re-render source of
  truth), `report.json`, timestamped `.md`/`.html` deliverables, and `run.log`.
- `sessions.py` — session metadata + the LangGraph SqliteSaver checkpointer (enables
  `resume`).
- `paths.py` — all user-writable locations go under platformdirs (config/data), never inside
  the source tree. Tests monkeypatch `config_dir`/`data_dir` into a temp dir (see
  `tests/conftest.py`).

### Reports

`argus/core/report.py` renders typed results + weaknesses into Markdown, self-contained HTML,
and JSON. Reports are deterministic and re-renderable from `results.json` via
`agent.write_reports()` / `argus report <run_id>`.

## Conventions

- All modules use `from __future__ import annotations`; every function needs type annotations
  (mypy `disallow_untyped_defs`).
- Data crossing extension/phase/state/report boundaries is a Pydantic model from `models.py` —
  don't pass raw dicts through the pipeline.
- Tests are fully offline and deterministic; parser tests read real captured tool output from
  `tests/fixtures/` (e.g. `httpx.jsonl`, `nuclei.jsonl`). When adding a tool, add its fixture.
- `IntEnum` `Phase` values double as phase numbers — keep the two in sync.
