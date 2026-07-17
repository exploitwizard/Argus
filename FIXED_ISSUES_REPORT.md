# ARGUS — Fixed Issues Report

**Date:** 2026-07-17
**Scope of work:** (A) audit & fix real errors, (B) refactor to a goose-style
web-recon architecture, (C) test everything.
**Build depth (agreed with operator):** full architecture + dry-run. Extensions
build correct commands and parse **real captured sample output**; live subprocess
execution is wired but gated behind the dry-run / human-in-the-loop gate. No live
traffic was sent during this work; the test suite performs **no** network calls.

---

## 1. Audit summary (reality vs. spec)

The repository was a **working CLI shell over an unimplemented pipeline** — not a
"partially built app with a few bugs". Before work:

| Area | State found |
|---|---|
| `argus/cli.py` | Typer app present; **all 6 command bodies were stubs** printing "not implemented" and exiting 1. |
| `argus/ui/console.py`, `argus/core/paths.py` | Real and working (banner, auth gate, platform paths). |
| `argus/core/{state,graph,llm,scope,config,report,sessions,agent,recipe,hints}` | **Did not exist** (empty `core/` beyond `paths.py`). |
| `argus/phases/`, `argus/install/` | Empty `__init__.py` only — **no phases, no dependency doctor**. |
| Extension system, recipes, sessions, hints (Part B) | **Did not exist**. |
| `tests/` | **Zero tests**. |
| Static checks | `ruff` clean, `compileall` clean, `mypy` **1 error**, `pytest` collected 0 tests. |

---

## 2. Issues fixed

### I1 — `argus config` unimplemented and rejecting arguments  ·  **blocker**  ·  `argus/cli.py`
- **Symptom:**
  - `argus config` → `⚠ argus config is not implemented yet …`, exit 1.
  - `argus config --provider anthropic` → `Error: No such option: --provider`.
  - `argus config sk-key` → `Error: Got unexpected extra argument(s) (sk-key)`.
- **Root cause:** the command was declared with **no parameters** and a stub body.
  There was no option definition for a provider and no interactive flow — it was
  an argument-definition problem, not a usage problem.
- **Fix:** implemented an interactive `config` command in `cli.py` backed by a new
  `argus/core/config.py`:
  - `--provider/-p` option (skips the picker) **plus** an interactive provider picker.
  - API key read with **hidden input** (`typer.prompt(..., hide_input=True)`) — never
    a positional argument (no shell-history / process-list leak), never echoed, never
    logged. Stored in the **OS keyring**.
  - Model selection with a sensible per-provider default; non-secret prefs saved to a
    YAML settings file that a guard prevents from ever holding a key.
  - Ollama path requires no key.
  - *Refusing a positional key is now intentional, correct behavior.*
- **Verification:** `printf '\n' | argus config --provider ollama` → stores default model,
  no key prompt; `argus config sk-LEAKYKEY` → correctly refused.
- **Regression tests:** `tests/test_config.py` — keyring round-trip (mocked), ollama
  needs-no-key, settings never persist a key, stray `api_key:` dropped on load.

### I2 — `argus models` unimplemented  ·  **blocker**  ·  `argus/cli.py`
- **Symptom:** stub, exit 1.
- **Root cause:** no LLM/provider layer existed.
- **Fix:** implemented `models` + `argus/core/llm.py` (LiteLLM gateway). Lists
  configured providers and does a **1-token liveness ping** per provider, injecting
  the key from the keyring at call time only. Errors degrade to a clean `✖ fail`
  row (no traceback, no key printed).
- **Verification:** `argus models` renders a table; offline Ollama shows
  `✖ fail — Connection refused` gracefully.
- **Regression tests:** `test_config.py::test_configured_providers_reflects_stored_keys`
  covers provider listing; the network ping is exercised manually (kept out of tests).

### I3 — `argus check-tools` unimplemented  ·  **blocker**  ·  `argus/cli.py`, `argus/install/check_tools.py`
- **Symptom:** stub, exit 1.
- **Root cause:** no tools layer / dependency doctor existed.
- **Fix:** `argus/install/check_tools.py` drives entirely off the **extension
  registry**, so it always reflects exactly the tools ARGUS can run. Reports found/
  missing per phase with per-tool install hints. Missing tools are informational,
  never fatal.
- **Verification:** `argus check-tools` prints per-phase tables and an
  `N/15 available` summary.
- **Regression test:** `tests/test_registry.py` asserts all 15 extensions and their
  contract fields exist (the doctor's data source).

### I4 — `argus scan` / `resume` / `report` unimplemented  ·  **blocker**  ·  `argus/cli.py`
- **Symptom:** stubs, exit 1; no pipeline, no checkpointing, no report.
- **Root cause:** the LangGraph pipeline, phases, sessions, and reporting did not exist.
- **Fix:** built the full pipeline (see §3) and wired real commands:
  `run <recipe>`, `scan <target>` (ad-hoc recipe), `resume <run_id>`,
  `sessions list`, `report <run_id> --format md|json`. A live run requires a scope
  file, passes the authorization + live-traffic gates; `--dry-run` plans with no
  traffic.
- **Verification:** `argus run argus/recipes/quick-recon.yaml --target example.com
  --dry-run` and `argus scan example.com --dry-run` complete, print the exact planned
  commands, write artifacts, and register a session; `argus sessions list` and
  `argus report <id> --format json` render.
- **Regression tests:** `tests/test_graph.py` (full mocked e2e, resume, gate abort,
  dry-run no-traffic, scope drop).

### I5 — `mypy` type error in the auth gate  ·  **minor**  ·  `argus/ui/console.py:137`
- **Symptom:** `error: Function is missing a type annotation for one or more parameters [no-untyped-def]` on `_write_ack(marker)`.
- **Root cause:** untyped parameter under `disallow_untyped_defs = true`.
- **Fix:** annotated `_write_ack(marker: Path) -> None` and imported `Path`.
- **Verification:** `mypy argus` → `Success: no issues found in 30 source files`.
- **Regression guard:** `mypy` runs clean over the whole tree; CI-style check documented below.

### I6 — subzy parser false-positive on "NOT VULNERABLE"  ·  **major**  ·  `argus/extensions/p2_hosts.py`
- **Symptom:** a `[ NOT VULNERABLE ] www.example.com` line was reported as a
  subdomain takeover. Caught by a parser unit test during Part C (`assert hosts ==
  {'takeover.example.com','old.example.com'}` failed with an extra `www.example.com`).
- **Root cause:** the vulnerability check used substring containment
  (`"VULNERABLE" in line`), and `"NOT VULNERABLE"` contains `"VULNERABLE"`.
- **Fix:** exclude lines containing `"NOT VULNERABLE"` before matching.
- **Verification:** `tests/test_parsers.py::test_subzy_only_reports_vulnerable` and
  `tests/test_report.py::test_aggregate_dedupes_and_counts` now pass.
- **Regression test:** yes (both tests above).

### I7 — SQLite checkpointer connection leak  ·  **minor**  ·  `argus/core/agent.py`, `argus/core/sessions.py`
- **Symptom:** `ResourceWarning: unclosed database` per run under pytest.
- **Root cause:** each run created a `SqliteSaver(sqlite3.connect(...))` that was
  never closed.
- **Fix:** added `sessions.close_checkpointer()` and call it in a `finally` around
  both `agent.execute` and `agent.resume`.
- **Verification:** full suite runs with **no warnings**.
- **Regression guard:** exercised by every `test_graph.py` run.

---

## 3. Refactor — goose-style architecture (web-recon only)

| Goose concept | ARGUS implementation |
|---|---|
| **Pluggable extensions** | `argus/extensions/`: `Extension` ABC (`name`, `phase`, `required_binary`, `is_available()`, `build_command()`, `parse()`, inherited `run()`). 15 tools implemented (subfinder, amass, puredns, dnsx, httpx, naabu, subzy, katana, gau, ffuf, LinkFinder, trufflehog, arjun, nuclei, gowitness). Each parses real-shape output into typed Pydantic `ExtensionResult`. |
| **Self-registering registry** | `@register` populates a registry; phases ask `available_for_phase(n)`. Missing binary → `available=False`, **never crashes**; the phase skips it. |
| **Recipes (YAML playbooks)** | `argus/core/recipe.py` + `argus/recipes/{quick-recon,deep-recon,single-target}.yaml`. `${param}` substitution (defaults overlaid with `--param k=v`), Pydantic validation (intensity/phases), retry policy. CLI: `argus run <recipe> --target …`. |
| **Skill/hints file** | `argus/argus_skill.md` + `argus/core/hints.py` (env → `./.argushints` → `./argus_skill.md` → packaged default). Standing rules loaded into run context each run. |
| **Sessions + checkpointing** | LangGraph `SqliteSaver` checkpointer (`argus/core/sessions.py`); per-run `meta.json` sidecar. `argus sessions list`, `argus resume <id>` — a crashed run resumes from its last checkpoint. |
| **Provider layer stays LiteLLM** | `argus/core/llm.py` keeps LiteLLM as the single gateway; per-run `--model`, local Ollama supported, `argus models` liveness ping. |
| **Six-phase web-recon pipeline** | `argus/core/graph.py`: `START → phase1 → gate → phase2 → phase3 → phase4 → phase5 → report → END`. `naabu` restricted to a fixed **web-ports** list (not operator-overridable); amass is passive-only; nuclei is detection-only. Scope file + human-in-the-loop live-traffic gate preserved. |

**Safety properties enforced in code:** scope checked before any tool runs (out-of-scope
takes precedence, dropped items logged); dry-run sends no traffic; secret findings store
**metadata only** (detector/location/verified) — the secret value is never captured,
printed, or persisted (verified by `test_parsers.py::test_trufflehog_never_stores_secret_value`
and a disk grep in smoke testing).

---

## 4. Test suite results

Command: `pytest -q --cov=argus`

```
58 passed in 0.26s
TOTAL coverage: 67%
```

| Test file | Covers |
|---|---|
| `test_registry.py` | 15 extensions register, per-phase membership, contract fields, duplicate rejection, availability gating. |
| `test_parsers.py` | Every one of the 15 parsers against captured sample output (`tests/fixtures/`); dedupe; secret-value never stored. |
| `test_scope.py` | In/out-of-scope, wildcard, CIDR, out-of-scope precedence, fan-out cap, sibling-domain leak guard. |
| `test_recipe.py` | Recipe load, `${param}` substitution, CLI override precedence, undefined-param error, invalid intensity/phase rejection, `--param` parsing, shipped recipes load. |
| `test_config.py` | Keyring round-trip (mocked), ollama-no-key, provider listing, settings never persist a key. |
| `test_extension_run.py` | Missing binary degrades gracefully, dry-run builds command but does **not** exec, subprocess failure captured not raised, real-output parse, naabu web-ports-only. |
| `test_graph.py` | Graph wiring; full **mocked** end-to-end run; gate blocks unauthorized live run; dry-run sends no traffic; resume completes; out-of-scope dropped. |
| `test_report.py` | Aggregation/dedupe, severity ordering, Markdown sections, JSON validity, secret value never rendered. |

**Static checks (all green):** `ruff check argus tests` — passed; `mypy argus` —
`Success: no issues found in 30 source files`; `python -m compileall argus` — clean.

Coverage note: the uncovered 33% is concentrated in `cli.py`, `llm.py`,
`ui/console.py`, and `check_tools.py` rendering — i.e. terminal I/O and live-network
paths. These are intentionally exercised by the **manual smoke tests** below rather
than by networked unit tests (per the "no network in tests" constraint).

### Manual smoke tests (all pass)
- `argus check-tools` → per-phase tables + install hints.
- `argus config --provider ollama` → stores default model, no key prompt.
- `argus config sk-KEY` → correctly refuses a positional key.
- `argus models` → provider table with graceful offline `✖ fail`.
- `argus run argus/recipes/quick-recon.yaml --target example.com --dry-run` → plans
  commands, **no traffic**, writes artifacts, registers session.
- `argus scan example.com --dry-run`, `argus sessions list`,
  `argus report <id> --format json` → all render.
- Disk grep of the runs directory for secret patterns → **none found**.

---

## 5. Summary table

| ID | Title | Severity | File/Phase | Regression test |
|---|---|---|---|---|
| I1 | `config` unimplemented / rejects args | blocker | `cli.py`, `core/config.py` | ✅ `test_config.py` |
| I2 | `models` unimplemented | blocker | `cli.py`, `core/llm.py` | ✅ (listing) `test_config.py` |
| I3 | `check-tools` unimplemented | blocker | `cli.py`, `install/check_tools.py` | ✅ `test_registry.py` |
| I4 | `scan`/`resume`/`report` unimplemented | blocker | `cli.py`, pipeline | ✅ `test_graph.py` |
| I5 | mypy untyped `_write_ack` | minor | `ui/console.py` | ✅ mypy clean |
| I6 | subzy "NOT VULNERABLE" false positive | major | `extensions/p2_hosts.py` | ✅ `test_parsers.py`, `test_report.py` |
| I7 | SQLite checkpointer leak | minor | `core/agent.py`, `core/sessions.py` | ✅ warning-free suite |

---

## 6. Found but deliberately NOT fixed (with reasoning)

1. **DOCX report format.** The README mentioned `docx`; the CLI now offers `md`/`json`
   only. `python-docx` is an optional dep and not needed for the recon workflow.
   *Next step:* add a `docx` renderer behind the existing `[docx]` extra.
2. **LLM triage / executive summary is a hook, not wired to call the model.** The
   report is composed **deterministically** from typed results so runs are offline-safe
   and tests are hermetic. `report.to_markdown(..., summary=...)` accepts an LLM
   summary but the report node does not call the model by default (avoids surprise
   network/cost). *Next step:* enable an opt-in LLM summary on non-dry-run.
3. **Live subprocess execution is unverified against real binaries/targets.** Per the
   agreed build depth, command-building and parsing are tested against captured output,
   but no tool was run against a live target (no authorized scope, and not all binaries
   are installed here). *Next step:* validate each `build_command`/`parse` pair against
   the real tool in an authorized lab.
4. **ffuf `-json` stdout shape varies by version.** The parser handles both the summary
   `{"results":[…]}` form and ndjson, but was validated against captured output, not a
   live ffuf. *Next step:* confirm against the installed ffuf version.
5. **Python version.** The working venv is Python 3.14; the spec targets 3.11+. Works,
   but `langchain-core` emits a Pydantic-v1 compatibility `UserWarning` on 3.14 which
   we suppress narrowly. *Next step:* pin CI to 3.11/3.12 as the supported baseline.

## 7. Recommended next steps
- Add a lab-validation pass for each extension's real tool output; capture any format
  drift into new fixtures.
- Wire the opt-in LLM triage/summary and add a mocked-LLM test.
- Add the DOCX renderer and a `report --format docx` path.
- Add a CI workflow running `ruff`, `mypy`, and `pytest` on Python 3.11/3.12.
- Consider a real rate-limiter/concurrency executor honoring `scope.limits` when live
  execution is enabled (limits are currently passed to each tool's own flags).
