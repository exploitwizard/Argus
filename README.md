# ARGUS

**Autonomous Recon & Guided Unified Scanner** — a terminal AI agent for
**authorized web-application reconnaissance**. ARGUS drives a six-phase recon
pipeline (a [LangGraph](https://langchain-ai.github.io/langgraph/) state machine)
with a bring-your-own-LLM "brain" that plans the run, adapts between phases,
triages results, and writes the report. External recon tools do the actual work;
ARGUS runs them safely, concurrently, and strictly inside your declared scope.
It performs **recon and detection only** — never exploitation.

---

> [!WARNING]
> ## Safety model — read first
>
> - **Authorized testing only.** ARGUS sends live reconnaissance traffic to the
>   targets you point it at. Running it against systems you do not own or lack
>   **explicit written authorization** to test may be a crime. You are solely
>   responsible for authorization.
> - **Recon & detection only.** No exploitation, no credential spraying, no
>   brute-forcing of authentication. `naabu` is restricted to web ports; `amass`
>   runs passive-only; `nuclei` runs in detection mode.
> - **Scope file is enforced before any traffic.** Every host/URL is checked
>   against `scope.yaml` *before* a tool runs; out-of-scope items are dropped and
>   logged. Out-of-scope rules take precedence over in-scope rules.
> - **Human-in-the-loop gate** pauses before the first live-traffic phase and
>   shows exactly what will run. A one-time authorization acknowledgement is
>   stored locally; `--i-am-authorized` accepts it (and the live gate)
>   non-interactively for automation.
> - **Rate & concurrency limits** from the scope file are honored by every tool.
> - **`--dry-run`** plans a run and prints the exact commands **without sending
>   any traffic**.

---

## The six phases

| # | Phase | Tools | What it does |
|---|-------|-------|--------------|
| 1 | Enumeration | `subfinder`, `amass`, `puredns`, `dnsx` | Passive+active subdomain discovery, resolve, dedupe |
| 2 | Host/Service Discovery | `httpx`, `naabu` (web ports), `subzy` | Probe live web hosts, web-port scan, takeover detection |
| 3 | Content/URL Harvesting | `katana`, `gau`, `ffuf` | Crawl, pull historical URLs, content-discovery fuzzing |
| 4 | Deep Analysis | `LinkFinder`, `trufflehog`, `arjun` | JS endpoint extraction, secret detection, hidden params |
| 5 | Vuln Scan & Triage | `nuclei`, `gowitness` | Template **detection** + screenshots |
| — | AI triage | *(LLM + web search)* | Turns raw evidence into structured, researched findings |
| 6 | Reporting | *(none)* | Composes a named `.md` + self-contained `.html` report (+ JSON) |

Secret findings store **metadata only** (detector, location, verified flag) — the
secret value is never captured, printed, or stored.

### Weaknesses and Vulnerabilities (AI triage)

After Phase 5, a triage agent converts every flagged signal (nuclei findings,
subdomain takeovers, exposed secrets, discovered params) into a structured
**Weakness** with: OWASP Top-10 (2025) category + CWE, severity with a CVSS-style
vector, confidence, evidence, numbered **steps to reproduce**, a minimal **safe
verification PoC**, impact, and concrete remediation. When a model is configured
it also runs **live web research** (provider-native web search via LiteLLM) to
cite matching CVEs and advisories. Every report gets a dedicated
**"Weaknesses and Vulnerabilities"** section led by a severity-sorted summary
table — nothing flagged is omitted. Offline/`--dry-run` runs still produce the
full deterministic findings (without enrichment). The tool documents and
verifies for responsible disclosure only — it never exploits.

## Requirements

- **Python 3.11+** (developed/tested on 3.11–3.14).
- Linux recommended (**Kali** is the primary environment); macOS works for the
  CLI/agent.
- External recon binaries, grouped by phase:
  - **Phase 1:** `subfinder`, `amass`, `puredns`, `dnsx`
  - **Phase 2:** `httpx`, `naabu`, `subzy`
  - **Phase 3:** `katana`, `gau`, `ffuf`
  - **Phase 4:** `linkfinder`, `trufflehog`, `arjun`
  - **Phase 5:** `nuclei`, `gowitness`

You don't need all of them — **missing tools are skipped gracefully**. Run
`argus check-tools` to see what's installed and get the exact install command for
anything missing.

## Installation

> [!IMPORTANT]
> Run `pip install -e .` from the **repository root** — the directory that
> contains `pyproject.toml`. Running it from the inner `argus/` package directory
> fails with *"does not appear to be a Python project: neither 'setup.py' nor
> 'pyproject.toml' found."* (That is the doubled-path `argus/argus` mistake.)

```bash
git clone https://github.com/exploitwizard/Argus.git argus && cd argus   # repo ROOT (where pyproject.toml lives)
python -m venv .venv && source .venv/bin/activate
pip install -e .                       # add ".[dev]" for the test/lint toolchain
```

Verify the CLI:

```bash
argus --help
argus check-tools                      # dependency doctor: what's installed / how to install the rest
argus install-tools                    # install the missing ones (asks first)
argus install-tools --dry-run          # just print the exact commands
```

### Auto-installing recon tools

`argus install-tools` resolves the correct install method per tool and installs
the missing ones:

- **apt** where the Kali package exists (nuclei, naabu, dnsx, gowitness, arjun,
  trufflehog) — falling back to `go install`/`pipx` off-Kali;
- **go install** for Go tools (subfinder, httpx, katana, gau, puredns, subzy, …);
- **pipx** for Python tools (outside the ARGUS venv, onto the system PATH);
- an **isolated venv + `/usr/local/bin` shim** for LinkFinder.

It handles the Kali quirks: warns if `~/go/bin` isn't on PATH, installs the
`libpcap-dev` (naabu) and `massdns` (puredns) prerequisites first, and runs
`nuclei -update-templates` after installing nuclei. The **exact commands are
shown first** (any `sudo` surfaced) and it asks before running — skip with
`--yes`. It's **idempotent** (present tools are skipped) and one tool failing
never aborts the rest. `argus scan TARGET --auto-install` installs anything
missing right before a run.

## Configure a model (bring your own key)

ARGUS uses [LiteLLM](https://docs.litellm.ai/), so you can point it at Anthropic,
OpenAI, Google Gemini, Groq, DeepSeek, or a local **Ollama**. Pick a model per run
with `--model`.

**Interactive setup (recommended)** — stores the key in your **OS keyring**
(never in the repo, never printed, never logged):

```bash
argus config                 # pick provider → paste key (hidden input) → choose default model
argus config --provider anthropic   # skip the provider picker
argus models                 # list keyring-configured providers + 1-token liveness ping
```

**Environment-variable alternative** — LiteLLM reads standard provider env vars at
call time, so an exported key works even without `argus config` (note: `argus
config`/`argus models` track the keyring, so an env-only provider won't appear in
`argus models`):

```bash
export ANTHROPIC_API_KEY=...     # or OPENAI_API_KEY, GEMINI_API_KEY, GROQ_API_KEY, DEEPSEEK_API_KEY
argus scan example.com --scope scope.yaml --model claude-sonnet-5
```

**Local / offline via Ollama** (no key needed):

```bash
argus config --provider ollama   # choose e.g. ollama/llama3.1
```

## Usage

### 1. Create a scope file (optional)

`--scope` is **optional**. If you omit it, ARGUS runs in **implicit-scope mode**:
the target's registrable domain (e.g. `example.com` from `api.example.com`)
becomes the scope — the apex plus every subdomain. A banner announces it:

```
Running in IMPLICIT-SCOPE mode — scope = example.com and subdomains
```

Anything discovered *outside* that root (unrelated domains, third-party hosts) is
still dropped and never probed — the safety floor is unchanged. A full
`scope.yaml` always takes precedence and is recommended for real engagements:

```bash
cp argus/config/scope.example.yaml scope.yaml   # then edit for your engagement
```

```yaml
# scope.yaml (excerpt) — checked BEFORE any tool runs
engagement: "Example Corp bug bounty"
authorized_by: "you@example.com"
in_scope:
  domains: ["example.com", "*.example.com"]
  cidrs:   ["203.0.113.0/24"]
out_of_scope:                 # takes precedence over in_scope
  domains: ["blog.example.com"]
limits:
  max_concurrency: 20
  requests_per_second: 10
  max_hosts_per_phase: 500
intensity: med                # low | med | high
```

### 2. Plan first with a dry run (no traffic)

```bash
argus scan example.com --dry-run          # prints the exact commands each phase WOULD run
```

### 3. Run a live scan (authorized targets only)

```bash
argus scan example.com --scope scope.yaml --intensity med
```

You'll acknowledge the authorization notice and pass the live-traffic gate (or use
`--i-am-authorized` to accept both non-interactively).

### Model selection — one model, or several at once

```bash
argus scan example.com --model claude-sonnet-5          # single model (default)
argus scan example.com --models claude-sonnet-5,gpt-5.1 # multi-model, concurrent
argus scan example.com --models m1,m2,m3 --multi-mode per-phase
```

`--models` runs several models **concurrently** (async via LiteLLM) for the
reasoning steps. Two modes, via `--multi-mode` (default `ensemble`):

- **ensemble** — the triage prompt goes to every model in parallel and the
  findings are merged by **consensus**: a weakness confirmed by ≥ quorum models
  gets a confidence boost and ranks higher, disagreements are flagged
  **"needs manual review"**, and every finding records **which model(s)**
  produced it.
- **per-phase** — a cheaper/faster model handles mechanical steps while a
  stronger model handles triage/reporting. The role→model map lives in
  `argus config` (`phase_models`) or a recipe.

If one model errors or has no key, it's logged and skipped — the run never
aborts because one provider failed. API keys are never printed. Run
`argus models` to see which providers are ready for multi-model use.

### Run a recipe (YAML playbook)

Recipes bundle which phases/extensions run, their flags, model, intensity, and
parameters. Three ship in `argus/recipes/`:

```bash
argus run argus/recipes/quick-recon.yaml  --target example.com --scope scope.yaml
argus run argus/recipes/deep-recon.yaml   --target example.com --scope scope.yaml \
    --param wordlist=/usr/share/wordlists/dirb/common.txt
argus run argus/recipes/quick-recon.yaml  --target example.com --dry-run
```

`--param key=value` (repeatable) overrides a recipe parameter.

### Sessions, resume, and reports

Each run is a checkpointed session, so an interrupted run resumes cleanly:

```bash
argus sessions list             # list runs (run_id, target, model, status)
argus resume <run_id>           # continue an interrupted run from its last checkpoint
argus report <run_id> --format both   # (re)write the report (md | html | both)
```

Reports are saved as `argus_report_<scope-or-target-slug>_<YYYYMMDD-HHMMSS>` in
both **`.md`** and **`.html`**, into the run's output directory. The base name
comes from the scope's engagement name, or the target/web-app domain in
implicit-scope mode. The `.html` is **fully self-contained** (inline CSS, no
external assets) in the charcoal/red VAPT house style, with a table of contents
and the "Weaknesses and Vulnerabilities" section rendered as styled cards +
tables; gowitness screenshots are linked relatively. A machine-readable
`report.json` (aggregate) and `results.json` (faithful re-render source) are
written alongside.

### Command reference

| Command | Purpose |
|---|---|
| `argus check-tools` | Report which recon binaries are installed + install hints |
| `argus install-tools [--yes] [--dry-run] [--all]` | Install missing tools (apt / go / pipx / LinkFinder shim) |
| `argus config [--provider P]` | Store a provider API key (keyring) + default model |
| `argus models` | List providers, liveness-ping each, and show multi-model readiness |
| `argus scan TARGET [--scope] [--model] [--models] [--multi-mode] [--intensity] [--auto-install] [--dry-run] [--i-am-authorized]` | Full six-phase pipeline (ad-hoc recipe) |
| `argus run RECIPE --target T [--scope] [--model] [--models] [--multi-mode] [--param k=v] [--dry-run] [--i-am-authorized]` | Run a YAML recipe |
| `argus resume RUN_ID` | Continue a checkpointed run |
| `argus report RUN_ID [--format md\|html\|both]` | (Re)write the `.md`/`.html` report (default both) |
| `argus sessions list` | List checkpointed runs |

> **Planned (not yet implemented):** DOCX report output — `report` currently
> writes `md` and self-contained `html` (plus a machine-readable `report.json`).

## Project layout

```
argus/                 # the import package (run pip install -e . from ITS PARENT)
  cli.py               # Typer entrypoint (app = argus.cli:app)
  core/                # models, scope, config, llm, graph, state, sessions, agent, recipe, hints, report, paths
  extensions/          # pluggable recon-tool extensions + self-registering registry (one per tool)
  phases/              # phase nodes + the phase runner wired into the graph
  install/             # check_tools.py dependency doctor
  ui/                  # rich banner, auth + live-traffic gates
  recipes/             # quick-recon.yaml, deep-recon.yaml, single-target.yaml
  config/              # scope.example.yaml, settings.example.yaml
  argus_skill.md       # standing behavioral rules loaded into the agent context
tests/                 # pytest suite + captured tool-output fixtures (no network)
pyproject.toml         # packaging (repo root)
```

## Development

```bash
pip install -e ".[dev]"     # from the repo root
pytest                      # full suite (no network calls)
ruff check argus tests      # lint
mypy argus                  # type-check
```

## License / disclaimer

MIT — see [`LICENSE`](LICENSE). **Authorized security testing only.** ARGUS is for
reconnaissance and detection against systems you are explicitly authorized to test.
You are solely responsible for how you use it.
