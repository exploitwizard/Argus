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
| 6 | Reporting | *(none)* | Composes a Markdown + JSON report |

Secret findings store **metadata only** (detector, location, verified flag) — the
secret value is never captured, printed, or stored.

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
```

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

### 1. Create a scope file

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
argus report <run_id> --format md     # re-render a finished run's report (md | json)
```

### Command reference

| Command | Purpose |
|---|---|
| `argus check-tools` | Report which recon binaries are installed + install hints |
| `argus config [--provider P]` | Store a provider API key (keyring) + default model |
| `argus models` | List configured providers and liveness-ping each |
| `argus scan TARGET [--scope] [--model] [--intensity] [--dry-run] [--i-am-authorized]` | Full six-phase pipeline (ad-hoc recipe) |
| `argus run RECIPE --target T [--scope] [--model] [--param k=v] [--dry-run] [--i-am-authorized]` | Run a YAML recipe |
| `argus resume RUN_ID` | Continue a checkpointed run |
| `argus report RUN_ID [--format md\|json]` | Re-render a report |
| `argus sessions list` | List checkpointed runs |

> **Planned (not yet implemented):** DOCX report output — `report` currently
> supports `md` and `json` only.

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
