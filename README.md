# ARGUS

**Autonomous Recon & Guided Unified Scanner** — a terminal-based, LLM-driven
reconnaissance agent for **authorized** bug bounty and penetration-testing work.

ARGUS orchestrates a six-phase recon pipeline as a [LangGraph](https://langchain-ai.github.io/langgraph/)
state machine. An LLM "brain" — pointed at any provider you paste a key for —
plans the run, adapts between phases, triages findings, and writes the report.
External recon tooling does the actual work; ARGUS runs it safely, concurrently,
and strictly inside your declared scope.

> [!WARNING]
> **Authorized testing only.** ARGUS sends live traffic to targets and *detects*
> vulnerabilities. It performs **recon and detection only** — no exploitation, no
> credential spraying, no brute-forcing of authentication. Running it against
> systems you do not own or lack explicit written authorization to test may be a
> crime. You are solely responsible for ensuring authorization. See `LICENSE`.

---

## The six phases

| # | Phase | Tools | What it does |
|---|-------|-------|--------------|
| 1 | Enumeration | `subfinder`, `amass`, `puredns`, `dnsx` | Passive+active subdomain discovery, resolve, dedupe |
| 2 | Host/Service Discovery | `httpx`, `naabu`, `subzy` | Probe live web hosts, port scan, takeover detection |
| 3 | Content/URL Harvesting | `katana`, `gau`, `ffuf` | Crawl, pull historical URLs, content-discovery fuzzing |
| 4 | Deep Analysis | `LinkFinder`, `trufflehog`, `arjun` | JS endpoint extraction, secret hunting, hidden params |
| 5 | Vuln Scan & Triage | `nuclei`, `gowitness` | Template scanning + screenshots, then **LLM triage** |
| 6 | Reporting | *(none)* | LLM composes Markdown + JSON (+ optional DOCX) report |

A **human-in-the-loop gate** pauses before Phase 2 (the first phase that touches
the live target) and shows exactly what will run against how many hosts.

## Install

Requires **Python 3.11+**. Primary environment is **Kali Linux**.

```bash
git clone https://github.com/exploitwizard/Argus.git argus && cd argus
python3 -m venv .venv && source .venv/bin/activate
pip install -e .            # add ".[docx]" for DOCX reports, ".[dev]" for tests
```

Then verify your recon toolchain:

```bash
argus check-tools           # dependency doctor with per-tool install hints
```

Most Phase 1–5 binaries come from ProjectDiscovery and are available in Kali or
via `go install`. `argus check-tools` prints the exact install command for
anything missing and ARGUS degrades gracefully when a tool is absent.

## Configure a model

```bash
argus config                # pick provider, paste API key, choose default model
argus models                # list configured providers + 1-token liveness ping
```

Keys are stored in your **OS keyring** — never in the repo, never printed back,
never written to logs. Supported providers: Anthropic (`claude-*`), OpenAI
(`gpt-*`/`o*`), Google Gemini (`gemini-*`), Groq, DeepSeek, and local **Ollama**
(`ollama/*`, no key needed for fully-offline hunting). Switch per run with
`--model`.

## Run

```bash
cp argus/config/scope.example.yaml scope.yaml   # then edit for your engagement
argus scan target.com --scope scope.yaml --intensity med
argus resume <run_id>                            # continue an interrupted run
argus report <run_id> --format md                # md | json | docx
```

## Safety model

- **Scope file** (`scope.yaml`): every host/URL is checked against in/out-of-scope
  rules **before** any tool runs. Out-of-scope items are dropped and logged.
- **Human-in-the-loop gate** before any live-traffic phase.
- **Global rate-limit / concurrency ceiling** honored by every tool wrapper.
- **Hard boundary in code:** recon and detection only. No exploitation actions.

## Project layout

```
argus/
  cli.py            # typer entrypoint
  core/             # state, graph, llm, scope, memory, tools, report, paths
  phases/           # p1_enumeration … p6_report
  ui/               # rich banners, live status view
  config/           # scope.example.yaml, settings.example.yaml
  install/          # check_tools.py dependency doctor
tests/
```

## License

MIT, with an authorized-testing-only notice. See `LICENSE`.
