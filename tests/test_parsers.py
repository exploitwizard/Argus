"""Parser tests — each extension parses captured real-shape sample output.

No network is used: parsers are pure functions over recorded tool output.
"""

from __future__ import annotations

from argus.extensions import get


def test_subfinder_parses_and_dedupes(fixture_text):
    res = get("subfinder").parse(fixture_text("subfinder.txt"))
    hosts = [s.host for s in res.subdomains]
    assert "www.example.com" in hosts and "api.example.com" in hosts
    assert hosts.count("www.example.com") == 1  # de-duplicated


def test_dnsx_strips_record_brackets(fixture_text):
    res = get("dnsx").parse(fixture_text("dnsx.txt"))
    hosts = {s.host for s in res.subdomains}
    assert hosts == {"www.example.com", "api.example.com", "dev.example.com"}


def test_httpx_parses_json_and_skips_noise(fixture_text):
    res = get("httpx").parse(fixture_text("httpx.jsonl"))
    assert len(res.live_hosts) == 3
    first = next(h for h in res.live_hosts if h.url == "https://www.example.com")
    assert first.status_code == 200
    assert first.webserver == "ECS"
    assert "Nginx" in first.tech


def test_naabu_parses_host_port(fixture_text):
    res = get("naabu").parse(fixture_text("naabu.txt"))
    pairs = {(p.host, p.port) for p in res.open_ports}
    assert ("www.example.com", 443) in pairs
    assert ("api.example.com", 8443) in pairs


def test_subzy_only_reports_vulnerable(fixture_text):
    res = get("subzy").parse(fixture_text("subzy.txt"))
    hosts = {t.host for t in res.takeovers}
    assert hosts == {"takeover.example.com", "old.example.com"}
    assert all(t.vulnerable for t in res.takeovers)


def test_katana_urls(fixture_text):
    res = get("katana").parse(fixture_text("katana.txt"))
    urls = {u.url for u in res.urls}
    assert "https://www.example.com/login" in urls
    assert len(urls) == 3  # deduped


def test_gau_skips_non_http(fixture_text):
    res = get("gau").parse(fixture_text("gau.txt"))
    urls = {u.url for u in res.urls}
    assert "ftp://ignored.example.com/file" not in urls
    assert "https://api.example.com/v1/users" in urls


def test_ffuf_parses_results_array(fixture_text):
    res = get("ffuf").parse(fixture_text("ffuf.json"))
    urls = {u.url for u in res.urls}
    assert urls == {
        "https://www.example.com/admin",
        "https://www.example.com/login",
    }


def test_linkfinder_endpoints(fixture_text):
    res = get("linkfinder").parse(fixture_text("linkfinder.txt"))
    eps = {e.endpoint for e in res.js_endpoints}
    assert "/api/v1/users" in eps
    assert len(eps) == 3


def test_trufflehog_never_stores_secret_value(fixture_text):
    raw = fixture_text("trufflehog.jsonl")
    res = get("trufflehog").parse(raw)
    assert len(res.secrets) == 2
    aws = next(s for s in res.secrets if s.detector == "AWS")
    assert aws.verified is True
    assert aws.location == "/run/artifacts/app.bundle.js"
    # The secret value must never appear anywhere in the parsed result.
    dumped = res.model_dump_json()
    assert "AKIAEXAMPLE" not in dumped
    assert "ghp_SHOULD_NOT_APPEAR" not in dumped


def test_arjun_params(fixture_text):
    res = get("arjun").parse(fixture_text("arjun.json"))
    params = {(p.url, p.param) for p in res.params}
    assert ("https://www.example.com/search", "debug") in params
    assert ("https://api.example.com/v1/users", "id") in params


def test_nuclei_findings_and_severity(fixture_text):
    res = get("nuclei").parse(fixture_text("nuclei.jsonl"))
    assert len(res.findings) == 3
    crit = next(f for f in res.findings if f.template_id == "CVE-2021-44228")
    assert crit.severity == "critical"
    assert crit.matched_at == "https://api.example.com/x"


def test_gowitness_screenshots(fixture_text):
    res = get("gowitness").parse(fixture_text("gowitness.txt"))
    assert len(res.screenshots) == 2
    urls = {s.url for s in res.screenshots}
    assert "https://www.example.com" in urls
    assert all(s.path.endswith(".png") for s in res.screenshots)
