"""Scope enforcement tests — in/out-of-scope, wildcards, CIDRs, precedence."""

from __future__ import annotations

from argus.core.scope import Scope

SCOPE = Scope.from_dict(
    {
        "engagement": "test",
        "in_scope": {
            "domains": ["example.com", "*.example.com"],
            "cidrs": ["203.0.113.0/24"],
        },
        "out_of_scope": {
            "domains": ["blog.example.com", "*.corp.example.com"],
        },
        "limits": {"max_hosts_per_phase": 3},
    }
)


def test_apex_and_subdomains_in_scope():
    assert SCOPE.is_in_scope("example.com")
    assert SCOPE.is_in_scope("api.example.com")
    assert SCOPE.is_in_scope("https://deep.api.example.com/path?x=1")


def test_out_of_scope_precedence():
    # matches *.example.com but is explicitly out of scope
    assert not SCOPE.is_in_scope("blog.example.com")
    assert not SCOPE.is_in_scope("internal.corp.example.com")


def test_unrelated_domain_out():
    assert not SCOPE.is_in_scope("evil.com")
    assert not SCOPE.is_in_scope("notexample.com")


def test_cidr_matching():
    assert SCOPE.is_in_scope("203.0.113.5")
    assert not SCOPE.is_in_scope("203.0.114.5")


def test_filter_splits_and_caps():
    kept, dropped = SCOPE.filter(
        ["api.example.com", "evil.com", "blog.example.com", "dev.example.com"]
    )
    assert set(kept) == {"api.example.com", "dev.example.com"}
    assert set(dropped) == {"evil.com", "blog.example.com"}


def test_wildcard_does_not_leak_to_sibling_domain():
    s = Scope.from_dict({"in_scope": {"domains": ["*.example.com"]}})
    assert not s.is_in_scope("example.com.evil.com")
    assert s.is_in_scope("a.example.com")
