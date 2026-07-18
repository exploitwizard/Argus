"""Scope enforcement tests — in/out-of-scope, wildcards, CIDRs, precedence."""

from __future__ import annotations

from argus.core.scope import Scope, registrable_domain

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


# ---- implicit-scope mode (Task 1) --------------------------------------- #
def test_registrable_domain_simple():
    assert registrable_domain("example.com") == "example.com"
    assert registrable_domain("api.example.com") == "example.com"
    assert registrable_domain("https://deep.api.example.com/x") == "example.com"


def test_registrable_domain_multi_label_suffix():
    assert registrable_domain("foo.bar.co.uk") == "bar.co.uk"
    assert registrable_domain("shop.example.com.au") == "example.com.au"
    assert registrable_domain("example.co.uk") == "example.co.uk"


def test_registrable_domain_none_for_ip_and_short():
    assert registrable_domain("203.0.113.5") is None
    assert registrable_domain("localhost") is None


def test_implicit_scope_from_subdomain_target():
    s = Scope.implicit("api.example.com")
    # registrable domain becomes the root: apex + all subdomains in scope
    assert s.is_in_scope("example.com")
    assert s.is_in_scope("api.example.com")
    assert s.is_in_scope("other.example.com")


def test_implicit_scope_rejects_out_of_root_hosts():
    s = Scope.implicit("example.com")
    # unrelated / third-party hosts are NOT in scope -> dropped, never probed
    assert not s.is_in_scope("evil.com")
    assert not s.is_in_scope("cdn.cloudfront.net")
    assert not s.is_in_scope("example.com.evil.com")


def test_implicit_scope_filter_drops_out_of_root():
    s = Scope.implicit("example.com")
    kept, dropped = s.filter(
        ["www.example.com", "assets.googleapis.com", "evil.com", "mail.example.com"]
    )
    assert set(kept) == {"www.example.com", "mail.example.com"}
    assert set(dropped) == {"assets.googleapis.com", "evil.com"}


def test_implicit_scope_for_ip_target():
    s = Scope.implicit("203.0.113.5")
    assert s.is_in_scope("203.0.113.5")
    assert not s.is_in_scope("203.0.113.6")
    assert not s.is_in_scope("example.com")
