"""Config tests — keyring round-trip (mocked) and settings, secret hygiene."""

from __future__ import annotations

import pytest

from argus.core import config


@pytest.fixture
def fake_keyring(monkeypatch):
    """In-memory keyring backend so no real OS keyring is touched."""
    store: dict[tuple[str, str], str] = {}
    monkeypatch.setattr(config.keyring, "set_password",
                        lambda service, name, val: store.__setitem__((service, name), val))
    monkeypatch.setattr(config.keyring, "get_password",
                        lambda service, name: store.get((service, name)))
    monkeypatch.setattr(config.keyring, "delete_password",
                        lambda service, name: store.pop((service, name), None))
    return store


def test_keyring_round_trip(fake_keyring):
    config.set_api_key("anthropic", "sk-secret-123")
    assert config.get_api_key("anthropic") == "sk-secret-123"
    assert config.has_api_key("anthropic")
    config.delete_api_key("anthropic")
    assert config.get_api_key("anthropic") is None


def test_ollama_needs_no_key(fake_keyring):
    assert config.has_api_key("ollama")  # no key required
    assert "ollama" in config.configured_providers()


def test_configured_providers_reflects_stored_keys(fake_keyring):
    assert set(config.configured_providers()) == {"ollama"}
    config.set_api_key("openai", "sk-x")
    assert set(config.configured_providers()) == {"openai", "ollama"}


def test_settings_round_trip_never_persists_key(fake_keyring):
    s = config.load_settings()
    s.default_model = "gpt-5.1"
    s.provider_defaults["openai"] = "gpt-5.1"
    config.save_settings(s)
    text = config.paths.settings_path().read_text(encoding="utf-8")
    assert "gpt-5.1" in text
    assert "api_key" not in text  # secrets never land in the settings file
    reloaded = config.load_settings()
    assert reloaded.default_model == "gpt-5.1"


def test_load_settings_drops_stray_api_key(fake_keyring):
    config.paths.settings_path().write_text(
        "default_model: x\napi_key: LEAKED\n", encoding="utf-8"
    )
    s = config.load_settings()
    assert not hasattr(s, "api_key")
    assert s.default_model == "x"
