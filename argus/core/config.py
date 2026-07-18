"""Provider/model configuration and secret storage.

API keys live only in the OS keyring — never in the repo, never in a settings
file, never printed back. Non-secret preferences (default model, per-provider
defaults, Ollama URL) live in a YAML settings file under the platform config dir.
"""

from __future__ import annotations

from typing import Optional

import keyring
import yaml
from keyring.errors import KeyringError
from pydantic import BaseModel, Field

from argus.core import paths

KEYRING_SERVICE = "argus"


class ProviderSpec(BaseModel):
    key: str
    litellm_prefix: str  # how litellm addresses this provider's models
    env_var: str  # env var litellm reads the key from
    needs_key: bool = True
    default_model: str = ""


# The supported providers. Ollama needs no key (fully-local hunting).
PROVIDERS: dict[str, ProviderSpec] = {
    "anthropic": ProviderSpec(
        key="anthropic", litellm_prefix="", env_var="ANTHROPIC_API_KEY",
        default_model="claude-sonnet-5",
    ),
    "openai": ProviderSpec(
        key="openai", litellm_prefix="", env_var="OPENAI_API_KEY",
        default_model="gpt-5.1",
    ),
    "gemini": ProviderSpec(
        key="gemini", litellm_prefix="gemini/", env_var="GEMINI_API_KEY",
        default_model="gemini/gemini-2.5-pro",
    ),
    "groq": ProviderSpec(
        key="groq", litellm_prefix="groq/", env_var="GROQ_API_KEY",
        default_model="groq/llama-3.3-70b-versatile",
    ),
    "deepseek": ProviderSpec(
        key="deepseek", litellm_prefix="deepseek/", env_var="DEEPSEEK_API_KEY",
        default_model="deepseek/deepseek-chat",
    ),
    "ollama": ProviderSpec(
        key="ollama", litellm_prefix="ollama/", env_var="", needs_key=False,
        default_model="ollama/llama3.1",
    ),
}


class Settings(BaseModel):
    """Non-secret preferences. Never contains an API key."""

    default_model: str = "claude-sonnet-5"
    provider_defaults: dict[str, str] = Field(default_factory=dict)
    ollama_base_url: str = "http://localhost:11434"
    # Per-phase (per-role) model assignment for multi-model runs:
    # {"mechanical": "<fast-model>", "triage": "<strong>", "reporting": "<strong>"}
    phase_models: dict[str, str] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# secrets (keyring)
# --------------------------------------------------------------------------- #
def _key_name(provider: str) -> str:
    return f"{provider}_api_key"


def set_api_key(provider: str, api_key: str) -> None:
    """Store an API key in the OS keyring. The value is never logged."""
    keyring.set_password(KEYRING_SERVICE, _key_name(provider), api_key)


def get_api_key(provider: str) -> Optional[str]:
    try:
        return keyring.get_password(KEYRING_SERVICE, _key_name(provider))
    except KeyringError:
        return None


def delete_api_key(provider: str) -> None:
    try:
        keyring.delete_password(KEYRING_SERVICE, _key_name(provider))
    except KeyringError:
        pass


def has_api_key(provider: str) -> bool:
    spec = PROVIDERS.get(provider)
    if spec and not spec.needs_key:
        return True
    return bool(get_api_key(provider))


def configured_providers() -> list[str]:
    """Providers that are ready to use (key present, or key not required)."""
    return [name for name in PROVIDERS if has_api_key(name)]


# --------------------------------------------------------------------------- #
# settings (non-secret YAML)
# --------------------------------------------------------------------------- #
def load_settings() -> Settings:
    path = paths.settings_path()
    if not path.exists():
        return Settings()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    data.pop("api_key", None)  # defensive: never accept a key from the file
    return Settings(**{k: v for k, v in data.items() if k in Settings.model_fields})


def save_settings(settings: Settings) -> None:
    path = paths.settings_path()
    path.write_text(
        yaml.safe_dump(settings.model_dump(), sort_keys=False),
        encoding="utf-8",
    )


def default_model_for(provider: str) -> str:
    return PROVIDERS[provider].default_model
