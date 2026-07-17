"""LiteLLM provider abstraction.

Keeps LiteLLM as the single model gateway so ARGUS supports Anthropic, OpenAI,
Gemini, Groq, DeepSeek, and local Ollama with per-run model switching. Keys are
pulled from the keyring and injected only into the call — never logged.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from argus.core import config


@dataclass
class PingResult:
    provider: str
    model: str
    ok: bool
    detail: str


def _provider_of_model(model: str) -> str:
    """Best-effort provider inference from a litellm model string."""
    if "/" in model:
        prefix = model.split("/", 1)[0]
        if prefix in config.PROVIDERS:
            return prefix
    if model.startswith("claude"):
        return "anthropic"
    if model.startswith(("gpt", "o1", "o3", "o4")):
        return "openai"
    if model.startswith("gemini"):
        return "gemini"
    return "anthropic"


def _call_kwargs(model: str) -> dict:
    """Assemble litellm kwargs, injecting the key for the model's provider."""
    provider = _provider_of_model(model)
    spec = config.PROVIDERS.get(provider)
    kwargs: dict = {"model": model}
    if spec is None:
        return kwargs
    if spec.needs_key:
        key = config.get_api_key(provider)
        if key:
            kwargs["api_key"] = key
    else:  # ollama
        kwargs["api_base"] = config.load_settings().ollama_base_url
    return kwargs


def complete(
    model: str,
    messages: list[dict],
    *,
    max_tokens: int = 1024,
    temperature: float = 0.2,
) -> str:
    """Run a chat completion via litellm and return the assistant text."""
    import litellm  # imported lazily so `--help` etc. stay fast

    resp = litellm.completion(
        messages=messages,
        max_tokens=max_tokens,
        temperature=temperature,
        **_call_kwargs(model),
    )
    return resp["choices"][0]["message"]["content"] or ""


def ping(model: str) -> PingResult:
    """1-token liveness ping. Returns a structured result, never raises."""
    import litellm

    provider = _provider_of_model(model)
    try:
        litellm.completion(
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=1,
            **_call_kwargs(model),
        )
        return PingResult(provider=provider, model=model, ok=True, detail="ok")
    except Exception as exc:  # any provider/network error -> not-ok, no traceback
        return PingResult(
            provider=provider, model=model, ok=False, detail=_short_error(exc)
        )


def _short_error(exc: Exception) -> str:
    msg = str(exc).strip().splitlines()[0] if str(exc).strip() else exc.__class__.__name__
    return msg[:160]


def resolve_model(cli_model: Optional[str]) -> str:
    """Pick the model for a run: CLI override > settings default."""
    if cli_model:
        return cli_model
    return config.load_settings().default_model
