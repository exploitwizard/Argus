"""ARGUS — Autonomous Recon & Guided Unified Scanner.

An LLM-driven, six-phase reconnaissance agent for *authorized* bug bounty and
penetration-testing work. Recon and detection only: no exploitation, no
credential spraying, no brute-forcing of authentication.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]

# Silence a noisy third-party warning emitted by langchain-core on Python 3.14+
# (it imports pydantic.v1 for back-compat). It is harmless and clutters CLI output.
import warnings as _warnings

_warnings.filterwarnings(
    "ignore",
    message="Core Pydantic V1 functionality isn't compatible with Python 3.14 or greater",
)
