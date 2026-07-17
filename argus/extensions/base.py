"""The extension contract — ARGUS's goose-style pluggable tool interface.

Every recon tool is an :class:`Extension` subclass implementing a uniform
contract: ``name``, ``phase``, ``required_binary``, ``is_available()``,
``build_command()``, ``parse()``, and an inherited ``run()`` that ties them
together with scope, dry-run, and graceful degradation when a binary is missing.

A missing binary is never an error: :meth:`Extension.run` returns an
``ExtensionResult(available=False)`` and phases simply skip it.
"""

from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod

from pydantic import BaseModel, Field

from argus.core.models import ExtensionResult, Phase
from argus.core.scope import Scope


class ExtensionInputs(BaseModel):
    """Everything an extension might need to build its command.

    Extensions read only the fields they care about. ``targets`` is always the
    already-scope-filtered set of hosts/URLs to act on.
    """

    targets: list[str] = Field(default_factory=list)
    run_dir: str | None = None
    wordlist: str | None = None
    resolvers: str | None = None
    rate_limit: int = 10
    concurrency: int = 20
    intensity: str = "med"
    extra_flags: list[str] = Field(default_factory=list)
    nuclei_templates: str | None = None


class Extension(ABC):
    """Base class for every recon tool wrapper.

    Subclasses set the class attributes and implement :meth:`build_command` and
    :meth:`parse`. :meth:`run` is provided and handles availability, dry-run,
    subprocess execution, timeouts, and error capture uniformly.
    """

    name: str = ""
    phase: Phase = Phase.ENUMERATION
    required_binary: str = ""
    install_hint: str = ""
    description: str = ""
    default_timeout: int = 900

    # ---- capability ----------------------------------------------------- #
    def is_available(self) -> bool:
        """True if the required binary is resolvable on PATH."""
        return shutil.which(self.required_binary) is not None

    # ---- contract ------------------------------------------------------- #
    @abstractmethod
    def build_command(self, inputs: ExtensionInputs, scope: Scope) -> list[str]:
        """Build the argv list for this tool. Never include out-of-scope hosts."""

    @abstractmethod
    def parse(self, output: str) -> ExtensionResult:
        """Parse raw tool stdout into a typed :class:`ExtensionResult`."""

    # ---- execution ------------------------------------------------------ #
    def _empty(self, **kw: object) -> ExtensionResult:
        return ExtensionResult(extension=self.name, phase=self.phase, **kw)  # type: ignore[arg-type]

    def run(
        self,
        inputs: ExtensionInputs,
        scope: Scope,
        *,
        dry_run: bool = False,
        timeout: int | None = None,
    ) -> ExtensionResult:
        """Execute the tool (or plan it, under ``dry_run``) and return results.

        Contract guarantees:
          * missing binary -> ``available=False``, never raises;
          * ``dry_run=True`` -> builds the command but sends no traffic;
          * subprocess failure/timeout -> captured in ``errors``, never raises.
        """
        if not self.is_available():
            return self._empty(available=False)

        try:
            command = self.build_command(inputs, scope)
        except Exception as exc:  # defensive: a bad command must not crash a run
            return self._empty(errors=[f"build_command failed: {exc}"])

        if not command:
            return self._empty(ran=False, errors=["no in-scope targets"])

        if dry_run:
            return self._empty(command=command, dry_run=True, ran=False)

        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout or self.default_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return self._empty(command=command, errors=["timed out"])
        except OSError as exc:
            return self._empty(command=command, errors=[f"exec failed: {exc}"])

        result = self.parse(proc.stdout)
        result.command = command
        result.ran = True
        if proc.returncode != 0 and proc.stderr:
            result.errors.append(proc.stderr.strip().splitlines()[-1][:300])
        return result
