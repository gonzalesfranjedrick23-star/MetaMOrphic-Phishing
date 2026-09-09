"""Pluggable dynamic-analysis backends for the sandbox (spec parts 22-24).

CyberSentinel never executes a sample on the host. Dynamic (behavioural)
analysis, if a researcher wants it, must run inside a genuinely isolated
environment provided by one of these backends. The default is NullDynamicBackend
(NOT_CONFIGURED) - a backend must be deliberately supplied.

A backend contract:
  - available() -> (bool, reason)     is it usable right now?
  - run(sample_path, workspace, timeout_s) -> observations dict
    MUST execute the sample only inside its isolated environment, with no
    network and no writable host mounts, and clean up after itself.
"""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Tuple


class DynamicBackend(ABC):
    name: str = "abstract"

    @abstractmethod
    def available(self) -> Tuple[bool, str]:
        ...

    @abstractmethod
    def run(self, sample_path: str, workspace: str, timeout_s: int) -> Dict[str, Any]:
        ...


class NullDynamicBackend(DynamicBackend):
    """Default. Dynamic analysis is not configured - reported honestly."""

    name = "null"

    def available(self) -> Tuple[bool, str]:
        return False, "no dynamic-analysis backend configured"

    def run(self, sample_path: str, workspace: str, timeout_s: int) -> Dict[str, Any]:
        raise RuntimeError("NullDynamicBackend cannot run a sample")


class DockerDynamicBackend(DynamicBackend):
    """Skeleton: run the sample inside a locked-down disposable container.

    Enabled only when Docker is present AND an explicit analysis image is given.
    The intended invocation (not executed until an image is verified by the
    operator) is:

        docker run --rm --network none --read-only --cpus 1 --memory 512m \
            --security-opt no-new-privileges --pids-limit 128 \
            -v <workspace>:/analysis:ro <image> /analysis/<sample>

    i.e. no network, read-only rootfs, read-only sample mount, resource caps.
    """

    name = "docker"

    def __init__(self, image: str | None = None):
        self.image = image

    def available(self) -> Tuple[bool, str]:
        if shutil.which("docker") is None:
            return False, "docker executable not found on PATH"
        if not self.image:
            return False, "no analysis image configured (DockerDynamicBackend(image=...))"
        return False, (
            "docker + image present but the analysis image has not been "
            "operator-verified; refusing to auto-run. Configure explicitly."
        )

    def run(self, sample_path: str, workspace: str, timeout_s: int) -> Dict[str, Any]:
        # Deliberately not implemented: running an unverified container image to
        # execute a potentially-malicious sample is exactly what must not happen
        # automatically. An operator wires this to a hardened image + policy.
        raise RuntimeError(
            "DockerDynamicBackend.run is a skeleton - wire it to an "
            "operator-verified, network-isolated analysis image before use"
        )
