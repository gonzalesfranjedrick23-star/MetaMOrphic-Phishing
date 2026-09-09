"""Sandbox job manager - isolated static analysis with a verified lifecycle.

Lifecycle (spec part 23):
    SUBMIT -> CREATE JOB -> PREPARE WORKSPACE -> STATIC ANALYSIS
    -> [OPTIONAL ISOLATED DYNAMIC ANALYSIS] -> COLLECT OBSERVATIONS
    -> TERMINATE JOB -> CLEAN WORKSPACE (verified) -> RETURN RESULT

Safety:
- The host never executes the sample (static only).
- Every job gets its own temp workspace under ``<root>/sandbox_jobs/<job_id>``.
- Cleanup only ever removes that workspace, and verifies it is gone
  (spec part 25). It never deletes anything outside the workspace.
- Dynamic analysis is NOT_CONFIGURED - fabricating dynamic observations is
  forbidden (spec part 37).
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_S = 120
MAX_WORKSPACE_BYTES = 200 * 1024 * 1024


class SandboxStatus(str, Enum):
    NOT_CONFIGURED = "NOT_CONFIGURED"
    UNAVAILABLE = "UNAVAILABLE"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    TIMEOUT = "TIMEOUT"
    FAILED = "FAILED"
    CLEANUP_FAILED = "CLEANUP_FAILED"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class SandboxJob:
    job_id: str
    sample_name: str
    sample_sha256: Optional[str] = None
    status: str = SandboxStatus.QUEUED.value
    created: str = field(default_factory=_now)
    started: Optional[str] = None
    ended: Optional[str] = None
    analysis_duration_s: float = 0.0
    workspace: Optional[str] = None
    static_result: Optional[Dict[str, Any]] = None
    dynamic_status: str = SandboxStatus.NOT_CONFIGURED.value
    observations: List[str] = field(default_factory=list)
    risk_contribution: Optional[float] = None       # 0-1, informational
    cleanup_status: str = "pending"
    error: Optional[str] = None
    isolation_verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["sandbox_status"] = self.status
        return d


class SandboxManager:
    """Run isolated static-analysis jobs on demand."""

    def __init__(self, root: Optional[str] = None, timeout_s: int = DEFAULT_TIMEOUT_S):
        self.root = Path(root) if root else Path("./sandbox_jobs")
        self.root.mkdir(parents=True, exist_ok=True)
        self.timeout_s = timeout_s
        self._jobs: Dict[str, SandboxJob] = {}
        self._lock = threading.RLock()

    # -- public -------------------------------------------------------
    def submit(self, file_path: str, *, run_dynamic: bool = False) -> SandboxJob:
        """Submit a sample; runs synchronously with a hard timeout guard."""
        src = Path(file_path)
        job = SandboxJob(job_id=uuid.uuid4().hex[:16], sample_name=src.name)
        with self._lock:
            self._jobs[job.job_id] = job

        if not src.exists() or not src.is_file():
            job.status = SandboxStatus.FAILED.value
            job.error = f"sample not found: {file_path}"
            job.cleanup_status = "not_needed"
            return job

        result: Dict[str, Any] = {}
        worker = threading.Thread(
            target=self._run_job, args=(job, src, run_dynamic, result),
            name=f"sandbox-{job.job_id}", daemon=True,
        )
        started = time.monotonic()
        job.started = _now()
        job.status = SandboxStatus.RUNNING.value
        worker.start()
        worker.join(timeout=self.timeout_s)
        job.analysis_duration_s = round(time.monotonic() - started, 3)

        if worker.is_alive():
            job.status = SandboxStatus.TIMEOUT.value
            job.error = f"job exceeded {self.timeout_s}s timeout"
            # the daemon thread is static-only (no child processes) so it will
            # unwind on its own; force cleanup now.
            self._cleanup(job)
            job.ended = _now()
            return job

        job.ended = _now()
        return job

    def get_job(self, job_id: str) -> Optional[SandboxJob]:
        with self._lock:
            return self._jobs.get(job_id)

    def list_jobs(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [j.to_dict() for j in self._jobs.values()]

    # -- internals --------------------------------------------------
    def _run_job(self, job: SandboxJob, src: Path, run_dynamic: bool, out: Dict[str, Any]) -> None:
        try:
            workspace = (self.root / job.job_id).resolve()
            workspace.mkdir(parents=True, exist_ok=True)
            job.workspace = str(workspace)

            # isolation check: workspace must be under root and empty-ish
            job.isolation_verified = self._verify_isolation(workspace)
            if not job.isolation_verified:
                job.status = SandboxStatus.FAILED.value
                job.error = "workspace failed isolation verification"
                self._cleanup(job)
                return

            if src.stat().st_size > MAX_WORKSPACE_BYTES:
                job.status = SandboxStatus.FAILED.value
                job.error = "sample exceeds sandbox size limit"
                self._cleanup(job)
                return

            # PREPARE: copy the sample into the isolated workspace (never touch original)
            staged = workspace / f"sample{src.suffix}"
            shutil.copy2(src, staged)
            job.observations.append(f"sample staged in isolated workspace ({staged.stat().st_size} bytes)")

            # STATIC ANALYSIS via the central engine (single source of truth)
            static = self._static_analysis(str(staged))
            job.static_result = static
            job.sample_sha256 = static.get("sha256")
            job.observations.append(
                f"static analysis: {static.get('classification')} @ {static.get('risk_percent')}% "
                f"({static.get('analysis_status')})"
            )
            rp = static.get("risk_percent")
            job.risk_contribution = None if rp is None else round(float(rp) / 100.0, 4)

            # DYNAMIC ANALYSIS - honestly not configured
            if run_dynamic:
                job.dynamic_status = SandboxStatus.NOT_CONFIGURED.value
                job.observations.append(
                    "dynamic analysis requested but NOT_CONFIGURED: no isolated "
                    "execution environment is wired in (never executed on host)"
                )
            else:
                job.dynamic_status = SandboxStatus.NOT_CONFIGURED.value

            job.status = SandboxStatus.COMPLETED.value
        except Exception as exc:
            job.status = SandboxStatus.FAILED.value
            job.error = f"{exc.__class__.__name__}: {exc}"
            logger.exception("Sandbox job %s failed", job.job_id)
        finally:
            self._cleanup(job)

    def _static_analysis(self, staged_path: str) -> Dict[str, Any]:
        """Run the central malware pipeline on the staged copy."""
        from cybersentinel.orchestrator import ThreatOrchestrator
        from cybersentinel.malware_engine.analyzer import MalwareEngine

        orch = ThreatOrchestrator()  # no quarantine/notify - analysis only
        engine = MalwareEngine()
        for i, analyzer in enumerate(engine.analyzers):
            orch.register_malware_engine(f"malware_layer_{i + 1}", analyzer)
        result = asyncio.run(orch.analyze_file(staged_path, enforce=False))
        return result.outcome or {}

    def _verify_isolation(self, workspace: Path) -> bool:
        try:
            root = self.root.resolve()
            workspace.relative_to(root)
        except ValueError:
            return False
        # workspace should contain nothing but what we put there
        return not any(workspace.iterdir())

    def _cleanup(self, job: SandboxJob) -> None:
        """Remove the job workspace and verify (spec part 25). Never leaves the dir."""
        ws = job.workspace
        if not ws:
            job.cleanup_status = "not_needed"
            return
        path = Path(ws).resolve()
        try:
            path.relative_to(self.root.resolve())
        except ValueError:
            job.cleanup_status = "refused (path outside sandbox root)"
            if job.status == SandboxStatus.COMPLETED.value:
                job.status = SandboxStatus.CLEANUP_FAILED.value
            return
        try:
            if path.exists():
                shutil.rmtree(path, ignore_errors=False)
            if path.exists():
                raise OSError("workspace still present after rmtree")
            job.cleanup_status = "verified_removed"
        except Exception as exc:
            job.cleanup_status = f"failed: {exc.__class__.__name__}: {exc}"
            if job.status in (SandboxStatus.COMPLETED.value, SandboxStatus.RUNNING.value):
                job.status = SandboxStatus.CLEANUP_FAILED.value
            logger.error("Sandbox cleanup failed for %s: %s", job.job_id, exc)
