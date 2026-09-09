"""On-demand isolated analysis jobs (spec parts 22-25).

This sandbox performs STATIC analysis inside a dedicated, per-job temporary
workspace that is always cleaned up. It does NOT execute the sample on the host.
Dynamic (behavioural) analysis is reported as NOT_CONFIGURED unless a genuinely
isolated backend is wired in - a failed or unavailable job is never reported as
SAFE.
"""

from .manager import SandboxManager, SandboxJob, SandboxStatus

__all__ = ["SandboxManager", "SandboxJob", "SandboxStatus"]
