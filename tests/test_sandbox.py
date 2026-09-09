"""Sandbox lifecycle (spec parts 22-25): isolated, cleaned up, never FAILED->SAFE."""

from pathlib import Path

from cybersentinel.sandbox import SandboxManager, SandboxStatus

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def test_completed_job_is_isolated_and_cleaned_up(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(EICAR)
    sm = SandboxManager(root=str(tmp_path / "jobs"))
    job = sm.submit(str(sample))

    assert job.status == SandboxStatus.COMPLETED.value
    assert job.isolation_verified is True
    assert job.cleanup_status == "verified_removed"
    assert not Path(job.workspace).exists()          # workspace gone
    assert sample.exists()                            # original untouched
    assert job.dynamic_status == SandboxStatus.NOT_CONFIGURED.value
    # static analysis flagged EICAR
    assert job.static_result["classification"] in ("MALICIOUS", "HIGH RISK", "SUSPICIOUS")
    assert 0.0 <= job.risk_contribution <= 1.0


def test_missing_sample_is_failed_not_safe(tmp_path):
    sm = SandboxManager(root=str(tmp_path / "jobs"))
    job = sm.submit(str(tmp_path / "does-not-exist.exe"))
    assert job.status == SandboxStatus.FAILED.value
    assert job.error
    assert job.static_result is None
    # a failed job must never look benign
    d = job.to_dict()
    assert d["sandbox_status"] == "FAILED"
    assert d.get("classification") is None


def test_dynamic_analysis_is_not_configured_not_fabricated(tmp_path):
    sample = tmp_path / "s.txt"
    sample.write_text("hello world")
    sm = SandboxManager(root=str(tmp_path / "jobs"))
    job = sm.submit(str(sample), run_dynamic=True)
    assert job.dynamic_status == SandboxStatus.NOT_CONFIGURED.value
    assert any("NOT_CONFIGURED" in o for o in job.observations)


def test_cleanup_only_touches_own_workspace(tmp_path):
    sample = tmp_path / "s.txt"
    sample.write_text("data")
    sibling = tmp_path / "jobs" / "important.txt"
    sm = SandboxManager(root=str(tmp_path / "jobs"))
    sibling.write_text("do not delete")
    job = sm.submit(str(sample))
    assert sibling.exists()      # cleanup removed only <root>/<job_id>, not siblings
    assert not Path(job.workspace).exists()
