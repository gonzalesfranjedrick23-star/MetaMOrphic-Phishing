"""Quarantine lifecycle: cross-process persistence + safe permanent delete."""

import stat
from pathlib import Path

import pytest

from cybersentinel.common.database import ThreatDatabase
from cybersentinel.quarantine.manager import QuarantineManager


def _mk(tmp_path):
    db = ThreatDatabase(db_path=str(tmp_path / "db"))
    qm = QuarantineManager(quarantine_root=str(tmp_path / "quar"), db=db)
    victim = tmp_path / "src" / "evil.exe"
    victim.parent.mkdir(parents=True, exist_ok=True)
    victim.write_bytes(b"MZ" + b"\x90" * 400)
    rec = qm.quarantine_file(str(victim), "malware", 96.8, "unit test", threat_name="MALICIOUS")
    return db, qm, rec, victim


def test_quarantine_record_survives_a_new_process(tmp_path):
    db, qm, rec, _ = _mk(tmp_path)
    assert Path(rec["quarantine_path"]).exists()

    # Simulate the website process opening the same db later.
    db2 = ThreatDatabase(db_path=str(tmp_path / "db"))
    qm2 = QuarantineManager(quarantine_root=str(tmp_path / "quar"), db=db2)
    listed = qm2.list_quarantine()
    assert any(r["quarantine_id"] == rec["quarantine_id"] for r in listed)


def test_delete_requires_confirmation(tmp_path):
    _, qm, rec, _ = _mk(tmp_path)
    with pytest.raises(ValueError):
        qm.delete_file(rec["quarantine_id"], confirm=False)
    assert Path(rec["quarantine_path"]).exists()


def test_delete_removes_payload_and_record_and_reports_hash(tmp_path):
    db, qm, rec, _ = _mk(tmp_path)
    qpath = Path(rec["quarantine_path"])
    result = qm.delete_file(rec["quarantine_id"], confirm=True)
    assert result["deleted"] is True
    assert result["sha256"] == rec["file_hash"]
    assert not qpath.exists()
    assert not any(r["quarantine_id"] == rec["quarantine_id"] for r in qm.list_quarantine())
    # and it stays gone for a fresh process
    db2 = ThreatDatabase(db_path=str(tmp_path / "db"))
    assert not any(r.quarantine_id == rec["quarantine_id"] for r in db2.get_quarantine_files())


def test_delete_rejects_path_outside_quarantine_dir(tmp_path):
    db, qm, rec, victim = _mk(tmp_path)
    # tamper the stored record to point outside the quarantine root
    outside = tmp_path / "src" / "notquarantined.txt"
    outside.write_text("do not delete me")
    db._quarantine[-1].quarantine_path = str(outside)
    with pytest.raises(ValueError):
        qm.delete_file(rec["quarantine_id"], confirm=True)
    assert outside.exists()


def test_delete_missing_payload_is_reported_not_faked(tmp_path):
    db, qm, rec, _ = _mk(tmp_path)
    Path(rec["quarantine_path"]).chmod(stat.S_IWRITE)
    Path(rec["quarantine_path"]).unlink()
    result = qm.delete_file(rec["quarantine_id"], confirm=True)
    assert result["deleted"] is True
    assert "already absent" in result["note"]


def test_restore_verifies_hash_and_clears_record(tmp_path):
    db, qm, rec, victim = _mk(tmp_path)
    dest = tmp_path / "restored" / "evil.exe"
    out = qm.restore_file(rec["quarantine_id"], str(dest))
    assert Path(out).exists()
    assert not any(r["quarantine_id"] == rec["quarantine_id"] for r in qm.list_quarantine())
