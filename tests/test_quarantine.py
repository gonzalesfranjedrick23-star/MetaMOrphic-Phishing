import tempfile
from pathlib import Path

from cybersentinel.common.database import ThreatDatabase, ThreatRecord, QuarantineRecord
from cybersentinel.common.database import compute_file_hash


def test_quarantine_records_file_and_hash():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        sample = root / 'malware.exe'
        sample.write_bytes(b'MZ' + b'\x00' * 128)

        db = ThreatDatabase(db_path=str(root / 'db'))
        file_hash = compute_file_hash(str(sample))

        record = ThreatRecord(
            record_id='r1',
            detection_time=__import__('datetime').datetime.utcnow(),
            threat_type='malware',
            file_path=str(sample),
            file_hash=file_hash,
            risk_score=90.0,
            risk_level='critical',
            detections={'malware_yara': {'matched_rules': ['SuspiciousString']}},
            explanation='Critical malware indicators were detected.',
            action_taken='quarantined',
        )
        db.add_threat(record)

        quarantine_dir = root / 'quarantine'
        quarantine_dir.mkdir(exist_ok=True)
        qpath = quarantine_dir / 'quarantined_malware.exe'
        qpath.write_bytes(sample.read_bytes())

        qrecord = QuarantineRecord(
            quarantine_id='q1',
            original_path=str(sample),
            quarantine_path=str(qpath),
            detection_time=record.detection_time,
            file_hash=file_hash,
            file_size=sample.stat().st_size,
            threat_name='SuspiciousString',
            risk_score=90.0,
            analysis_json={'detections': record.detections},
        )
        db.add_quarantine(qrecord)

        assert db.get_quarantine_files(limit=10)[0].quarantine_path == str(qpath)
        assert db.get_quarantine_by_hash(file_hash) is not None
        assert db.get_statistics()['quarantined_files'] >= 1
