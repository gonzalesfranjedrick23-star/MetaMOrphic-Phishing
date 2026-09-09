"""Central enforcement policy (spec parts 6, 25, 32) + shared schema field."""

from cybersentinel.common.result import enforcement_for, EnforcementAction


def test_malware_policy():
    assert enforcement_for("MALICIOUS", "critical", "file") == "QUARANTINE"
    assert enforcement_for("MALICIOUS", "critical", "file", quarantine_enabled=False) == "BLOCK"
    assert enforcement_for("HIGH RISK", "high", "file") == "QUARANTINE"
    assert enforcement_for("HIGH RISK", "high", "file", quarantine_enabled=False) == "BLOCK"
    assert enforcement_for("SUSPICIOUS", "medium", "file") == "WARN"
    assert enforcement_for("SAFE", "safe", "file") == "ALLOW"


def test_phishing_policy():
    assert enforcement_for("PHISHING", "critical", "url") == "REDIRECT"
    assert enforcement_for("PHISHING", "high", "url") == "REDIRECT"
    assert enforcement_for("SUSPICIOUS", "medium", "url") == "WARN"
    assert enforcement_for("SAFE", "low", "url") == "ALLOW"


def test_failure_states_never_allow():
    assert enforcement_for("UNKNOWN", "unknown", "file") == "ANALYSIS_INCOMPLETE"
    assert enforcement_for("SAFE", "safe", "file", "failed") == "ANALYSIS_INCOMPLETE"
    assert enforcement_for("UNKNOWN", "unknown", "url") == "ANALYSIS_INCOMPLETE"


def test_enum_values_match_spec():
    assert {e.value for e in EnforcementAction} == {
        "ALLOW", "WARN", "BLOCK", "QUARANTINE", "REDIRECT", "ANALYSIS_INCOMPLETE",
    }
