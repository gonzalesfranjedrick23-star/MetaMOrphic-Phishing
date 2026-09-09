import asyncio
from pathlib import Path

from cybersentinel.malware_engine.analyzer import YARAAnalyzer, GraphAnalyzer


def test_yara_analyzer_detects_suspicious_strings(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule_file = rules_dir / "suspicious.yar"
    rule_file.write_text(
        '''
rule SuspiciousString {
    strings:
        $s1 = "powershell" ascii
        $s2 = "URLDownloadToFile" ascii
    condition:
        any of them
}
'''
    )

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"powershell /c URLDownloadToFile http://example.com payload.exe")

    analyzer = YARAAnalyzer(rules_dir=str(rules_dir))
    prediction = analyzer.analyze.__wrapped__ if hasattr(analyzer.analyze, '__wrapped__') else None

    import asyncio
    result = asyncio.run(analyzer.analyze(str(sample)))

    assert result is not None
    assert result.model_name == "malware_yara"
    assert result.malicious_probability > 0.5
    assert "SuspiciousString" in str(result.evidence)


def test_graph_analyzer_non_pe_is_recorded_as_not_applicable(tmp_path):
    sample = tmp_path / "sample.txt"
    sample.write_text("plain-text sample with no PE header")

    analyzer = GraphAnalyzer()
    result = asyncio.run(analyzer.analyze(str(sample)))

    assert result is not None
    assert result.model_name == "malware_graph"
    assert result.malicious_probability == 0.0
    assert result.evidence["is_pe"] is False
    assert result.evidence["analysis_status"] == "not_applicable"
    assert result.evidence["available"] is False
