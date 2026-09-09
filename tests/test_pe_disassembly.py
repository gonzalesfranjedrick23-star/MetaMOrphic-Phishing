import asyncio

from cybersentinel.malware_engine.analyzer import GraphAnalyzer
from cybersentinel.malware_engine.pe_disassembler import PEDisassembler


def test_pe_disassembler_handles_small_binary(tmp_path):
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"MZ" + b"\x00" * 64)

    disassembler = PEDisassembler()
    result = disassembler.disassemble_file(str(file_path))

    assert result is not None
    assert result.file_path == str(file_path)
    assert result.instructions
    assert 0.0 <= result.risk_score <= 1.0


def test_graph_analyzer_uses_pe_disassembler(tmp_path):
    file_path = tmp_path / "sample.exe"
    file_path.write_bytes(b"MZ" + b"\x00" * 128)

    analyzer = GraphAnalyzer()
    prediction = asyncio.run(analyzer.analyze(str(file_path)))

    assert prediction is not None
    assert prediction.model_name == "malware_graph"
    assert 0.0 <= prediction.malicious_probability <= 1.0
    assert prediction.reasoning
