import asyncio
from pathlib import Path
from cybersentinel.malware_engine.analyzer import YARAAnalyzer

p = Path('eicar_test.txt')
p.write_bytes(b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')
a = YARAAnalyzer()
b = p.read_bytes()
print('rules loaded', len(a.rules))
print('rule names', [r['name'] for r in a.rules])
print('fallback matches', a._scan_rules_fallback(b))
result = asyncio.run(a.analyze(str(p)))
print('model', result.model_name)
print('prob', result.malicious_probability)
print('evidence', result.evidence)
print('reasoning', result.reasoning)
