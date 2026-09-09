import asyncio

from cybersentinel.common.risk_scorer import ModelPrediction, RiskScorer
from cybersentinel.xai.explainer import XAIExplainer


def test_xai_explainer_highlights_evidence():
    predictions = [
        ModelPrediction(
            model_name='malware_yara',
            malicious_probability=0.9,
            confidence=0.95,
            reasoning='YARA matched suspicious PowerShell strings',
            evidence={'matched_rules': ['SuspiciousString'], 'rule_count': 1},
        ),
        ModelPrediction(
            model_name='malware_graph',
            malicious_probability=0.7,
            confidence=0.75,
            reasoning='Graph analysis decoded PE instructions with suspicious calls',
            evidence={'instructions': 128, 'suspicious_indicators': ['call', 'jmp']},
        ),
    ]

    result = XAIExplainer().explain_prediction(predictions)

    assert result['summary']
    # the human summary names the driving detector; the raw signal lives in top_factors
    assert 'malware_yara' in result['summary']
    assert 'SuspiciousString' in str(result['top_factors'])
    assert 'malware_yara' in result['top_factors'][0]['model']
    assert result['risk_level'] in {'high', 'critical', 'medium'}

    scorer = RiskScorer()
    assessment = scorer.score(predictions)
    assert assessment.explanation
    assert 'model' in assessment.explanation.lower()
