from app.engine.risk_scorer import RiskScorer
from app.engine.sanitizer import Sanitizer


def test_risk_scorer_zero_findings():
    scorer = RiskScorer()
    res = scorer.calculate([])
    assert res["risk_score"] == 0.0
    assert res["counts"]["CRITICAL"] == 0
    assert res["distinct_resources_affected"] == 0


def test_risk_scorer_critical_findings():
    scorer = RiskScorer()
    findings = [
        {"severity": "CRITICAL", "resource_id": "res-1"},
        {"severity": "CRITICAL", "resource_id": "res-2"},
        {"severity": "HIGH", "resource_id": "res-3"},
    ]
    res = scorer.calculate(findings, total_resources=3)
    assert res["risk_score"] > 0.0
    assert res["risk_score"] <= 100.0
    assert res["counts"]["CRITICAL"] == 2
    assert res["counts"]["HIGH"] == 1
    assert res["distinct_resources_affected"] == 3


def test_sanitizer_redaction():
    raw_evidence = {
        "bucket_name": "vault",
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "nested": {
            "password": "supersecretpassword123!",
            "normal_field": "public-read",
        },
    }
    sanitized = Sanitizer.sanitize_dict(raw_evidence)
    assert sanitized["aws_secret_access_key"] == "***REDACTED_SECRET***"
    assert sanitized["nested"]["password"] == "***REDACTED_SECRET***"
    assert sanitized["nested"]["normal_field"] == "public-read"


def test_sanitizer_csv_formula_injection():
    # Danger prefixes: =, +, -, @, \t, \r
    assert Sanitizer.sanitize_csv_cell("=cmd|'/C calc'!A0") == "'=cmd|'/C calc'!A0"
    assert Sanitizer.sanitize_csv_cell("+12345") == "'+12345"
    assert Sanitizer.sanitize_csv_cell("-12345") == "'-12345"
    assert Sanitizer.sanitize_csv_cell("@SUM(1,2)") == "'@SUM(1,2)"
    assert Sanitizer.sanitize_csv_cell("normal-string") == "normal-string"


def test_sanitizer_html_escape():
    raw = "<script>alert('xss')</script>"
    escaped = Sanitizer.escape_html(raw)
    assert "<script>" not in escaped
    assert "&lt;script&gt;" in escaped
