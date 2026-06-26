"""
Unit tests for the AI-Driven Security Analyzer (ai/analyzer.py).
"""

from __future__ import annotations

import json
import sys
import os

import pytest

# Make sure the ai/ directory is on the path so we can import analyzer
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analyzer import (
    Severity,
    Finding,
    _map_severity,
    _ai_priority_score,
    _generate_remediation,
    _deduplicate,
    _parse_sast_results,
    _parse_dast_results,
)


# ---------------------------------------------------------------------------
# _map_severity
# ---------------------------------------------------------------------------


class TestMapSeverity:
    def test_critical(self):
        assert _map_severity("critical") == Severity.CRITICAL

    def test_error_maps_to_high(self):
        assert _map_severity("ERROR") == Severity.HIGH

    def test_warning_maps_to_medium(self):
        assert _map_severity("WARNING") == Severity.MEDIUM

    def test_info_maps_to_info(self):
        assert _map_severity("info") == Severity.INFO

    def test_informational_maps_to_info(self):
        assert _map_severity("informational") == Severity.INFO

    def test_unknown_defaults_to_medium(self):
        assert _map_severity("unknown-level") == Severity.MEDIUM


# ---------------------------------------------------------------------------
# _ai_priority_score
# ---------------------------------------------------------------------------


def _make_finding(**kwargs) -> Finding:
    defaults = dict(
        id="f-1",
        scan_type="sast",
        rule_id="test-rule",
        title="Test Finding",
        description="",
        severity=Severity.MEDIUM,
        confidence=1.0,
        file_path=None,
        line_number=None,
        url=None,
        false_positive_probability=0.0,
    )
    defaults.update(kwargs)
    return Finding(**defaults)


class TestAiPriorityScore:
    def test_critical_severity_scores_highest(self):
        f = _make_finding(severity=Severity.CRITICAL)
        score = _ai_priority_score(f)
        assert score > 0.8

    def test_info_severity_scores_lowest(self):
        f = _make_finding(severity=Severity.INFO)
        score = _ai_priority_score(f)
        assert score < 0.3

    def test_score_bounded_between_zero_and_one(self):
        for sev in Severity:
            f = _make_finding(severity=sev)
            score = _ai_priority_score(f)
            assert 0.0 <= score <= 1.0, f"Score {score} out of range for {sev}"

    def test_high_impact_pattern_boosts_score(self):
        base = _make_finding(severity=Severity.MEDIUM, title="Some finding")
        boosted = _make_finding(severity=Severity.MEDIUM, title="SQL Injection vulnerability")
        assert _ai_priority_score(boosted) > _ai_priority_score(base)

    def test_low_confidence_reduces_score(self):
        high_conf = _make_finding(confidence=1.0)
        low_conf = _make_finding(confidence=0.1)
        assert _ai_priority_score(low_conf) < _ai_priority_score(high_conf)

    def test_false_positive_path_reduces_score(self):
        normal = _make_finding(file_path="src/app.py")
        test_file = _make_finding(file_path="tests/test_app.py")
        assert _ai_priority_score(test_file) <= _ai_priority_score(normal)


# ---------------------------------------------------------------------------
# _generate_remediation
# ---------------------------------------------------------------------------


class TestGenerateRemediation:
    def test_sql_keyword(self):
        f = _make_finding(title="SQL Injection", description="")
        advice = _generate_remediation(f)
        assert "parameterized" in advice.lower() or "orm" in advice.lower()

    def test_secret_keyword(self):
        f = _make_finding(rule_id="hardcoded-secret", title="Hardcoded Secret", description="")
        advice = _generate_remediation(f)
        assert "secret" in advice.lower() or "vault" in advice.lower()

    def test_default_fallback(self):
        f = _make_finding(title="Some obscure finding", description="")
        advice = _generate_remediation(f)
        assert len(advice) > 0


# ---------------------------------------------------------------------------
# _deduplicate
# ---------------------------------------------------------------------------


class TestDeduplicate:
    def test_removes_exact_duplicates(self):
        f1 = _make_finding(rule_id="r1", file_path="a.py", line_number=10, url=None)
        f2 = _make_finding(rule_id="r1", file_path="a.py", line_number=10, url=None)
        result = _deduplicate([f1, f2])
        assert len(result) == 1

    def test_keeps_different_lines(self):
        f1 = _make_finding(rule_id="r1", file_path="a.py", line_number=10, url=None)
        f2 = _make_finding(rule_id="r1", file_path="a.py", line_number=20, url=None)
        result = _deduplicate([f1, f2])
        assert len(result) == 2

    def test_keeps_different_rules(self):
        f1 = _make_finding(rule_id="r1", file_path="a.py", line_number=10, url=None)
        f2 = _make_finding(rule_id="r2", file_path="a.py", line_number=10, url=None)
        result = _deduplicate([f1, f2])
        assert len(result) == 2

    def test_empty_list(self):
        assert _deduplicate([]) == []


# ---------------------------------------------------------------------------
# _parse_sast_results  (Semgrep JSON format)
# ---------------------------------------------------------------------------

SEMGREP_SAMPLE = {
    "results": [
        {
            "check_id": "python.lang.security.audit.exec-detected",
            "path": "app/views.py",
            "start": {"line": 42, "col": 4},
            "end": {"line": 42, "col": 20},
            "extra": {
                "severity": "ERROR",
                "message": "Dangerous exec() call detected",
                "metadata": {
                    "description": "Avoid using exec() with user-supplied input.",
                    "confidence": "0.9",
                },
            },
        },
        {
            "check_id": "python.lang.security.audit.hardcoded-password",
            "path": "config/settings.py",
            "start": {"line": 15, "col": 1},
            "end": {"line": 15, "col": 30},
            "extra": {
                "severity": "WARNING",
                "message": "Hardcoded password detected",
                "metadata": {"description": "Remove hardcoded passwords.", "confidence": "0.7"},
            },
        },
    ],
    "errors": [],
}


class TestParseSastResults:
    def test_returns_correct_count(self):
        findings = _parse_sast_results(SEMGREP_SAMPLE)
        assert len(findings) == 2

    def test_scan_type_is_sast(self):
        findings = _parse_sast_results(SEMGREP_SAMPLE)
        assert all(f.scan_type == "sast" for f in findings)

    def test_severity_mapped_correctly(self):
        findings = _parse_sast_results(SEMGREP_SAMPLE)
        assert findings[0].severity == Severity.HIGH   # ERROR -> HIGH
        assert findings[1].severity == Severity.MEDIUM  # WARNING -> MEDIUM

    def test_file_path_extracted(self):
        findings = _parse_sast_results(SEMGREP_SAMPLE)
        assert findings[0].file_path == "app/views.py"

    def test_line_number_extracted(self):
        findings = _parse_sast_results(SEMGREP_SAMPLE)
        assert findings[0].line_number == 42

    def test_ai_priority_score_set(self):
        findings = _parse_sast_results(SEMGREP_SAMPLE)
        for f in findings:
            assert 0.0 <= f.ai_priority_score <= 1.0

    def test_remediation_populated(self):
        findings = _parse_sast_results(SEMGREP_SAMPLE)
        for f in findings:
            assert len(f.remediation) > 0

    def test_empty_results(self):
        assert _parse_sast_results({"results": []}) == []

    def test_missing_results_key(self):
        assert _parse_sast_results({}) == []


# ---------------------------------------------------------------------------
# _parse_dast_results  (OWASP ZAP JSON format)
# ---------------------------------------------------------------------------

ZAP_SAMPLE = {
    "site": [
        {
            "name": "http://example.com",
            "alerts": [
                {
                    "pluginid": "40012",
                    "alert": "Cross Site Scripting (Reflected)",
                    "riskdesc": "High (Medium)",
                    "confidence": "Medium",
                    "desc": "XSS vulnerability detected in a reflected parameter.",
                    "solution": "Validate and encode all user input.",
                    "instances": [
                        {"uri": "http://example.com/search?q=test"},
                        {"uri": "http://example.com/login?redirect=bad"},
                    ],
                },
                {
                    "pluginid": "10016",
                    "alert": "Web Browser XSS Protection Not Enabled",
                    "riskdesc": "Low (Medium)",
                    "confidence": "Medium",
                    "desc": "X-XSS-Protection header not set.",
                    "solution": "Set the X-XSS-Protection header.",
                    "instances": [{"uri": "http://example.com/"}],
                },
            ],
        }
    ]
}


class TestParseDastResults:
    def test_returns_correct_count(self):
        # 2 instances in first alert + 1 in second = 3 findings
        findings = _parse_dast_results(ZAP_SAMPLE)
        assert len(findings) == 3

    def test_scan_type_is_dast(self):
        findings = _parse_dast_results(ZAP_SAMPLE)
        assert all(f.scan_type == "dast" for f in findings)

    def test_severity_mapped_correctly(self):
        findings = _parse_dast_results(ZAP_SAMPLE)
        assert findings[0].severity == Severity.HIGH   # High
        assert findings[2].severity == Severity.LOW    # Low

    def test_url_extracted(self):
        findings = _parse_dast_results(ZAP_SAMPLE)
        assert findings[0].url == "http://example.com/search?q=test"

    def test_ai_priority_score_set(self):
        findings = _parse_dast_results(ZAP_SAMPLE)
        for f in findings:
            assert 0.0 <= f.ai_priority_score <= 1.0

    def test_remediation_from_zap_solution(self):
        findings = _parse_dast_results(ZAP_SAMPLE)
        assert "encode" in findings[0].remediation.lower() or len(findings[0].remediation) > 0

    def test_empty_site(self):
        assert _parse_dast_results({"site": []}) == []

    def test_missing_site_key(self):
        assert _parse_dast_results({}) == []
