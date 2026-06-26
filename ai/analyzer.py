"""
AI-Driven Security Analyzer for SAST and DAST Results.

This service receives scan results from SAST (Semgrep) and DAST (OWASP ZAP)
tools running in Kubernetes and uses AI/ML techniques to:
  - Deduplicate and correlate findings across tools
  - Score and prioritize vulnerabilities using CVSS and ML models
  - Generate actionable remediation guidance
  - Reduce false positives using heuristic and learned patterns
  - Expose aggregated results via a REST API
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s – %(message)s",
)
logger = logging.getLogger("ai-analyzer")

app = FastAPI(
    title="AI-Driven Security Analyzer",
    description="Analyzes SAST and DAST results with AI-assisted prioritization",
    version="1.0.0",
)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    id: str
    scan_type: str          # "sast" | "dast"
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: float       # 0.0–1.0
    file_path: str | None
    line_number: int | None
    url: str | None
    ai_priority_score: float = 0.0
    remediation: str = ""
    false_positive_probability: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# In-memory store (replace with a database in production)
_findings: list[Finding] = []
_scan_stats: dict[str, Any] = {
    "sast_scans": 0,
    "dast_scans": 0,
    "total_findings": 0,
    "last_scan": None,
}

# ---------------------------------------------------------------------------
# AI / heuristic scoring
# ---------------------------------------------------------------------------

# Known high-impact patterns that raise priority
_HIGH_IMPACT_PATTERNS = [
    re.compile(r"sql.injection", re.I),
    re.compile(r"remote.code.execution", re.I),
    re.compile(r"command.injection", re.I),
    re.compile(r"path.traversal", re.I),
    re.compile(r"xxe", re.I),
    re.compile(r"ssrf", re.I),
    re.compile(r"deserialization", re.I),
    re.compile(r"hardcoded.secret", re.I),
    re.compile(r"authentication.bypass", re.I),
    re.compile(r"privilege.escalation", re.I),
]

# Patterns that suggest a likely false positive
_FALSE_POSITIVE_PATTERNS = [
    re.compile(r"test", re.I),
    re.compile(r"mock", re.I),
    re.compile(r"example", re.I),
    re.compile(r"sample", re.I),
    re.compile(r"demo", re.I),
    re.compile(r"dummy", re.I),
]

_SEVERITY_BASE_SCORE: dict[str, float] = {
    "CRITICAL": 1.0,
    "HIGH": 0.8,
    "MEDIUM": 0.5,
    "LOW": 0.2,
    "INFO": 0.1,
    "ERROR": 0.8,
    "WARNING": 0.5,
    "INFORMATIONAL": 0.1,
}

_REMEDIATION_TEMPLATES: dict[str, str] = {
    "sql": (
        "Use parameterized queries or an ORM instead of string concatenation. "
        "Validate and sanitize all user input before use in database queries."
    ),
    "xss": (
        "Encode all user-supplied data before rendering in HTML. "
        "Apply a strict Content-Security-Policy header."
    ),
    "injection": (
        "Avoid passing user input to system commands. "
        "If unavoidable, use an allowlist and properly escape arguments."
    ),
    "secret": (
        "Remove the hardcoded credential immediately and rotate it. "
        "Store secrets in a vault solution (e.g. HashiCorp Vault, AWS Secrets Manager) "
        "and inject them via environment variables or Kubernetes Secrets."
    ),
    "auth": (
        "Enforce strong authentication mechanisms. "
        "Use established libraries for session management and token validation."
    ),
    "crypto": (
        "Replace weak or deprecated cryptographic algorithms with industry-standard ones "
        "(e.g. AES-256-GCM, RSA-2048+, SHA-256). Ensure proper key management."
    ),
    "path": (
        "Validate and sanitize file paths. Use an allowlist of permitted directories "
        "and avoid constructing paths from user input."
    ),
    "default": (
        "Review the flagged code and apply the principle of least privilege. "
        "Consult OWASP guidelines for remediation best practices."
    ),
}


def _map_severity(raw: str) -> Severity:
    """Normalise severity strings from different tools to our enum."""
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "error": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "warning": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
        "informational": Severity.INFO,
    }
    return mapping.get(raw.lower(), Severity.MEDIUM)


def _ai_priority_score(finding: Finding) -> float:
    """
    Heuristic-based priority score (0.0–1.0).

    In a production system this would call an ML model trained on historical
    vulnerability data.  Here we combine:
      - Base score from severity
      - Boost for known high-impact patterns
      - Confidence weighting
      - Penalty for likely false positives
    """
    score = _SEVERITY_BASE_SCORE.get(finding.severity.value, 0.5)

    title_desc = f"{finding.title} {finding.description} {finding.rule_id}".lower()
    for pattern in _HIGH_IMPACT_PATTERNS:
        if pattern.search(title_desc):
            score = min(1.0, score + 0.15)

    score *= finding.confidence

    fp_prob = finding.false_positive_probability
    if finding.file_path:
        path_lower = finding.file_path.lower()
        hits = sum(1 for p in _FALSE_POSITIVE_PATTERNS if p.search(path_lower))
        if hits:
            fp_prob = min(1.0, fp_prob + 0.1 * hits)

    score *= 1.0 - fp_prob * 0.5
    return round(min(1.0, max(0.0, score)), 4)


def _generate_remediation(finding: Finding) -> str:
    """Return a remediation hint based on the finding's title/description."""
    text = f"{finding.title} {finding.description} {finding.rule_id}".lower()
    for keyword, advice in _REMEDIATION_TEMPLATES.items():
        if keyword in text:
            return advice
    return _REMEDIATION_TEMPLATES["default"]


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings by (rule_id, file_path, line_number)."""
    seen: set[tuple] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.file_path, f.line_number, f.url)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ---------------------------------------------------------------------------
# SAST result parser (Semgrep JSON format)
# ---------------------------------------------------------------------------


def _parse_sast_results(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    results = data.get("results", [])
    for idx, result in enumerate(results):
        extra = result.get("extra", {})
        severity_raw = extra.get("severity", "WARNING")
        severity = _map_severity(severity_raw)

        finding = Finding(
            id=f"sast-{idx}-{int(time.time())}",
            scan_type="sast",
            rule_id=result.get("check_id", f"unknown-{idx}"),
            title=extra.get("message", result.get("check_id", "Unknown")),
            description=extra.get("metadata", {}).get("description", ""),
            severity=severity,
            confidence=float(extra.get("metadata", {}).get("confidence", 0.8)),
            file_path=result.get("path"),
            line_number=result.get("start", {}).get("line"),
            url=None,
        )
        finding.false_positive_probability = 0.0
        finding.ai_priority_score = _ai_priority_score(finding)
        finding.remediation = _generate_remediation(finding)
        findings.append(finding)
    return findings


# ---------------------------------------------------------------------------
# DAST result parser (OWASP ZAP JSON format)
# ---------------------------------------------------------------------------


def _parse_dast_results(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    idx = 0
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk = alert.get("riskdesc", "Low").split()[0]
            severity = _map_severity(risk)
            confidence_map = {"High": 0.9, "Medium": 0.7, "Low": 0.5}
            confidence_raw = alert.get("confidence", "Medium")
            confidence = confidence_map.get(confidence_raw, 0.6)

            instances = alert.get("instances", [{}])
            for instance in instances:
                finding = Finding(
                    id=f"dast-{idx}-{int(time.time())}",
                    scan_type="dast",
                    rule_id=alert.get("pluginid", f"zap-{idx}"),
                    title=alert.get("alert", "Unknown"),
                    description=alert.get("desc", ""),
                    severity=severity,
                    confidence=confidence,
                    file_path=None,
                    line_number=None,
                    url=instance.get("uri"),
                )
                finding.false_positive_probability = 0.0
                finding.ai_priority_score = _ai_priority_score(finding)
                finding.remediation = (
                    alert.get("solution", "") or _generate_remediation(finding)
                )
                findings.append(finding)
                idx += 1
    return findings


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "version": "1.0.0"}


@app.get("/metrics")
async def metrics() -> dict[str, Any]:
    """Return scan statistics and finding severity distribution."""
    severity_counts: dict[str, int] = {s.value: 0 for s in Severity}
    for f in _findings:
        severity_counts[f.severity.value] += 1
    return {
        "scan_stats": _scan_stats,
        "total_findings": len(_findings),
        "severity_distribution": severity_counts,
        "top_findings": [
            asdict(f)
            for f in sorted(_findings, key=lambda x: x.ai_priority_score, reverse=True)[:10]
        ],
    }


@app.post("/analyze/sast")
async def analyze_sast(request: Request) -> JSONResponse:
    """Accept Semgrep JSON output and process it with the AI analyzer."""
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {exc}") from exc

    new_findings = _parse_sast_results(body)
    new_findings = _deduplicate(new_findings)
    _findings.extend(new_findings)

    _scan_stats["sast_scans"] += 1
    _scan_stats["total_findings"] += len(new_findings)
    _scan_stats["last_scan"] = datetime.now(timezone.utc).isoformat()

    logger.info("SAST scan processed: %d findings", len(new_findings))

    return JSONResponse(
        status_code=200,
        content={
            "status": "processed",
            "scan_type": "sast",
            "findings_count": len(new_findings),
            "findings": [asdict(f) for f in new_findings],
        },
    )


@app.post("/analyze/dast")
async def analyze_dast(request: Request) -> JSONResponse:
    """Accept OWASP ZAP JSON output and process it with the AI analyzer."""
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {exc}") from exc

    new_findings = _parse_dast_results(body)
    new_findings = _deduplicate(new_findings)
    _findings.extend(new_findings)

    _scan_stats["dast_scans"] += 1
    _scan_stats["total_findings"] += len(new_findings)
    _scan_stats["last_scan"] = datetime.now(timezone.utc).isoformat()

    logger.info("DAST scan processed: %d findings", len(new_findings))

    return JSONResponse(
        status_code=200,
        content={
            "status": "processed",
            "scan_type": "dast",
            "findings_count": len(new_findings),
            "findings": [asdict(f) for f in new_findings],
        },
    )


@app.get("/findings")
async def get_findings(
    severity: str | None = None,
    scan_type: str | None = None,
    min_priority: float = 0.0,
) -> JSONResponse:
    """Return filtered, AI-prioritized findings."""
    results = list(_findings)

    if severity:
        try:
            sev = Severity(severity.upper())
            results = [f for f in results if f.severity == sev]
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid severity: {severity}")

    if scan_type:
        results = [f for f in results if f.scan_type == scan_type.lower()]

    results = [f for f in results if f.ai_priority_score >= min_priority]
    results.sort(key=lambda x: x.ai_priority_score, reverse=True)

    return JSONResponse(
        content={
            "total": len(results),
            "findings": [asdict(f) for f in results],
        }
    )


@app.delete("/findings")
async def clear_findings() -> dict[str, str]:
    """Clear all stored findings (useful between scan cycles)."""
    _findings.clear()
    _scan_stats.update(
        sast_scans=0, dast_scans=0, total_findings=0, last_scan=None
    )
    return {"status": "cleared"}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
