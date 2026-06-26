# AI-Driven-K8s

> **AI-powered Static Application Security Testing (SAST) and Dynamic Application Security Testing (DAST) orchestrated on Kubernetes.**

---

## Overview

AI-Driven-K8s integrates leading open-source security scanners with an AI analyzer service to deliver prioritized, actionable security findings across your entire software supply chain — from source code to running services.

| Layer | Tool | Purpose |
|---|---|---|
| SAST | [Semgrep](https://semgrep.dev/) | Source-code vulnerability scanning |
| DAST | [OWASP ZAP](https://www.zaproxy.org/) | Runtime web-application scanning |
| AI Analyzer | FastAPI + heuristics | Deduplication, scoring, remediation |
| Orchestration | Kubernetes Jobs | Scalable, ephemeral scan workloads |
| CI/CD | GitHub Actions | Triggered on every push / PR / nightly |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Kubernetes Cluster                    │
│  Namespace: security-scanning                           │
│                                                         │
│  ┌──────────────┐    ┌──────────────┐                  │
│  │  SAST Job    │    │  DAST Job    │                  │
│  │  (Semgrep)   │    │  (OWASP ZAP) │                  │
│  └──────┬───────┘    └──────┬───────┘                  │
│         │ POST /analyze/sast │ POST /analyze/dast       │
│         └─────────┬──────────┘                          │
│                   ▼                                     │
│         ┌──────────────────┐                            │
│         │   AI Analyzer    │  GET /findings             │
│         │   (FastAPI)      │◄──── Dashboard / CLI       │
│         └──────────────────┘                            │
└─────────────────────────────────────────────────────────┘
```

### AI Analyzer

The AI Analyzer (`ai/analyzer.py`) receives raw JSON output from both scanning tools and applies:

- **Severity normalization** – maps tool-specific severity labels to a common enum (`CRITICAL → INFO`)
- **Heuristic priority scoring** – combines base severity, pattern matching against known high-impact vulnerability classes, tool confidence, and false-positive probability
- **Deduplication** – removes duplicate findings keyed by `(rule_id, file_path, line_number, url)`
- **Remediation guidance** – generates actionable remediation hints mapped to vulnerability categories
- **REST API** – exposes findings for integration with dashboards and alerting tools

---

## Repository Layout

```
.
├── ai/
│   ├── analyzer.py          # AI Analyzer service (FastAPI)
│   ├── requirements.txt     # Python dependencies
│   ├── Dockerfile           # Container image for AI Analyzer
│   └── tests/
│       └── test_analyzer.py # Unit tests (pytest, 36 tests)
├── k8s/
│   ├── namespace.yaml       # Kubernetes namespace
│   ├── rbac/
│   │   └── serviceaccount.yaml
│   ├── sast/
│   │   ├── job.yaml         # Semgrep scan Job + ConfigMap
│   │   └── pvc.yaml         # Source-code PersistentVolumeClaim
│   ├── dast/
│   │   └── job.yaml         # OWASP ZAP scan Job + ConfigMaps
│   └── ai-analyzer/
│       ├── deployment.yaml  # AI Analyzer Deployment
│       └── service.yaml     # ClusterIP Service
├── helm/
│   └── ai-driven-k8s/       # Helm chart for one-command deployment
│       ├── Chart.yaml
│       ├── values.yaml
│       └── templates/
├── .github/workflows/
│   ├── sast.yaml            # SAST CI/CD workflow (push / PR)
│   ├── dast.yaml            # DAST CI/CD workflow (push / nightly)
│   └── build.yaml           # AI Analyzer Docker build & push
└── scripts/
    ├── run-sast.sh          # On-demand SAST trigger script
    └── run-dast.sh          # On-demand DAST trigger script
```

---

## Quick Start

### Prerequisites

- Kubernetes cluster (v1.25+) with `kubectl` configured
- (Optional) Helm v3 for chart-based deployment
- (Optional) GitHub repository secrets for CI/CD

### 1. Deploy with kubectl

```bash
# Create namespace and RBAC
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/rbac/serviceaccount.yaml

# Deploy the AI Analyzer
kubectl apply -f k8s/ai-analyzer/deployment.yaml
kubectl apply -f k8s/ai-analyzer/service.yaml

# Run a SAST scan
kubectl apply -f k8s/sast/pvc.yaml   # ensure source code is mounted
kubectl apply -f k8s/sast/job.yaml

# Run a DAST scan (update target URL in dast/job.yaml first)
kubectl apply -f k8s/dast/job.yaml
```

### 2. Deploy with Helm

```bash
helm install ai-driven-k8s helm/ai-driven-k8s/ \
  --set dast.targetUrl="http://my-app:8080"
```

### 3. On-demand scans via scripts

```bash
# SAST
./scripts/run-sast.sh

# DAST
./scripts/run-dast.sh --target http://my-app:8080
```

---

## GitHub Actions CI/CD

| Workflow | Trigger | What it does |
|---|---|---|
| `sast.yaml` | Push / PR | Runs Semgrep, uploads SARIF to GitHub Security tab, sends results to AI Analyzer |
| `dast.yaml` | Push to main / nightly | Runs OWASP ZAP baseline scan, correlates with SAST findings |
| `build.yaml` | Push to main (ai/ changes) | Builds and pushes the AI Analyzer Docker image to GHCR |

### Required Secrets

| Secret | Description |
|---|---|
| `AI_ANALYZER_URL` | URL of the deployed AI Analyzer service (optional) |
| `DAST_TARGET_URL` | URL of the application to scan with DAST |
| `SEMGREP_APP_TOKEN` | Semgrep Cloud Platform token (optional) |

---

## AI Analyzer API

The AI Analyzer exposes a REST API on port `8080`.

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check |
| `/metrics` | GET | Scan stats and top-10 prioritized findings |
| `/analyze/sast` | POST | Accept Semgrep JSON output |
| `/analyze/dast` | POST | Accept OWASP ZAP JSON output |
| `/findings` | GET | Filtered, prioritized findings |
| `/findings` | DELETE | Clear findings store |

**Query parameters for `GET /findings`:**

| Parameter | Type | Description |
|---|---|---|
| `severity` | string | Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO) |
| `scan_type` | string | Filter by scan type (`sast` or `dast`) |
| `min_priority` | float | Minimum AI priority score (0.0–1.0) |

---

## Running Tests

```bash
pip install -r ai/requirements.txt pytest
pytest ai/tests/test_analyzer.py -v
```

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes and add tests
4. Run the test suite (`pytest ai/tests/ -v`)
5. Open a pull request

---

## License

This project is licensed under the MIT License.
