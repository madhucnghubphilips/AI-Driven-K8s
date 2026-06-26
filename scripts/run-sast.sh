#!/usr/bin/env bash
# run-sast.sh – Trigger an on-demand SAST scan in the Kubernetes cluster.
#
# Usage:
#   ./scripts/run-sast.sh [--namespace <ns>] [--image <semgrep-image>]
#
# Prerequisites:
#   - kubectl configured and pointing at the target cluster
#   - Namespace 'security-scanning' (or --namespace override) already exists
#   - Source code PVC populated (or configure an alternative volume mount)

set -euo pipefail

NAMESPACE="security-scanning"
SEMGREP_IMAGE="returntocorp/semgrep:latest"
JOB_NAME="sast-scan-$(date +%s)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --namespace) NAMESPACE="$2"; shift 2 ;;
    --image)     SEMGREP_IMAGE="$2"; shift 2 ;;
    *)           echo "Unknown option: $1"; exit 1 ;;
  esac
done

echo "==> Applying base manifests..."
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/rbac/serviceaccount.yaml
kubectl apply -f k8s/sast/pvc.yaml
kubectl apply -f k8s/ai-analyzer/deployment.yaml
kubectl apply -f k8s/ai-analyzer/service.yaml

echo "==> Waiting for AI Analyzer to be ready..."
kubectl rollout status deployment/ai-analyzer -n "$NAMESPACE" --timeout=120s

echo "==> Launching SAST scan job: $JOB_NAME"
kubectl create job "$JOB_NAME" \
  --namespace="$NAMESPACE" \
  --image="$SEMGREP_IMAGE" \
  --from=cronjob/sast-scan 2>/dev/null || \
kubectl apply -f k8s/sast/job.yaml

echo "==> Waiting for SAST job to complete..."
kubectl wait --for=condition=complete \
  --timeout=600s \
  "job/$JOB_NAME" \
  -n "$NAMESPACE" 2>/dev/null || \
kubectl wait --for=condition=complete \
  --timeout=600s \
  job/sast-scan \
  -n "$NAMESPACE"

echo "==> SAST scan complete. Fetching results from AI Analyzer..."
kubectl run -it --rm result-fetcher \
  --image=python:3.12-slim \
  --restart=Never \
  --namespace="$NAMESPACE" \
  -- python3 -c "
import urllib.request, json
resp = urllib.request.urlopen('http://ai-analyzer-service:8080/findings')
print(json.dumps(json.loads(resp.read()), indent=2))
"

echo "==> Done."
