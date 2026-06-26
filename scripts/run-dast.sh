#!/usr/bin/env bash
# run-dast.sh – Trigger an on-demand DAST scan in the Kubernetes cluster.
#
# Usage:
#   ./scripts/run-dast.sh --target <url> [--namespace <ns>]
#
# Prerequisites:
#   - kubectl configured and pointing at the target cluster
#   - Namespace 'security-scanning' (or --namespace override) already exists

set -euo pipefail

NAMESPACE="security-scanning"
TARGET_URL=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)    TARGET_URL="$2"; shift 2 ;;
    --namespace) NAMESPACE="$2"; shift 2 ;;
    *)           echo "Unknown option: $1"; exit 1 ;;
  esac
done

if [[ -z "$TARGET_URL" ]]; then
  echo "Error: --target <url> is required."
  echo "Usage: $0 --target http://my-app:8080 [--namespace security-scanning]"
  exit 1
fi

echo "==> Applying base manifests..."
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/rbac/serviceaccount.yaml
kubectl apply -f k8s/ai-analyzer/deployment.yaml
kubectl apply -f k8s/ai-analyzer/service.yaml

echo "==> Waiting for AI Analyzer to be ready..."
kubectl rollout status deployment/ai-analyzer -n "$NAMESPACE" --timeout=120s

echo "==> Patching DAST target URL: $TARGET_URL"
kubectl create configmap dast-target-config \
  --namespace="$NAMESPACE" \
  --from-literal=target-url="$TARGET_URL" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "==> Launching DAST scan job..."
kubectl apply -f k8s/dast/job.yaml

echo "==> Waiting for DAST job to complete (this may take several minutes)..."
kubectl wait --for=condition=complete \
  --timeout=1800s \
  job/dast-scan \
  -n "$NAMESPACE"

echo "==> DAST scan complete. Fetching results from AI Analyzer..."
kubectl run -it --rm result-fetcher \
  --image=curlimages/curl:latest \
  --restart=Never \
  --namespace="$NAMESPACE" \
  -- curl -sf "http://ai-analyzer-service:8080/findings?scan_type=dast" | python3 -m json.tool

echo "==> Done."
