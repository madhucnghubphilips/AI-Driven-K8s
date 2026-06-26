# Kubernetes Baseline Hardening

Prefer non-root containers, immutable image references, read-only root filesystems, CPU and memory requests and limits, and restricted Linux capabilities. Disable privilege escalation with `allowPrivilegeEscalation: false` and drop all capabilities by default.

Use namespace-level NetworkPolicy with a default-deny posture before adding application-specific allow rules. Public Services and Ingress objects should have explicit ownership, TLS, source restrictions, and monitoring.

RBAC should be least privilege. Avoid wildcard verbs or resources, avoid broad subjects such as `system:authenticated`, and reserve `cluster-admin` for tightly governed break-glass workflows.
