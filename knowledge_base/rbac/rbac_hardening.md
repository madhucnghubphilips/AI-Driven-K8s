# RBAC Hardening

RBAC findings involving `bind`, `escalate`, and `impersonate` should be reviewed first because they can allow privilege escalation. Secret read access is also sensitive because Kubernetes Secrets often contain credentials for databases, cloud APIs, and service accounts.

Prefer namespace-scoped Roles over ClusterRoles when the workflow does not need cluster-wide access. Bind permissions to service accounts owned by a specific application team.
