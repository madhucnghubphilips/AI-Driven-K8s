from __future__ import annotations

import csv
import html as html_lib
import io
import json
import os
import re
import subprocess
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

import pandas as pd
import requests
import streamlit as st
import yaml


ROOT_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = ROOT_DIR / "uploads"
LOG_DIR = ROOT_DIR / "logs"
REPORT_DIR = ROOT_DIR / "reports"
VECTOR_DIR = ROOT_DIR / "vector_store"
KNOWLEDGE_DIR = ROOT_DIR / "knowledge_base"
RULE_DIR = ROOT_DIR / "app" / "rules"

SEVERITY_ORDER = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Info": 1,
}

SEVERITY_COLORS = {
    "Critical": "#b91c1c",
    "High": "#dc2626",
    "Medium": "#d97706",
    "Low": "#2563eb",
    "Info": "#64748b",
}

DANGEROUS_CAPABILITIES = {
    "ALL",
    "SYS_ADMIN",
    "NET_ADMIN",
    "SYS_MODULE",
    "SYS_PTRACE",
    "DAC_READ_SEARCH",
    "DAC_OVERRIDE",
}

SENSITIVE_KEYWORDS = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "access_key",
    "private_key",
    "client_secret",
    "connection_string",
)


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    file: str
    object_ref: str
    message: str
    recommendation: str
    evidence: str = ""

    def to_row(self) -> dict[str, str]:
        return asdict(self)


def ensure_project_dirs() -> None:
    for path in [
        UPLOAD_DIR,
        LOG_DIR,
        REPORT_DIR / "csv",
        REPORT_DIR / "html",
        REPORT_DIR / "pdf",
        VECTOR_DIR,
        KNOWLEDGE_DIR,
        RULE_DIR,
    ]:
        path.mkdir(parents=True, exist_ok=True)


def inject_css() -> None:
    st.markdown(
        """
        <style>
        :root {
            --ks-bg: #eef4fb;
            --ks-ink: #0b1b34;
            --ks-muted: #5c6d85;
            --ks-line: #d8e4f2;
            --ks-blue: #2454ff;
            --ks-cyan: #00c8bc;
        }
        .stApp {
            background:
                linear-gradient(rgba(211, 222, 238, .55) 1px, transparent 1px),
                linear-gradient(90deg, rgba(211, 222, 238, .55) 1px, transparent 1px),
                var(--ks-bg);
            background-size: 40px 40px;
            color: var(--ks-ink);
        }
        [data-testid="stSidebar"] {
            background: #0b1729;
            color: white;
        }
        [data-testid="stSidebar"] label,
        [data-testid="stSidebar"] p,
        [data-testid="stSidebar"] span {
            color: #dbeafe;
        }
        .ks-topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 18px;
            background: #0b1729;
            color: white;
            padding: 14px 20px;
            margin: -4rem -4rem 24px -4rem;
            border-bottom: 1px solid rgba(255,255,255,.08);
            box-shadow: 0 12px 30px rgba(15, 23, 42, .18);
        }
        .ks-brand {
            display: flex;
            align-items: center;
            gap: 12px;
            font-weight: 800;
            letter-spacing: 0;
        }
        .ks-logo {
            width: 34px;
            height: 34px;
            border-radius: 8px;
            display: grid;
            place-items: center;
            color: #042f2e;
            background: linear-gradient(145deg, #15dfca, #08aeb3);
            font-weight: 900;
        }
        .ks-subbrand {
            color: #93a4ba;
            font-size: 12px;
            font-weight: 500;
            margin-left: 4px;
        }
        .ks-hero {
            max-width: 840px;
            margin: 0 auto 28px auto;
            padding: 40px 32px;
            border-radius: 10px;
            background: linear-gradient(135deg, #0d2038, #174866);
            color: white;
            text-align: center;
            box-shadow: 0 24px 70px rgba(11, 27, 52, .24);
        }
        .ks-hero h1 {
            margin: 0;
            font-size: 32px;
            line-height: 1.15;
            letter-spacing: 0;
        }
        .ks-hero p {
            color: #d3e5f7;
            max-width: 700px;
            margin: 14px auto 22px auto;
            line-height: 1.7;
        }
        .ks-pill-row {
            display: flex;
            justify-content: center;
            flex-wrap: wrap;
            gap: 10px;
        }
        .ks-pill {
            border: 1px solid rgba(255,255,255,.22);
            background: rgba(255,255,255,.09);
            color: #eaf5ff;
            border-radius: 999px;
            padding: 7px 14px;
            font-size: 13px;
            font-weight: 700;
        }
        .ks-panel {
            border: 2px solid #3578ff;
            background: rgba(244, 248, 255, .94);
            border-radius: 10px;
            padding: 24px;
            box-shadow: 0 20px 60px rgba(22, 59, 128, .08);
        }
        .ks-section-title {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 8px;
        }
        .ks-icon {
            width: 42px;
            height: 42px;
            border-radius: 8px;
            background: #c9f6ed;
            display: grid;
            place-items: center;
            color: #0f766e;
            font-weight: 900;
        }
        .ks-badge {
            display: inline-flex;
            align-items: center;
            border-radius: 999px;
            border: 1px solid #9ec5ff;
            background: #dbeafe;
            color: #1d4ed8;
            padding: 6px 14px;
            font-weight: 800;
            font-size: 13px;
            letter-spacing: .04em;
        }
        .ks-muted {
            color: #5c6d85;
            font-size: 14px;
            margin: 0;
        }
        .ks-divider {
            border-top: 1px solid #d8e4f2;
            margin: 18px 0;
        }
        .ks-finding {
            border: 1px solid #d8e4f2;
            border-left: 6px solid #64748b;
            border-radius: 8px;
            padding: 14px 16px;
            background: white;
            margin-bottom: 10px;
        }
        .ks-finding h4 {
            margin: 0 0 4px 0;
            font-size: 16px;
        }
        .ks-finding p {
            margin: 4px 0;
            color: #334155;
        }
        .ks-small {
            color: #64748b;
            font-size: 12px;
        }
        div[data-testid="stTabs"] button {
            font-weight: 700;
        }
        div[data-testid="stFileUploader"] section {
            border: 2px dashed #3578ff;
            background: rgba(255,255,255,.55);
        }
        div.stButton > button:first-child {
            background: #2454ff;
            color: white;
            border: 0;
            border-radius: 8px;
            font-weight: 800;
        }
        div.stDownloadButton > button:first-child {
            border-radius: 8px;
            font-weight: 800;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_topbar() -> None:
    st.markdown(
        """
        <div class="ks-topbar">
            <div class="ks-brand">
                <div class="ks-logo">S</div>
                <div>KubeSentinel <span class="ks-subbrand">Security Scanner</span></div>
            </div>
            <div class="ks-subbrand">Streamlit Edition</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_hero() -> None:
    st.markdown(
        """
        <div class="ks-hero">
            <h1>KubeSentinel AI</h1>
            <p>Detect misconfigurations, privilege escalation paths, exposed secrets, and Kubernetes security risks in manifests, cluster snapshots, Terraform, Helm charts, and audit logs.</p>
            <div class="ks-pill-row">
                <span class="ks-pill">AI-assisted analysis</span>
                <span class="ks-pill">YAML scanning</span>
                <span class="ks-pill">Live cluster support</span>
                <span class="ks-pill">RBAC and secrets checks</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_panel_header(code: str, label: str, title: str, help_text: str) -> None:
    st.markdown(
        f"""
        <div class="ks-section-title">
            <div class="ks-icon">{html_lib.escape(code)}</div>
            <div>
                <span class="ks-badge">{html_lib.escape(label)}</span>
                <h3 style="margin:8px 0 2px 0;">{html_lib.escape(title)}</h3>
                <p class="ks-muted">{html_lib.escape(help_text)}</p>
            </div>
        </div>
        <div class="ks-divider"></div>
        """,
        unsafe_allow_html=True,
    )


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def save_upload(file_name: str, data: bytes) -> Path:
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", file_name).strip("._") or "upload.txt"
    target = UPLOAD_DIR / f"{now_stamp()}_{safe_name}"
    target.write_bytes(data)
    return target


def decode_bytes(data: bytes) -> str:
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def parse_yaml_documents(text: str) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    try:
        for item in yaml.safe_load_all(text):
            if isinstance(item, dict):
                items = item.get("items")
                if isinstance(items, list) and str(item.get("kind") or "").endswith("List"):
                    docs.extend([entry for entry in items if isinstance(entry, dict)])
                else:
                    docs.append(item)
            elif isinstance(item, list):
                docs.extend([entry for entry in item if isinstance(entry, dict)])
    except yaml.YAMLError as exc:
        raise ValueError(f"YAML parser error: {exc}") from exc
    return docs


def object_ref(doc: dict[str, Any]) -> str:
    kind = str(doc.get("kind") or "Object")
    metadata = doc.get("metadata") or {}
    name = metadata.get("name") or "<unnamed>"
    namespace = metadata.get("namespace")
    return f"{kind}/{name}" if not namespace else f"{kind}/{namespace}/{name}"


def pod_specs_for(doc: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    kind = str(doc.get("kind") or "")
    if kind == "Pod":
        return [(object_ref(doc), doc.get("spec") or {})]

    workload_kinds = {
        "Deployment",
        "StatefulSet",
        "DaemonSet",
        "ReplicaSet",
        "ReplicationController",
        "Job",
    }
    if kind in workload_kinds:
        spec = (((doc.get("spec") or {}).get("template") or {}).get("spec") or {})
        return [(object_ref(doc), spec)]
    if kind == "CronJob":
        template = (
            (((doc.get("spec") or {}).get("jobTemplate") or {}).get("spec") or {}).get("template")
            or {}
        )
        return [(object_ref(doc), template.get("spec") or {})]
    return []


def all_containers(pod_spec: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    containers: list[tuple[str, dict[str, Any]]] = []
    for key in ("initContainers", "containers", "ephemeralContainers"):
        for container in pod_spec.get(key) or []:
            if isinstance(container, dict):
                containers.append((key, container))
    return containers


def add_finding(
    findings: list[Finding],
    rule_id: str,
    title: str,
    severity: str,
    category: str,
    file_name: str,
    obj: str,
    message: str,
    recommendation: str,
    evidence: str = "",
) -> None:
    findings.append(
        Finding(
            rule_id=rule_id,
            title=title,
            severity=severity,
            category=category,
            file=file_name,
            object_ref=obj,
            message=message,
            recommendation=recommendation,
            evidence=evidence,
        )
    )


def get_namespace(doc: dict[str, Any]) -> str:
    metadata = doc.get("metadata") or {}
    return str(metadata.get("namespace") or "default")


def image_without_safe_tag(image: str) -> bool:
    image = image.strip()
    if not image:
        return True
    if "@sha256:" in image:
        return False
    last_segment = image.rsplit("/", 1)[-1]
    if ":" not in last_segment:
        return True
    return last_segment.lower().endswith(":latest")


def has_sensitive_name(name: str) -> bool:
    lowered = name.lower()
    return any(keyword in lowered for keyword in SENSITIVE_KEYWORDS)


def scan_pod_security(doc: dict[str, Any], file_name: str, findings: list[Finding]) -> None:
    for obj, pod_spec in pod_specs_for(doc):
        pod_security_context = pod_spec.get("securityContext") or {}

        for field in ("hostNetwork", "hostPID", "hostIPC"):
            if pod_spec.get(field) is True:
                add_finding(
                    findings,
                    f"K8S-POD-{field.upper()}",
                    f"{field} is enabled",
                    "High",
                    "Pod security",
                    file_name,
                    obj,
                    f"{field} allows a workload to share host-level namespaces.",
                    f"Set spec.{field} to false unless there is a documented exception.",
                    f"spec.{field}: true",
                )

        if pod_spec.get("automountServiceAccountToken") is not False:
            add_finding(
                findings,
                "K8S-POD-SA-TOKEN",
                "Service account token is auto-mounted",
                "Medium",
                "Identity",
                file_name,
                obj,
                "Pods can receive API credentials automatically unless this is disabled.",
                "Set automountServiceAccountToken: false for workloads that do not call the Kubernetes API.",
            )

        for volume in pod_spec.get("volumes") or []:
            if not isinstance(volume, dict):
                continue
            if volume.get("hostPath"):
                add_finding(
                    findings,
                    "K8S-POD-HOSTPATH",
                    "hostPath volume is mounted",
                    "High",
                    "Host security",
                    file_name,
                    obj,
                    "hostPath can expose host filesystems to the workload.",
                    "Avoid hostPath. If unavoidable, mount the narrowest path as read-only and add admission controls.",
                    f"volume: {volume.get('name', '<unnamed>')}",
                )

        for container_group, container in all_containers(pod_spec):
            name = container.get("name") or "<unnamed>"
            prefix = f"{obj} container/{name}"
            image = str(container.get("image") or "")
            security_context = container.get("securityContext") or {}

            if image_without_safe_tag(image):
                add_finding(
                    findings,
                    "K8S-IMG-TAG",
                    "Container image is not pinned",
                    "Medium",
                    "Image security",
                    file_name,
                    prefix,
                    "The image tag is missing, mutable, or uses latest.",
                    "Pin images to an immutable version or digest and scan them before deployment.",
                    f"image: {image or '<missing>'}",
                )

            if security_context.get("privileged") is True:
                add_finding(
                    findings,
                    "K8S-CTR-PRIVILEGED",
                    "Privileged container",
                    "Critical",
                    "Pod security",
                    file_name,
                    prefix,
                    "Privileged containers can bypass normal container isolation.",
                    "Set securityContext.privileged to false and replace privileged access with specific capabilities.",
                    "securityContext.privileged: true",
                )

            if security_context.get("allowPrivilegeEscalation") is not False:
                add_finding(
                    findings,
                    "K8S-CTR-PRIV-ESC",
                    "Privilege escalation is not disabled",
                    "High",
                    "Pod security",
                    file_name,
                    prefix,
                    "The container may be able to gain more privileges through setuid binaries or similar paths.",
                    "Set securityContext.allowPrivilegeEscalation: false.",
                )

            container_non_root = security_context.get("runAsNonRoot")
            pod_non_root = pod_security_context.get("runAsNonRoot")
            if container_non_root is not True and pod_non_root is not True:
                add_finding(
                    findings,
                    "K8S-CTR-RUN-AS-NON-ROOT",
                    "Container is not forced to run as non-root",
                    "Medium",
                    "Pod security",
                    file_name,
                    prefix,
                    "The manifest does not require a non-root user.",
                    "Set runAsNonRoot: true and use a numeric non-root runAsUser.",
                )

            capabilities = security_context.get("capabilities") or {}
            added_caps = {str(item).upper() for item in capabilities.get("add") or []}
            dangerous_caps = sorted(added_caps.intersection(DANGEROUS_CAPABILITIES))
            if dangerous_caps:
                add_finding(
                    findings,
                    "K8S-CTR-CAP-ADD",
                    "Dangerous Linux capability is added",
                    "High",
                    "Container security",
                    file_name,
                    prefix,
                    "The container adds capabilities that can weaken isolation.",
                    "Drop all capabilities by default and add only the minimum capability required.",
                    f"added capabilities: {', '.join(dangerous_caps)}",
                )

            dropped_caps = {str(item).upper() for item in capabilities.get("drop") or []}
            if "ALL" not in dropped_caps:
                add_finding(
                    findings,
                    "K8S-CTR-CAP-DROP",
                    "Container does not drop all capabilities",
                    "Low",
                    "Container security",
                    file_name,
                    prefix,
                    "Default Linux capabilities remain available.",
                    "Set securityContext.capabilities.drop: ['ALL'] and add back only required capabilities.",
                )

            resources = container.get("resources") or {}
            if not resources.get("requests") or not resources.get("limits"):
                add_finding(
                    findings,
                    "K8S-CTR-RESOURCES",
                    "CPU or memory requests and limits are incomplete",
                    "Medium",
                    "Reliability",
                    file_name,
                    prefix,
                    "Missing requests or limits can create noisy-neighbor risk and denial-of-service exposure.",
                    "Set CPU and memory requests and limits for every container.",
                )

            if not container.get("livenessProbe") or not container.get("readinessProbe"):
                add_finding(
                    findings,
                    "K8S-CTR-PROBES",
                    "Health probes are incomplete",
                    "Low",
                    "Reliability",
                    file_name,
                    prefix,
                    "Missing probes reduce Kubernetes' ability to detect and isolate unhealthy workloads.",
                    "Add livenessProbe and readinessProbe with application-specific checks.",
                )

            for env_var in container.get("env") or []:
                if not isinstance(env_var, dict):
                    continue
                env_name = str(env_var.get("name") or "")
                if has_sensitive_name(env_name) and "value" in env_var:
                    add_finding(
                        findings,
                        "K8S-SECRET-ENV",
                        "Sensitive value is set directly in environment",
                        "High",
                        "Secrets management",
                        file_name,
                        prefix,
                        "A likely secret is embedded in the manifest as plain text.",
                        "Move the value to a Kubernetes Secret or external secret manager and reference it securely.",
                        f"env: {env_name}",
                    )

            if container_group == "ephemeralContainers":
                add_finding(
                    findings,
                    "K8S-EPHEMERAL-CONTAINER",
                    "Ephemeral container is defined",
                    "Info",
                    "Runtime access",
                    file_name,
                    prefix,
                    "Ephemeral containers are useful for debugging but should be controlled in production.",
                    "Restrict ephemeral container creation with RBAC and admission policy.",
                )


def scan_rbac(doc: dict[str, Any], file_name: str, findings: list[Finding]) -> None:
    kind = str(doc.get("kind") or "")
    obj = object_ref(doc)
    if kind in {"Role", "ClusterRole"}:
        for idx, rule in enumerate(doc.get("rules") or [], start=1):
            if not isinstance(rule, dict):
                continue
            verbs = {str(item).lower() for item in rule.get("verbs") or []}
            resources = {str(item).lower() for item in rule.get("resources") or []}
            api_groups = {str(item).lower() for item in rule.get("apiGroups") or []}
            if "*" in verbs or "*" in resources:
                add_finding(
                    findings,
                    "K8S-RBAC-WILDCARD",
                    "RBAC rule uses wildcard access",
                    "High",
                    "RBAC",
                    file_name,
                    obj,
                    "Wildcard verbs or resources can grant broad permissions beyond the intended scope.",
                    "Replace wildcards with the exact verbs, API groups, and resources required.",
                    f"rule {idx}: verbs={sorted(verbs)} resources={sorted(resources)} apiGroups={sorted(api_groups)}",
                )
            dangerous_verbs = verbs.intersection({"escalate", "bind", "impersonate"})
            if dangerous_verbs:
                add_finding(
                    findings,
                    "K8S-RBAC-ESCALATE",
                    "RBAC rule can escalate privileges",
                    "Critical",
                    "RBAC",
                    file_name,
                    obj,
                    "The rule grants verbs that can be abused to gain or assign stronger identities.",
                    "Remove escalate, bind, and impersonate unless the subject is a tightly controlled admin workflow.",
                    f"rule {idx}: {', '.join(sorted(dangerous_verbs))}",
                )
            if "secrets" in resources and {"get", "list", "watch"}.intersection(verbs):
                add_finding(
                    findings,
                    "K8S-RBAC-SECRETS-READ",
                    "RBAC grants secret read access",
                    "High",
                    "Secrets management",
                    file_name,
                    obj,
                    "Reading Kubernetes Secrets can expose credentials for the namespace or cluster.",
                    "Grant secret read access only to identities that absolutely require it.",
                    f"rule {idx}: verbs={sorted(verbs)}",
                )

    if kind in {"RoleBinding", "ClusterRoleBinding"}:
        role_ref = doc.get("roleRef") or {}
        role_name = str(role_ref.get("name") or "")
        if role_name == "cluster-admin":
            add_finding(
                findings,
                "K8S-RBAC-CLUSTER-ADMIN",
                "Binding grants cluster-admin",
                "Critical",
                "RBAC",
                file_name,
                obj,
                "The binding grants full cluster control.",
                "Avoid cluster-admin bindings. Create least-privilege roles scoped to the namespace and workflow.",
                "roleRef.name: cluster-admin",
            )
        for subject in doc.get("subjects") or []:
            if not isinstance(subject, dict):
                continue
            name = str(subject.get("name") or "")
            if name in {"system:anonymous", "system:unauthenticated", "system:authenticated"}:
                add_finding(
                    findings,
                    "K8S-RBAC-BROAD-SUBJECT",
                    "RBAC binding targets a broad system subject",
                    "Critical",
                    "RBAC",
                    file_name,
                    obj,
                    "The binding applies to anonymous, unauthenticated, or all authenticated users.",
                    "Bind roles to specific service accounts, users, or tightly governed groups.",
                    f"subject: {name}",
                )


def scan_services_and_ingress(doc: dict[str, Any], file_name: str, findings: list[Finding]) -> None:
    kind = str(doc.get("kind") or "")
    obj = object_ref(doc)
    spec = doc.get("spec") or {}

    if kind == "Service":
        svc_type = str(spec.get("type") or "ClusterIP")
        if svc_type in {"LoadBalancer", "NodePort"}:
            add_finding(
                findings,
                "K8S-SVC-EXPOSED",
                f"Service uses {svc_type}",
                "Medium",
                "Networking",
                file_name,
                obj,
                "The service may expose workloads outside the cluster boundary.",
                "Confirm exposure is intentional and restrict source ranges, firewall rules, and authentication.",
                f"spec.type: {svc_type}",
            )
        if spec.get("externalIPs"):
            add_finding(
                findings,
                "K8S-SVC-EXTERNAL-IP",
                "Service defines externalIPs",
                "High",
                "Networking",
                file_name,
                obj,
                "externalIPs can route external traffic directly to services and are easy to overlook.",
                "Avoid externalIPs unless controlled by policy and network governance.",
                f"externalIPs: {spec.get('externalIPs')}",
            )

    if kind == "Ingress":
        if not spec.get("tls"):
            add_finding(
                findings,
                "K8S-INGRESS-NO-TLS",
                "Ingress does not define TLS",
                "Medium",
                "Networking",
                file_name,
                obj,
                "Ingress traffic can be exposed without transport encryption.",
                "Configure TLS with a managed certificate and redirect HTTP to HTTPS.",
            )


def scan_secrets(doc: dict[str, Any], file_name: str, findings: list[Finding]) -> None:
    if str(doc.get("kind") or "") != "Secret":
        return
    obj = object_ref(doc)
    if doc.get("stringData"):
        add_finding(
            findings,
            "K8S-SECRET-STRINGDATA",
            "Secret uses stringData",
            "Medium",
            "Secrets management",
            file_name,
            obj,
            "stringData stores secret values in plain text in source files before the API server encodes them.",
            "Keep secret material out of manifests and use an external secrets workflow.",
        )
    for key in list((doc.get("data") or {}).keys()) + list((doc.get("stringData") or {}).keys()):
        if has_sensitive_name(str(key)):
            add_finding(
                findings,
                "K8S-SECRET-SENSITIVE-KEY",
                "Secret contains sensitive credential key",
                "Info",
                "Secrets management",
                file_name,
                obj,
                "The Secret contains a key that appears to hold credential material.",
                "Verify rotation, encryption at rest, access controls, and external secret ownership.",
                f"key: {key}",
            )


def scan_namespace_policy_gap(
    manifests: list[tuple[str, dict[str, Any]]], findings: list[Finding]
) -> None:
    workload_kinds = {
        "Pod",
        "Deployment",
        "StatefulSet",
        "DaemonSet",
        "ReplicaSet",
        "ReplicationController",
        "Job",
        "CronJob",
    }
    workload_namespaces: set[str] = set()
    policy_namespaces: set[str] = set()

    for _, doc in manifests:
        kind = str(doc.get("kind") or "")
        if kind in workload_kinds:
            workload_namespaces.add(get_namespace(doc))
        if kind == "NetworkPolicy":
            policy_namespaces.add(get_namespace(doc))

    for namespace in sorted(workload_namespaces - policy_namespaces):
        add_finding(
            findings,
            "K8S-NETPOL-MISSING",
            "Namespace has workloads but no NetworkPolicy",
            "Medium",
            "Networking",
            "manifest set",
            f"Namespace/{namespace}",
            "No NetworkPolicy object was found for a namespace that contains workloads.",
            "Add default-deny ingress and egress policies, then allow required application traffic.",
        )


def scan_kubernetes_manifest_files(files: list[tuple[str, str]]) -> list[Finding]:
    findings: list[Finding] = []
    manifests: list[tuple[str, dict[str, Any]]] = []

    for file_name, text in files:
        try:
            docs = parse_yaml_documents(text)
        except ValueError as exc:
            add_finding(
                findings,
                "K8S-YAML-PARSE",
                "YAML parse failed",
                "High",
                "Parser",
                file_name,
                file_name,
                str(exc),
                "Fix the YAML syntax and run the scan again.",
            )
            continue

        for doc in docs:
            manifests.append((file_name, doc))
            scan_pod_security(doc, file_name, findings)
            scan_rbac(doc, file_name, findings)
            scan_services_and_ingress(doc, file_name, findings)
            scan_secrets(doc, file_name, findings)

    scan_namespace_policy_gap(manifests, findings)
    return sort_findings(findings)


def scan_terraform_files(files: list[tuple[str, str]]) -> list[Finding]:
    findings: list[Finding] = []
    for file_name, text in files:
        lowered = text.lower()
        if re.search(r'resource\s+"aws_eks_cluster"', text):
            if "endpoint_public_access = true" in lowered:
                add_finding(
                    findings,
                    "TF-EKS-PUBLIC-ENDPOINT",
                    "EKS API endpoint is public",
                    "High",
                    "EKS",
                    file_name,
                    "aws_eks_cluster",
                    "The EKS control plane endpoint is publicly reachable.",
                    "Set endpoint_private_access = true and restrict endpoint_public_access or public_access_cidrs.",
                )
            if "public_access_cidrs" not in lowered or "0.0.0.0/0" in lowered:
                add_finding(
                    findings,
                    "TF-EKS-PUBLIC-CIDR",
                    "EKS public access CIDR is broad",
                    "High",
                    "EKS",
                    file_name,
                    "aws_eks_cluster",
                    "The public endpoint appears to allow broad source ranges.",
                    "Restrict public_access_cidrs to known administrator IP ranges or disable public access.",
                )
            if "enabled_cluster_log_types" not in lowered:
                add_finding(
                    findings,
                    "TF-EKS-LOGGING",
                    "EKS control plane logging is not configured",
                    "Medium",
                    "Control plane",
                    file_name,
                    "aws_eks_cluster",
                    "Control plane audit, API, authenticator, controller manager, and scheduler logs improve detection and investigations.",
                    "Enable EKS control plane log types and retain them in CloudWatch or a SIEM.",
                )
            if "encryption_config" not in lowered:
                add_finding(
                    findings,
                    "TF-EKS-SECRETS-ENCRYPTION",
                    "EKS secrets encryption is not configured",
                    "High",
                    "Secrets management",
                    file_name,
                    "aws_eks_cluster",
                    "Kubernetes secrets may not be encrypted with a customer-managed KMS key.",
                    "Configure encryption_config with a KMS key for Kubernetes secrets.",
                )

        for match in re.finditer(r'resource\s+"aws_iam_policy"[\s\S]+?policy\s*=\s*(?:jsonencode\()?([\s\S]+?)(?:\n\})', text):
            policy_block = match.group(1)
            if '"Action": "*"' in policy_block or '"Resource": "*"' in policy_block or "actions = [\"*\"]" in policy_block.lower():
                add_finding(
                    findings,
                    "TF-IAM-WILDCARD",
                    "IAM policy uses wildcard access",
                    "High",
                    "IAM",
                    file_name,
                    "aws_iam_policy",
                    "Wildcard IAM actions or resources can create unnecessary cloud privilege.",
                    "Scope IAM actions and resources to the minimum required permissions.",
                )

        if re.search(r'resource\s+"kubernetes_secret"', text):
            add_finding(
                findings,
                "TF-K8S-SECRET",
                "Terraform manages a Kubernetes Secret",
                "Medium",
                "Secrets management",
                file_name,
                "kubernetes_secret",
                "Terraform state can retain secret values and spread them to backends or plans.",
                "Prefer external secret managers and ensure Terraform state encryption and access controls.",
            )

        if "skip_final_snapshot = true" in lowered:
            add_finding(
                findings,
                "TF-DATA-LOSS-RISK",
                "Final snapshot is skipped",
                "Low",
                "Resilience",
                file_name,
                "terraform",
                "Skipping final snapshots can remove recovery options during deletion.",
                "Use final snapshots for production stateful services unless deletion is intentionally ephemeral.",
            )

    return sort_findings(findings)


def scan_helm_files(files: list[tuple[str, str]]) -> list[Finding]:
    findings: list[Finding] = []
    manifest_like: list[tuple[str, str]] = []
    for file_name, text in files:
        lower_name = file_name.lower()
        if lower_name.endswith((".yaml", ".yml", ".tpl")):
            if "{{" not in text and "}}" not in text:
                manifest_like.append((file_name, text))
            if re.search(r"tag\s*:\s*latest\b", text, flags=re.IGNORECASE):
                add_finding(
                    findings,
                    "HELM-IMG-LATEST",
                    "Helm values use latest image tag",
                    "Medium",
                    "Image security",
                    file_name,
                    "values",
                    "A chart value pins an image to latest or another mutable reference.",
                    "Use versioned image tags or digests and keep chart defaults production-safe.",
                )
            if re.search(r"service\s*:\s*[\s\S]{0,200}type\s*:\s*(LoadBalancer|NodePort)", text, flags=re.IGNORECASE):
                add_finding(
                    findings,
                    "HELM-SVC-EXPOSED",
                    "Helm values expose a service",
                    "Medium",
                    "Networking",
                    file_name,
                    "values",
                    "A chart value may create a LoadBalancer or NodePort service.",
                    "Default to ClusterIP and require explicit environment approval for public exposure.",
                )
            if re.search(r"(password|token|secret|clientSecret)\s*:\s*['\"]?[^'\"\n{}]+", text, flags=re.IGNORECASE):
                add_finding(
                    findings,
                    "HELM-SECRET-IN-VALUES",
                    "Possible secret in Helm values",
                    "High",
                    "Secrets management",
                    file_name,
                    "values",
                    "A sensitive value appears to be set directly in chart values.",
                    "Move secrets to an external secret manager or a sealed secret workflow.",
                )

        if lower_name.endswith("chart.yaml") and "appversion:" not in text.lower():
            add_finding(
                findings,
                "HELM-CHART-APPVERSION",
                "Chart does not define appVersion",
                "Info",
                "Helm metadata",
                file_name,
                "Chart.yaml",
                "appVersion helps track application release intent across chart versions.",
                "Set appVersion to the application version shipped by the chart.",
            )

    findings.extend(scan_kubernetes_manifest_files(manifest_like))
    return sort_findings(findings)


def audit_event_name(event: dict[str, Any]) -> str:
    obj = event.get("objectRef") or {}
    resource = obj.get("resource") or "resource"
    namespace = obj.get("namespace")
    name = obj.get("name")
    if namespace and name:
        return f"{resource}/{namespace}/{name}"
    if name:
        return f"{resource}/{name}"
    return str(resource)


def scan_audit_logs(files: list[tuple[str, str]]) -> list[Finding]:
    findings: list[Finding] = []
    for file_name, text in files:
        for line_no, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                event = json.loads(stripped)
            except json.JSONDecodeError:
                lower = stripped.lower()
                if any(term in lower for term in ("system:anonymous", "forbidden", "pods/exec", "impersonate")):
                    add_finding(
                        findings,
                        "AUDIT-TEXT-SIGNAL",
                        "Suspicious audit log text signal",
                        "Medium",
                        "Audit logs",
                        file_name,
                        f"line {line_no}",
                        "A security-sensitive term appears in a non-JSON audit log line.",
                        "Inspect the event context and confirm the actor, verb, resource, and source IP.",
                        stripped[:220],
                    )
                continue

            user = ((event.get("user") or {}).get("username")) or "<unknown>"
            verb = str(event.get("verb") or "").lower()
            obj = event.get("objectRef") or {}
            resource = str(obj.get("resource") or "").lower()
            subresource = str(obj.get("subresource") or "").lower()
            code = ((event.get("responseStatus") or {}).get("code")) or ""
            target = audit_event_name(event)

            if user in {"system:anonymous", "system:unauthenticated"}:
                add_finding(
                    findings,
                    "AUDIT-ANON-ACTOR",
                    "Anonymous actor activity",
                    "Critical",
                    "Audit logs",
                    file_name,
                    target,
                    "An anonymous or unauthenticated user generated an API event.",
                    "Verify API server authentication controls and investigate the source IP immediately.",
                    f"line {line_no}: user={user} verb={verb}",
                )
            if verb in {"escalate", "bind", "impersonate"}:
                add_finding(
                    findings,
                    "AUDIT-PRIV-ESC-VERB",
                    "Privilege escalation verb observed",
                    "Critical",
                    "Audit logs",
                    file_name,
                    target,
                    "A Kubernetes privilege escalation verb was observed in audit logs.",
                    "Confirm whether the actor is authorized for this administrative action.",
                    f"line {line_no}: verb={verb} user={user}",
                )
            if resource == "secrets" and verb in {"get", "list", "watch"}:
                add_finding(
                    findings,
                    "AUDIT-SECRET-READ",
                    "Secret read activity",
                    "High",
                    "Audit logs",
                    file_name,
                    target,
                    "A user or service account read Kubernetes Secret data.",
                    "Validate the actor and compare against expected secret access patterns.",
                    f"line {line_no}: user={user} verb={verb}",
                )
            if resource == "pods" and subresource in {"exec", "attach", "portforward"}:
                add_finding(
                    findings,
                    "AUDIT-POD-REMOTE-ACCESS",
                    "Remote pod access observed",
                    "High",
                    "Audit logs",
                    file_name,
                    target,
                    "The audit log contains exec, attach, or port-forward activity.",
                    "Confirm this was an approved operation and inspect source IP and actor identity.",
                    f"line {line_no}: subresource={subresource} user={user}",
                )
            if str(code) == "403":
                add_finding(
                    findings,
                    "AUDIT-FORBIDDEN",
                    "Forbidden API request",
                    "Low",
                    "Audit logs",
                    file_name,
                    target,
                    "A request was denied by authorization.",
                    "Review repeated denials as possible reconnaissance or broken automation.",
                    f"line {line_no}: user={user} verb={verb} resource={resource}",
                )

    return sort_findings(findings)


def run_kubectl_snapshot() -> tuple[list[tuple[str, str]], list[str]]:
    commands = {
        "pods.yaml": ["kubectl", "get", "pods", "-A", "-o", "yaml"],
        "deployments.yaml": ["kubectl", "get", "deployments,statefulsets,daemonsets,jobs,cronjobs", "-A", "-o", "yaml"],
        "services.yaml": ["kubectl", "get", "services,ingress,networkpolicy", "-A", "-o", "yaml"],
        "rbac.yaml": ["kubectl", "get", "roles,clusterroles,rolebindings,clusterrolebindings", "-A", "-o", "yaml"],
    }
    files: list[tuple[str, str]] = []
    errors: list[str] = []
    for file_name, command in commands.items():
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except FileNotFoundError:
            errors.append("kubectl was not found on PATH.")
            break
        except subprocess.TimeoutExpired:
            errors.append(f"{file_name}: kubectl timed out.")
            continue
        if result.returncode != 0:
            errors.append(f"{file_name}: {result.stderr.strip() or result.stdout.strip()}")
        elif result.stdout.strip():
            files.append((file_name, result.stdout))
    return files, errors


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda item: (
            -SEVERITY_ORDER.get(item.severity, 0),
            item.category,
            item.rule_id,
            item.file,
        ),
    )


def findings_to_dataframe(findings: list[Finding]) -> pd.DataFrame:
    columns = [
        "severity",
        "category",
        "rule_id",
        "title",
        "file",
        "object_ref",
        "message",
        "recommendation",
        "evidence",
    ]
    return pd.DataFrame([finding.to_row() for finding in findings], columns=columns)


def render_metrics(findings: list[Finding]) -> None:
    counts = Counter(finding.severity for finding in findings)
    cols = st.columns(5)
    for idx, severity in enumerate(["Critical", "High", "Medium", "Low", "Info"]):
        cols[idx].metric(severity, counts.get(severity, 0))


def render_finding_cards(findings: list[Finding], max_items: int = 12) -> None:
    if not findings:
        st.success("No findings detected in the current scan scope.")
        return
    for finding in findings[:max_items]:
        color = SEVERITY_COLORS.get(finding.severity, "#64748b")
        st.markdown(
            f"""
            <div class="ks-finding" style="border-left-color:{color};">
                <div class="ks-small">{html_lib.escape(finding.severity)} / {html_lib.escape(finding.category)} / {html_lib.escape(finding.rule_id)}</div>
                <h4>{html_lib.escape(finding.title)}</h4>
                <p><strong>Target:</strong> {html_lib.escape(finding.object_ref)} <span class="ks-small">in {html_lib.escape(finding.file)}</span></p>
                <p>{html_lib.escape(finding.message)}</p>
                <p><strong>Fix:</strong> {html_lib.escape(finding.recommendation)}</p>
                <p class="ks-small">{html_lib.escape(finding.evidence)}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    if len(findings) > max_items:
        st.caption(f"Showing {max_items} of {len(findings)} findings. Use the table and report downloads for the full list.")


def build_html_report(findings: list[Finding], title: str, ai_summary: str = "") -> str:
    rows = []
    for finding in findings:
        color = SEVERITY_COLORS.get(finding.severity, "#64748b")
        rows.append(
            "<tr>"
            f"<td><span style='color:{color};font-weight:700'>{html_lib.escape(finding.severity)}</span></td>"
            f"<td>{html_lib.escape(finding.category)}</td>"
            f"<td>{html_lib.escape(finding.rule_id)}</td>"
            f"<td>{html_lib.escape(finding.title)}</td>"
            f"<td>{html_lib.escape(finding.file)}</td>"
            f"<td>{html_lib.escape(finding.object_ref)}</td>"
            f"<td>{html_lib.escape(finding.recommendation)}</td>"
            "</tr>"
        )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{html_lib.escape(title)}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #0f172a; }}
    h1 {{ margin-bottom: 4px; }}
    .muted {{ color: #64748b; }}
    .summary {{ background: #eef6ff; border: 1px solid #cfe3ff; padding: 16px; border-radius: 8px; margin: 20px 0; }}
    table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
    th, td {{ border: 1px solid #dbe3ef; padding: 8px; vertical-align: top; }}
    th {{ background: #0b1729; color: white; text-align: left; }}
  </style>
</head>
<body>
  <h1>{html_lib.escape(title)}</h1>
  <div class="muted">Generated {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
  <div class="summary"><strong>Summary</strong><br>{html_lib.escape(ai_summary or deterministic_summary(findings))}</div>
  <table>
    <thead>
      <tr>
        <th>Severity</th><th>Category</th><th>Rule</th><th>Title</th><th>File</th><th>Target</th><th>Recommendation</th>
      </tr>
    </thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</body>
</html>
"""


def build_pdf_report(findings: list[Finding], title: str, ai_summary: str = "") -> bytes | None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except Exception:
        return None

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=28, rightMargin=28, topMargin=28, bottomMargin=28)
    styles = getSampleStyleSheet()
    story: list[Any] = [
        Paragraph(title, styles["Title"]),
        Paragraph(datetime.now().strftime("Generated %Y-%m-%d %H:%M:%S"), styles["Normal"]),
        Spacer(1, 10),
        Paragraph(ai_summary or deterministic_summary(findings), styles["BodyText"]),
        Spacer(1, 14),
    ]

    table_data = [["Severity", "Rule", "Title", "Target"]]
    for finding in findings[:80]:
        table_data.append(
            [
                finding.severity,
                finding.rule_id,
                finding.title,
                finding.object_ref,
            ]
        )
    table = Table(table_data, colWidths=[58, 92, 170, 190], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b1729")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(table)
    doc.build(story)
    return buffer.getvalue()


def save_reports(findings: list[Finding], title: str, ai_summary: str = "") -> dict[str, Path]:
    stamp = now_stamp()
    paths: dict[str, Path] = {}
    df = findings_to_dataframe(findings)

    csv_path = REPORT_DIR / "csv" / f"kubesentinel_{stamp}.csv"
    df.to_csv(csv_path, index=False, quoting=csv.QUOTE_MINIMAL)
    paths["csv"] = csv_path

    html_path = REPORT_DIR / "html" / f"kubesentinel_{stamp}.html"
    html_path.write_text(build_html_report(findings, title, ai_summary), encoding="utf-8")
    paths["html"] = html_path

    pdf_bytes = build_pdf_report(findings, title, ai_summary)
    if pdf_bytes:
        pdf_path = REPORT_DIR / "pdf" / f"kubesentinel_{stamp}.pdf"
        pdf_path.write_bytes(pdf_bytes)
        paths["pdf"] = pdf_path

    log_path = LOG_DIR / f"scan_{stamp}.json"
    log_path.write_text(json.dumps([finding.to_row() for finding in findings], indent=2), encoding="utf-8")
    paths["log"] = log_path
    return paths


def load_knowledge_chunks() -> list[dict[str, str]]:
    metadata_path = VECTOR_DIR / "metadata.json"
    if metadata_path.exists():
        try:
            payload = json.loads(metadata_path.read_text(encoding="utf-8"))
            if isinstance(payload, list):
                return [item for item in payload if isinstance(item, dict)]
            if isinstance(payload, dict) and isinstance(payload.get("chunks"), list):
                return [item for item in payload["chunks"] if isinstance(item, dict)]
        except json.JSONDecodeError:
            pass

    chunks: list[dict[str, str]] = []
    for path in KNOWLEDGE_DIR.rglob("*.md"):
        text = path.read_text(encoding="utf-8", errors="replace")
        chunks.append({"source": str(path.relative_to(ROOT_DIR)), "text": text[:3000]})
    return chunks


def retrieve_context(findings: list[Finding], limit: int = 4) -> str:
    chunks = load_knowledge_chunks()
    if not chunks:
        return ""

    query_words = set()
    for finding in findings[:15]:
        query_words.update(re.findall(r"[a-zA-Z]{4,}", f"{finding.category} {finding.title} {finding.message}".lower()))
    if not query_words:
        return ""

    scored: list[tuple[int, dict[str, str]]] = []
    for chunk in chunks:
        text = str(chunk.get("text") or "")
        words = set(re.findall(r"[a-zA-Z]{4,}", text.lower()))
        score = len(query_words.intersection(words))
        if score:
            scored.append((score, chunk))

    scored.sort(key=lambda item: item[0], reverse=True)
    selected = []
    for _, chunk in scored[:limit]:
        source = chunk.get("source") or "knowledge_base"
        text = re.sub(r"\s+", " ", str(chunk.get("text") or "")).strip()
        selected.append(f"Source: {source}\n{text[:900]}")
    return "\n\n".join(selected)


def deterministic_summary(findings: list[Finding]) -> str:
    if not findings:
        return "No findings were detected in the scanned files."
    counts = Counter(finding.severity for finding in findings)
    categories = Counter(finding.category for finding in findings)
    top_categories = ", ".join(f"{name} ({count})" for name, count in categories.most_common(4))
    priority = next((finding for finding in findings if finding.severity in {"Critical", "High"}), findings[0])
    return (
        f"The scan produced {len(findings)} findings: "
        f"{counts.get('Critical', 0)} critical, {counts.get('High', 0)} high, "
        f"{counts.get('Medium', 0)} medium, {counts.get('Low', 0)} low, and {counts.get('Info', 0)} informational. "
        f"Most activity is in {top_categories}. Start with {priority.rule_id}: {priority.title}."
    )


def generate_ai_summary(findings: list[Finding], ollama_url: str, model: str, enabled: bool) -> str:
    fallback = deterministic_summary(findings)
    if not enabled or not findings:
        return fallback

    context = retrieve_context(findings)
    compact_findings = [
        {
            "severity": finding.severity,
            "category": finding.category,
            "rule": finding.rule_id,
            "title": finding.title,
            "target": finding.object_ref,
            "recommendation": finding.recommendation,
        }
        for finding in findings[:25]
    ]
    prompt = f"""You are KubeSentinel AI, a Kubernetes security analyst.
Create a concise executive summary and prioritized remediation plan.
Use the knowledge context when helpful. Do not invent cluster facts.

Findings:
{json.dumps(compact_findings, indent=2)}

Knowledge context:
{context or "No local knowledge context was found."}
"""
    try:
        response = requests.post(
            f"{ollama_url.rstrip('/')}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=45,
        )
        response.raise_for_status()
        payload = response.json()
        return str(payload.get("response") or "").strip() or fallback
    except Exception as exc:
        return f"{fallback}\n\nAI summary was not available from Ollama: {exc}"


def uploaded_files_to_text(uploaded_files: Iterable[Any]) -> list[tuple[str, str]]:
    files: list[tuple[str, str]] = []
    for uploaded in uploaded_files or []:
        data = uploaded.getvalue()
        save_upload(uploaded.name, data)
        files.append((uploaded.name, decode_bytes(data)))
    return files


def apply_filters(findings: list[Finding], severities: list[str], search: str) -> list[Finding]:
    filtered = [finding for finding in findings if finding.severity in severities]
    if search.strip():
        needle = search.strip().lower()
        filtered = [
            finding
            for finding in filtered
            if needle
            in " ".join(
                [
                    finding.rule_id,
                    finding.title,
                    finding.category,
                    finding.file,
                    finding.object_ref,
                    finding.message,
                    finding.recommendation,
                ]
            ).lower()
        ]
    return filtered


def render_results(scope: str, findings: list[Finding], ai_summary: str, auto_save: bool) -> None:
    st.session_state["last_findings"] = findings
    st.session_state["last_scope"] = scope
    st.session_state["last_summary"] = ai_summary

    if auto_save:
        paths = save_reports(findings, f"KubeSentinel {scope} Report", ai_summary)
        st.caption("Saved report files: " + ", ".join(str(path.relative_to(ROOT_DIR)) for path in paths.values()))

    st.markdown("#### Results")
    render_metrics(findings)
    st.markdown("#### AI Summary")
    st.info(ai_summary)

    severities = st.multiselect(
        "Severity filter",
        ["Critical", "High", "Medium", "Low", "Info"],
        default=["Critical", "High", "Medium", "Low", "Info"],
        key=f"{scope}_severity_filter",
    )
    search = st.text_input("Search findings", key=f"{scope}_search")
    filtered = apply_filters(findings, severities, search)
    render_finding_cards(filtered)

    df = findings_to_dataframe(filtered)
    st.dataframe(df, use_container_width=True, hide_index=True)

    csv_bytes = df.to_csv(index=False).encode("utf-8")
    html_report = build_html_report(filtered, f"KubeSentinel {scope} Report", ai_summary)
    pdf_bytes = build_pdf_report(filtered, f"KubeSentinel {scope} Report", ai_summary)

    col1, col2, col3 = st.columns(3)
    col1.download_button(
        "Download CSV",
        data=csv_bytes,
        file_name=f"kubesentinel_{scope.lower().replace(' ', '_')}.csv",
        mime="text/csv",
        use_container_width=True,
    )
    col2.download_button(
        "Download HTML",
        data=html_report.encode("utf-8"),
        file_name=f"kubesentinel_{scope.lower().replace(' ', '_')}.html",
        mime="text/html",
        use_container_width=True,
    )
    if pdf_bytes:
        col3.download_button(
            "Download PDF",
            data=pdf_bytes,
            file_name=f"kubesentinel_{scope.lower().replace(' ', '_')}.pdf",
            mime="application/pdf",
            use_container_width=True,
        )
    else:
        col3.caption("Install reportlab to enable PDF downloads.")


def render_sast_tab(ollama_url: str, model: str, ai_enabled: bool, auto_save: bool) -> None:
    with st.container():
        st.markdown('<div class="ks-panel">', unsafe_allow_html=True)
        render_panel_header("Y", "AI-ENABLED K8S SAST", "Upload Manifests", "Static analysis of Kubernetes YAML manifests from your local machine.")
        uploaded = st.file_uploader(
            "Upload .yaml or .yml files",
            type=["yaml", "yml", "json"],
            accept_multiple_files=True,
            key="sast_upload",
        )
        if st.button("Scan Manifests", use_container_width=True):
            files = uploaded_files_to_text(uploaded)
            if not files:
                st.warning("Upload at least one Kubernetes manifest before scanning.")
            else:
                with st.spinner("Scanning Kubernetes manifests..."):
                    findings = scan_kubernetes_manifest_files(files)
                    summary = generate_ai_summary(findings, ollama_url, model, ai_enabled)
                render_results("K8s SAST", findings, summary, auto_save)
        st.markdown("</div>", unsafe_allow_html=True)


def render_dast_tab(ollama_url: str, model: str, ai_enabled: bool, auto_save: bool) -> None:
    st.markdown('<div class="ks-panel">', unsafe_allow_html=True)
    render_panel_header("D", "K8S DAST", "Live Cluster or Snapshot Scan", "Run read-only kubectl checks or upload cluster snapshots exported as YAML.")
    mode = st.radio("Scan source", ["Upload cluster snapshot", "Run local kubectl snapshot"], horizontal=True)

    if mode == "Upload cluster snapshot":
        uploaded = st.file_uploader(
            "Upload kubectl YAML snapshots",
            type=["yaml", "yml", "json"],
            accept_multiple_files=True,
            key="dast_upload",
        )
        if st.button("Scan Snapshot", use_container_width=True):
            files = uploaded_files_to_text(uploaded)
            if not files:
                st.warning("Upload a snapshot before scanning.")
            else:
                with st.spinner("Scanning cluster snapshot..."):
                    findings = scan_kubernetes_manifest_files(files)
                    summary = generate_ai_summary(findings, ollama_url, model, ai_enabled)
                render_results("K8s DAST", findings, summary, auto_save)
    else:
        st.caption("The live check runs read-only kubectl get commands against your current kubeconfig context.")
        if st.button("Run kubectl Snapshot", use_container_width=True):
            with st.spinner("Collecting read-only cluster data with kubectl..."):
                files, errors = run_kubectl_snapshot()
                for file_name, text in files:
                    save_upload(file_name, text.encode("utf-8"))
                findings = scan_kubernetes_manifest_files(files) if files else []
                summary = generate_ai_summary(findings, ollama_url, model, ai_enabled)
            for error in errors:
                st.warning(error)
            render_results("K8s DAST", findings, summary, auto_save)
    st.markdown("</div>", unsafe_allow_html=True)


def render_terraform_tab(ollama_url: str, model: str, ai_enabled: bool, auto_save: bool) -> None:
    st.markdown('<div class="ks-panel">', unsafe_allow_html=True)
    render_panel_header("T", "TERRAFORM", "Upload Infrastructure Code", "Scan Terraform files for EKS, IAM, and secret-management risks.")
    uploaded = st.file_uploader(
        "Upload .tf or .tfvars files",
        type=["tf", "tfvars", "txt"],
        accept_multiple_files=True,
        key="tf_upload",
    )
    if st.button("Scan Terraform", use_container_width=True):
        files = uploaded_files_to_text(uploaded)
        if not files:
            st.warning("Upload Terraform files before scanning.")
        else:
            with st.spinner("Scanning Terraform..."):
                findings = scan_terraform_files(files)
                summary = generate_ai_summary(findings, ollama_url, model, ai_enabled)
            render_results("Terraform", findings, summary, auto_save)
    st.markdown("</div>", unsafe_allow_html=True)


def render_helm_tab(ollama_url: str, model: str, ai_enabled: bool, auto_save: bool) -> None:
    st.markdown('<div class="ks-panel">', unsafe_allow_html=True)
    render_panel_header("H", "HELM CHARTS", "Upload Chart Files", "Scan Helm templates, Chart.yaml, and values files for risky defaults.")
    uploaded = st.file_uploader(
        "Upload chart YAML, template, or values files",
        type=["yaml", "yml", "tpl", "txt"],
        accept_multiple_files=True,
        key="helm_upload",
    )
    if st.button("Scan Helm Chart", use_container_width=True):
        files = uploaded_files_to_text(uploaded)
        if not files:
            st.warning("Upload Helm chart files before scanning.")
        else:
            with st.spinner("Scanning Helm chart files..."):
                findings = scan_helm_files(files)
                summary = generate_ai_summary(findings, ollama_url, model, ai_enabled)
            render_results("Helm Charts", findings, summary, auto_save)
    st.markdown("</div>", unsafe_allow_html=True)


def render_audit_tab(ollama_url: str, model: str, ai_enabled: bool, auto_save: bool) -> None:
    st.markdown('<div class="ks-panel">', unsafe_allow_html=True)
    render_panel_header("A", "AUDIT LOGS", "Upload Kubernetes Audit Logs", "Detect suspicious API activity from JSONL or text audit logs.")
    uploaded = st.file_uploader(
        "Upload .log, .jsonl, or .txt files",
        type=["log", "jsonl", "json", "txt"],
        accept_multiple_files=True,
        key="audit_upload",
    )
    if st.button("Scan Audit Logs", use_container_width=True):
        files = uploaded_files_to_text(uploaded)
        if not files:
            st.warning("Upload audit logs before scanning.")
        else:
            with st.spinner("Scanning audit logs..."):
                findings = scan_audit_logs(files)
                summary = generate_ai_summary(findings, ollama_url, model, ai_enabled)
            render_results("Audit Logs", findings, summary, auto_save)
    st.markdown("</div>", unsafe_allow_html=True)


def render_knowledge_tab() -> None:
    st.markdown('<div class="ks-panel">', unsafe_allow_html=True)
    render_panel_header("K", "KNOWLEDGE BASE", "RAG Source Documents", "Drop Markdown knowledge files into knowledge_base and ingest them into vector_store.")
    md_files = sorted(KNOWLEDGE_DIR.rglob("*.md"))
    metadata_path = VECTOR_DIR / "metadata.json"
    faiss_path = VECTOR_DIR / "faiss.index"
    col1, col2, col3 = st.columns(3)
    col1.metric("Markdown files", len(md_files))
    col2.metric("metadata.json", "Present" if metadata_path.exists() else "Missing")
    col3.metric("faiss.index", "Present" if faiss_path.exists() else "Optional")

    uploaded_docs = st.file_uploader(
        "Add Markdown knowledge files",
        type=["md"],
        accept_multiple_files=True,
        key="kb_upload",
    )
    if st.button("Save Knowledge Files", use_container_width=True):
        if not uploaded_docs:
            st.warning("Upload one or more Markdown files.")
        else:
            for uploaded in uploaded_docs:
                target = KNOWLEDGE_DIR / re.sub(r"[^A-Za-z0-9._-]+", "_", uploaded.name)
                target.write_bytes(uploaded.getvalue())
            st.success("Knowledge files saved. Run ingest_docs.py to refresh metadata and FAISS index.")

    if md_files:
        st.markdown("#### Available documents")
        for path in md_files[:30]:
            st.caption(str(path.relative_to(ROOT_DIR)))
    st.code("python ingest_docs.py\nstreamlit run streamlit_app.py", language="bash")
    st.markdown("</div>", unsafe_allow_html=True)


def render_reports_tab() -> None:
    st.markdown('<div class="ks-panel">', unsafe_allow_html=True)
    render_panel_header("R", "REPORTS", "Saved Scan Outputs", "Review saved CSV, HTML, PDF, and JSON scan logs.")
    report_files = sorted(REPORT_DIR.rglob("*.*"), key=lambda item: item.stat().st_mtime, reverse=True)
    log_files = sorted(LOG_DIR.rglob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
    col1, col2 = st.columns(2)
    col1.metric("Report files", len(report_files))
    col2.metric("Scan logs", len(log_files))

    if "last_findings" in st.session_state:
        st.markdown("#### Last scan")
        render_metrics(st.session_state["last_findings"])
        st.info(st.session_state.get("last_summary", "No summary available."))

    st.markdown("#### Recent files")
    for path in (report_files + log_files)[:40]:
        rel = path.relative_to(ROOT_DIR)
        st.caption(f"{rel} - {datetime.fromtimestamp(path.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')}")
        st.download_button(
            f"Download {rel.name}",
            data=path.read_bytes(),
            file_name=rel.name,
            mime="application/octet-stream",
            key=f"download_{rel}",
        )
    st.markdown("</div>", unsafe_allow_html=True)


def render_sidebar() -> tuple[str, str, bool, bool]:
    st.sidebar.title("LLM details")
    ai_enabled = st.sidebar.checkbox("Enable Ollama summary", value=False)
    ollama_url = st.sidebar.text_input("Ollama URL", value=os.environ.get("OLLAMA_URL", "http://localhost:11434"))
    model = st.sidebar.text_input("Model", value=os.environ.get("OLLAMA_MODEL", "llama3.1"))
    auto_save = st.sidebar.checkbox("Save reports automatically", value=True)
    st.sidebar.markdown("---")
    st.sidebar.caption("Copy Markdown files into knowledge_base and run ingest_docs.py when the RAG corpus changes.")
    st.sidebar.caption("DAST live mode uses the current kubeconfig context and read-only kubectl commands.")
    return ollama_url, model, ai_enabled, auto_save


def main() -> None:
    ensure_project_dirs()
    st.set_page_config(page_title="KubeSentinel AI", layout="wide")
    inject_css()
    render_topbar()
    ollama_url, model, ai_enabled, auto_save = render_sidebar()
    render_hero()

    tabs = st.tabs(
        [
            "K8s SAST",
            "K8s DAST",
            "Terraform",
            "Helm Charts",
            "Audit Logs",
            "Knowledge Base",
            "Reports",
        ]
    )
    with tabs[0]:
        render_sast_tab(ollama_url, model, ai_enabled, auto_save)
    with tabs[1]:
        render_dast_tab(ollama_url, model, ai_enabled, auto_save)
    with tabs[2]:
        render_terraform_tab(ollama_url, model, ai_enabled, auto_save)
    with tabs[3]:
        render_helm_tab(ollama_url, model, ai_enabled, auto_save)
    with tabs[4]:
        render_audit_tab(ollama_url, model, ai_enabled, auto_save)
    with tabs[5]:
        render_knowledge_tab()
    with tabs[6]:
        render_reports_tab()


if __name__ == "__main__":
    main()
