"""
k8s_hardener.py — Kubernetes Security Audit & Auto-Remediation
Author: securekamal
"""

import json
import yaml
import logging
import argparse
from dataclasses import dataclass, field
from typing import Any, Optional
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class Finding:
    check_id: str
    severity: str
    title: str
    description: str
    resource: str
    namespace: str = "default"
    remediation: str = ""
    cis_ref: str = ""
    mitre_tactic: str = ""


@dataclass
class AuditReport:
    cluster: str
    findings: list[Finding] = field(default_factory=list)

    def summary(self) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def to_text(self) -> str:
        lines = [f"\n{'='*60}", f"  K8S SECURITY AUDIT — {self.cluster}", f"{'='*60}"]
        lines.append(f"\nSummary: {self.summary()}\n")
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(self.findings, key=lambda f: sev_order.get(f.severity, 9))
        for f in sorted_findings:
            lines += [
                f"[{f.severity}] {f.check_id} — {f.title}",
                f"  Resource    : {f.namespace}/{f.resource}",
                f"  Description : {f.description}",
                f"  CIS Ref     : {f.cis_ref}",
                f"  MITRE       : {f.mitre_tactic}",
                f"  Remediation : {f.remediation}",
                "",
            ]
        return "\n".join(lines)

    def to_sarif(self) -> dict:
        rules, results = [], []
        for f in self.findings:
            rules.append({
                "id": f.check_id,
                "shortDescription": {"text": f.title},
                "help": {"text": f.remediation},
                "properties": {"severity": f.severity, "cis": f.cis_ref},
            })
            results.append({
                "ruleId": f.check_id,
                "level": "error" if f.severity in ("CRITICAL", "HIGH") else "warning",
                "message": {"text": f.description},
                "locations": [{"logicalLocations": [{"name": f"{f.namespace}/{f.resource}"}]}],
            })
        return {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "K8sSecurityHardener", "rules": rules}}, "results": results}],
        }


# ─────────────────────────────────────────────
#  MANIFEST SCANNER
# ─────────────────────────────────────────────

class ManifestScanner:
    """Scans Kubernetes YAML manifests for security misconfigurations."""

    def scan(self, manifest: dict, source: str = "manifest") -> list[Finding]:
        findings = []
        kind = manifest.get("kind", "")
        name = manifest.get("metadata", {}).get("name", "unknown")
        namespace = manifest.get("metadata", {}).get("namespace", "default")

        if kind in ("Deployment", "DaemonSet", "StatefulSet", "Pod"):
            findings += self._scan_pod_spec(manifest, name, namespace, source)

        if kind in ("Role", "ClusterRole"):
            findings += self._scan_rbac(manifest, name, namespace)

        if kind == "Service":
            findings += self._scan_service(manifest, name, namespace)

        return findings

    def _scan_pod_spec(self, manifest: dict, name: str, namespace: str, source: str) -> list[Finding]:
        findings = []
        spec = manifest.get("spec", {})
        # Handle nested pod spec in Deployments
        if "template" in spec:
            spec = spec["template"].get("spec", {})

        pod_sec = spec.get("securityContext", {})
        containers = spec.get("containers", []) + spec.get("initContainers", [])

        # Pod-level checks
        if spec.get("hostPID"):
            findings.append(Finding("K8S-001", "CRITICAL", "hostPID enabled",
                "Pod shares host PID namespace — enables container escape", name, namespace,
                "Set hostPID: false", "CIS 5.2.2", "TA0004 Privilege Escalation"))

        if spec.get("hostNetwork"):
            findings.append(Finding("K8S-002", "CRITICAL", "hostNetwork enabled",
                "Pod shares host network — bypasses network policies", name, namespace,
                "Set hostNetwork: false", "CIS 5.2.4", "TA0011 Command and Control"))

        if spec.get("hostIPC"):
            findings.append(Finding("K8S-003", "CRITICAL", "hostIPC enabled",
                "Pod shares host IPC namespace", name, namespace,
                "Set hostIPC: false", "CIS 5.2.3", "TA0004 Privilege Escalation"))

        for container in containers:
            cname = container.get("name", "unknown")
            csec = container.get("securityContext", {})
            resource_id = f"{name}/{cname}"

            if csec.get("privileged"):
                findings.append(Finding("K8S-004", "CRITICAL", "Privileged container",
                    f"Container '{cname}' runs with full host privileges",
                    resource_id, namespace,
                    "Set privileged: false in securityContext", "CIS 5.2.1",
                    "TA0004 Privilege Escalation"))

            if not csec.get("runAsNonRoot") and csec.get("runAsUser", 0) == 0:
                findings.append(Finding("K8S-005", "HIGH", "Container may run as root",
                    f"Container '{cname}' does not enforce non-root execution",
                    resource_id, namespace,
                    "Set runAsNonRoot: true and runAsUser: 1000+", "CIS 5.2.6",
                    "TA0004 Privilege Escalation"))

            if csec.get("allowPrivilegeEscalation", True):
                findings.append(Finding("K8S-006", "HIGH", "Privilege escalation allowed",
                    f"Container '{cname}' allows privilege escalation via setuid",
                    resource_id, namespace,
                    "Set allowPrivilegeEscalation: false", "CIS 5.2.5",
                    "TA0004 Privilege Escalation"))

            if not csec.get("readOnlyRootFilesystem"):
                findings.append(Finding("K8S-007", "MEDIUM", "Writable root filesystem",
                    f"Container '{cname}' has writable root filesystem",
                    resource_id, namespace,
                    "Set readOnlyRootFilesystem: true", "CIS 5.2.8",
                    "TA0003 Persistence"))

            caps = csec.get("capabilities", {})
            drop = caps.get("drop", [])
            if "ALL" not in drop and "NET_RAW" not in drop:
                findings.append(Finding("K8S-008", "HIGH", "NET_RAW capability not dropped",
                    f"Container '{cname}' retains NET_RAW — enables ARP spoofing",
                    resource_id, namespace,
                    "Add capabilities.drop: [ALL]", "CIS 5.2.7",
                    "TA0008 Lateral Movement"))

            limits = container.get("resources", {}).get("limits", {})
            if not limits.get("cpu") or not limits.get("memory"):
                findings.append(Finding("K8S-009", "MEDIUM", "Missing resource limits",
                    f"Container '{cname}' has no CPU/memory limits — DoS risk",
                    resource_id, namespace,
                    "Set resources.limits.cpu and resources.limits.memory", "CIS 5.2.12",
                    "TA0040 Impact"))

            # Check for secrets in env vars
            for env in container.get("env", []):
                if env.get("name", "").upper() in ("PASSWORD", "SECRET", "API_KEY", "TOKEN", "PRIVATE_KEY"):
                    if env.get("value"):  # hardcoded — not using secretKeyRef
                        findings.append(Finding("K8S-010", "HIGH", "Hardcoded secret in env var",
                            f"Container '{cname}' has potential secret '{env['name']}' as plain env var",
                            resource_id, namespace,
                            "Use secretKeyRef or external secrets operator", "CIS 5.4.1",
                            "TA0006 Credential Access"))

        return findings

    def _scan_rbac(self, manifest: dict, name: str, namespace: str) -> list[Finding]:
        findings = []
        for rule in manifest.get("rules", []):
            verbs = rule.get("verbs", [])
            resources = rule.get("resources", [])
            if "*" in verbs:
                findings.append(Finding("K8S-011", "CRITICAL", "Wildcard verbs in role",
                    f"Role '{name}' grants wildcard verbs on {resources}",
                    name, namespace,
                    "Replace wildcard with specific verbs (get, list, watch)", "CIS 5.1.3",
                    "TA0004 Privilege Escalation"))
            if "*" in resources:
                findings.append(Finding("K8S-012", "CRITICAL", "Wildcard resources in role",
                    f"Role '{name}' grants access to all resources",
                    name, namespace,
                    "Specify explicit resource types", "CIS 5.1.3",
                    "TA0004 Privilege Escalation"))
        return findings

    def _scan_service(self, manifest: dict, name: str, namespace: str) -> list[Finding]:
        findings = []
        stype = manifest.get("spec", {}).get("type", "ClusterIP")
        if stype == "NodePort":
            findings.append(Finding("K8S-013", "MEDIUM", "NodePort service exposed",
                f"Service '{name}' uses NodePort — exposed on all cluster nodes",
                name, namespace,
                "Use LoadBalancer with restricted ingress or ClusterIP + Ingress", "CIS 5.3.2",
                "TA0011 Command and Control"))
        return findings


# ─────────────────────────────────────────────
#  AUTO-REMEDIATION
# ─────────────────────────────────────────────

def harden_manifest(manifest: dict) -> dict:
    """Apply security hardening to a K8s manifest in-place."""
    kind = manifest.get("kind", "")
    if kind not in ("Deployment", "DaemonSet", "StatefulSet", "Pod"):
        return manifest

    spec = manifest.setdefault("spec", {})
    if "template" in spec:
        pod_spec = spec["template"].setdefault("spec", {})
    else:
        pod_spec = spec

    pod_spec["hostPID"] = False
    pod_spec["hostNetwork"] = False
    pod_spec["hostIPC"] = False

    for container in pod_spec.get("containers", []):
        csec = container.setdefault("securityContext", {})
        csec["privileged"] = False
        csec["runAsNonRoot"] = True
        csec.setdefault("runAsUser", 1000)
        csec["allowPrivilegeEscalation"] = False
        csec["readOnlyRootFilesystem"] = True
        csec.setdefault("capabilities", {})["drop"] = ["ALL"]

        res = container.setdefault("resources", {})
        res.setdefault("limits", {"cpu": "500m", "memory": "256Mi"})
        res.setdefault("requests", {"cpu": "100m", "memory": "64Mi"})

    return manifest


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="K8s Security Hardener")
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan-manifest", help="Scan a manifest file")
    scan_p.add_argument("--file", required=True)
    scan_p.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    scan_p.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM"])
    scan_p.add_argument("--out")

    rem_p = sub.add_parser("remediate", help="Generate hardened manifest")
    rem_p.add_argument("--input", required=True)
    rem_p.add_argument("--out", required=True)

    args = parser.parse_args()

    if args.command == "scan-manifest":
        scanner = ManifestScanner()
        report = AuditReport(cluster="manifest-scan")

        for path in Path(args.file).rglob("*.yaml") if Path(args.file).is_dir() else [Path(args.file)]:
            with open(path) as f:
                for doc in yaml.safe_load_all(f):
                    if doc:
                        report.findings += scanner.scan(doc, str(path))

        if args.format == "text":
            output = report.to_text()
        elif args.format == "sarif":
            output = json.dumps(report.to_sarif(), indent=2)
        else:
            output = json.dumps({"summary": report.summary(),
                                  "findings": [f.__dict__ for f in report.findings]}, indent=2)

        print(output)
        if args.out:
            Path(args.out).write_text(output)

        if args.fail_on:
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            threshold = sev_order[args.fail_on]
            if any(sev_order.get(f.severity, 9) <= threshold for f in report.findings):
                raise SystemExit(1)

    elif args.command == "remediate":
        with open(args.input) as f:
            docs = list(yaml.safe_load_all(f))

        out_path = Path(args.out)
        out_path.mkdir(parents=True, exist_ok=True)

        for i, doc in enumerate(docs):
            if doc:
                hardened = harden_manifest(doc)
                name = doc.get("metadata", {}).get("name", f"resource-{i}")
                out_file = out_path / f"{name}-hardened.yaml"
                with open(out_file, "w") as f:
                    yaml.dump(hardened, f, default_flow_style=False)
                logger.info(f"Hardened manifest written to {out_file}")


if __name__ == "__main__":
    main()
