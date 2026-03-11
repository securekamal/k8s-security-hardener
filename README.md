# ☸️ K8s Security Hardener

> Kubernetes security auditor and auto-remediation tool — scans clusters against CIS Benchmark, NSA/CISA hardening guide, and MITRE ATT&CK for Containers. Generates hardened manifests automatically.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue)](https://python.org)
[![CIS Benchmark](https://img.shields.io/badge/CIS-Kubernetes-blue)](https://www.cisecurity.org)
[![NSA/CISA](https://img.shields.io/badge/NSA%2FCISA-Hardening-red)](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)

## Features

- 🔍 **Cluster audit** — scans live cluster via `kubectl` or kubeconfig
- 📋 **CIS Benchmark** — all 5 CIS Kubernetes Benchmark sections
- 🔐 **RBAC analysis** — wildcard permissions, cluster-admin bindings, service account abuse
- 🐳 **Pod security** — privileged containers, hostPath mounts, root users, capabilities
- 🌐 **Network policies** — missing NetworkPolicy, unrestricted egress
- 🔑 **Secrets audit** — secrets in env vars, ConfigMaps, or base64 in YAML
- 🛠️ **Auto-remediation** — generates hardened manifests for every finding
- 📊 **HTML/SARIF/JSON reports** — CI/CD native

## Quickstart

```bash
pip install -r requirements.txt

# Audit current kubeconfig context
python k8s_hardener.py audit --all-namespaces

# Audit specific namespace
python k8s_hardener.py audit --namespace production --output report.html

# Generate hardened manifests
python k8s_hardener.py remediate --input deployment.yaml --out hardened/

# Run against a manifest file (no cluster needed)
python k8s_hardener.py scan-manifest --file k8s/deployment.yaml

# Check RBAC specifically
python k8s_hardener.py rbac --namespace default --show-risk-paths
```

## Checks Performed

### Pod Security (CIS 5.x)
| Check | Severity |
|-------|----------|
| Container running as root | HIGH |
| Privileged container | CRITICAL |
| hostPID / hostNetwork / hostIPC | CRITICAL |
| Writable root filesystem | HIGH |
| NET_RAW capability | HIGH |
| Missing readOnlyRootFilesystem | MEDIUM |
| Missing resource limits | MEDIUM |
| Missing liveness/readiness probes | LOW |

### RBAC (CIS 5.1.x)
| Check | Severity |
|-------|----------|
| Wildcard verbs in ClusterRole | CRITICAL |
| cluster-admin binding to SA | CRITICAL |
| Default service account used | MEDIUM |
| Automounted service account token | MEDIUM |

### Network
| Check | Severity |
|-------|----------|
| No NetworkPolicy in namespace | HIGH |
| Unrestricted egress | HIGH |
| NodePort services exposed | MEDIUM |

## Auto-Remediation Example

Input `deployment.yaml`:
```yaml
containers:
  - name: app
    image: myapp:latest
    securityContext:
      privileged: true   # ← CRITICAL
```

Output `hardened/deployment.yaml`:
```yaml
containers:
  - name: app
    image: myapp:latest
    securityContext:
      privileged: false
      runAsNonRoot: true
      runAsUser: 1000
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
    resources:
      limits:
        cpu: "500m"
        memory: "256Mi"
```

## CI/CD Integration

```yaml
# .github/workflows/k8s-security.yml
- name: K8s Security Scan
  run: |
    python k8s_hardener.py scan-manifest \
      --file k8s/ \
      --fail-on CRITICAL \
      --format sarif \
      --out k8s-security.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: k8s-security.sarif
```
