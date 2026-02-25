"""IaC Scanner for Docker and Kubernetes"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


class KubernetesScanner:
    """Scan Kubernetes manifests for security best practices."""

    RULES = [
        {
            "id": "IAC-K8S-001",
            "pattern": r"privileged:\s*true",
            "description": "Privileged container detected",
            "severity": "Critical",
        },
        {
            "id": "IAC-K8S-002",
            "pattern": r"hostPID:\s*true|hostNetwork:\s*true|hostIPC:\s*true",
            "description": "Container sharing host namespace (PID/Network/IPC)",
            "severity": "High",
        },
        {
            "id": "IAC-K8S-003",
            "pattern": r"runAsUser:\s*0|runAsNonRoot:\s*false",
            "description": "Container running as root user",
            "severity": "High",
        },
        {
            "id": "IAC-K8S-004",
            "pattern": r"readOnlyRootFilesystem:\s*false",
            "description": "Root filesystem should be read-only",
            "severity": "Medium",
        },
        {
            "id": "IAC-K8S-005",
            "pattern": r"automountServiceAccountToken:\s*true",
            "description": "Service Account token automatically mounted (disable if not needed)",
            "severity": "Low",
        },
    ]

    def scan(self, file_path: Path) -> list[dict[str, Any]]:
        """Scan a Kubernetes manifest for issues."""
        findings = []
        try:
            content = file_path.read_text(encoding="utf-8")
            # Basic check if it looks like k8s
            if "apiVersion:" not in content or "kind:" not in content:
                return []

            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                line = line.strip()
                if line.startswith("#") or not line:
                    continue

                for rule in self.RULES:
                    if re.search(rule["pattern"], line, re.IGNORECASE):
                        findings.append(
                            {
                                "rule_id": rule["id"],
                                "title": rule["description"],
                                "severity": rule["severity"],
                                "file_path": str(file_path),
                                "line": i,
                                "code": line,
                                "type": "IaC",
                            }
                        )
        except Exception as e:
            print(f"[!] Error scanning K8s manifest {file_path}: {e}")

        return findings

    @staticmethod
    def detect_files(project_dir: Path) -> list[Path]:
        """Detect Kubernetes manifests in the project."""
        files = []
        files.extend(list(project_dir.rglob("*.yaml")))
        files.extend(list(project_dir.rglob("*.yml")))

        # Filter for actual K8s files (simple check)
        k8s_files = []
        for f in files:
            if "node_modules" in f.parts or ".git" in f.parts:
                continue
            try:
                # Read first few lines to check for apiVersion/kind
                content = f.read_text(encoding="utf-8", errors="ignore")[:500]
                if "apiVersion:" in content and "kind:" in content:
                    k8s_files.append(f)
            except Exception:
                continue

        return k8s_files


class DockerfileScanner:
    """Scan Dockerfiles for security best practices."""

    RULES = [
        {
            "id": "IAC-DOCKER-001",
            "pattern": r"^USER\s+root",
            "description": "Running container as root user",
            "severity": "High",
        },
        {
            "id": "IAC-DOCKER-002",
            "pattern": r"FROM\s+.*:latest",
            "description": "Using 'latest' tag for base image",
            "severity": "Medium",
        },
        {
            "id": "IAC-DOCKER-003",
            "pattern": r"apk add --no-cache|apt-get install -y",
            "description": "Missing version pinning in package installation",
            "severity": "Low",
        },
        {
            "id": "IAC-DOCKER-004",
            "pattern": r"ADD\s+",
            "description": "Use COPY instead of ADD (ADD can retrieve remote URLs/extract archives)",
            "severity": "Low",
        },
        {
            "id": "IAC-DOCKER-005",
            "pattern": r"EXPOSE\s+22",
            "description": "Exposing SSH port 22 in container",
            "severity": "High",
        },
    ]

    def scan(self, file_path: Path) -> list[dict[str, Any]]:
        """Scan a Dockerfile for issues."""
        findings = []
        try:
            content = file_path.read_text(encoding="utf-8")
            lines = content.splitlines()

            for i, line in enumerate(lines, 1):
                line = line.strip()
                if line.startswith("#") or not line:
                    continue

                for rule in self.RULES:
                    if re.search(rule["pattern"], line, re.IGNORECASE):
                        findings.append(
                            {
                                "rule_id": rule["id"],
                                "title": rule["description"],
                                "severity": rule["severity"],
                                "file_path": str(file_path),
                                "line": i,
                                "code": line,
                                "type": "IaC",
                            }
                        )
        except Exception as e:
            print(f"[!] Error scanning Dockerfile {file_path}: {e}")

        return findings

    @staticmethod
    def detect_files(project_dir: Path) -> list[Path]:
        """Detect Dockerfiles in the project."""
        files = list(project_dir.rglob("Dockerfile*"))
        return [f for f in files if "node_modules" not in f.parts and ".git" not in f.parts]
