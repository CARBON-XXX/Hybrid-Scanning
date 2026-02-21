"""IaC Scanner for Docker and Kubernetes"""
from __future__ import annotations

from pathlib import Path
from typing import List, Dict, Any
import re

class DockerfileScanner:
    """Scan Dockerfiles for security best practices."""

    RULES = [
        {
            "id": "IAC-DOCKER-001",
            "pattern": r"^USER\s+root",
            "description": "Running container as root user",
            "severity": "High"
        },
        {
            "id": "IAC-DOCKER-002",
            "pattern": r"FROM\s+.*:latest",
            "description": "Using 'latest' tag for base image",
            "severity": "Medium"
        },
        {
            "id": "IAC-DOCKER-003",
            "pattern": r"apk add --no-cache|apt-get install -y",
            "description": "Missing version pinning in package installation",
            "severity": "Low"
        },
        {
            "id": "IAC-DOCKER-004",
            "pattern": r"ADD\s+",
            "description": "Use COPY instead of ADD (ADD can retrieve remote URLs/extract archives)",
            "severity": "Low"
        },
        {
            "id": "IAC-DOCKER-005",
            "pattern": r"EXPOSE\s+22",
            "description": "Exposing SSH port 22 in container",
            "severity": "High"
        }
    ]

    def scan(self, file_path: Path) -> List[Dict[str, Any]]:
        """Scan a Dockerfile for issues."""
        findings = []
        try:
            content = file_path.read_text(encoding='utf-8')
            lines = content.splitlines()

            for i, line in enumerate(lines, 1):
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                
                for rule in self.RULES:
                    if re.search(rule["pattern"], line, re.IGNORECASE):
                        findings.append({
                            "rule_id": rule["id"],
                            "title": rule["description"],
                            "severity": rule["severity"],
                            "file_path": str(file_path),
                            "line": i,
                            "code": line,
                            "type": "IaC"
                        })
        except Exception as e:
            print(f"[!] Error scanning Dockerfile {file_path}: {e}")
        
        return findings

    @staticmethod
    def detect_files(project_dir: Path) -> List[Path]:
        """Detect Dockerfiles in the project."""
        files = list(project_dir.rglob("Dockerfile*"))
        return [f for f in files if "node_modules" not in f.parts and ".git" not in f.parts]
