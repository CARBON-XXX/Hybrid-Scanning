"""Dependency Parser for SCA"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional
import re

class DependencyParser:
    """Parse dependency files to extract package names and versions."""

    @staticmethod
    def parse_package_json(file_path: Path) -> Dict[str, str]:
        """Parse package.json file."""
        try:
            content = json.loads(file_path.read_text(encoding='utf-8'))
            deps = content.get('dependencies', {})
            dev_deps = content.get('devDependencies', {})
            # Merge both
            return {**deps, **dev_deps}
        except Exception as e:
            print(f"[!] Error parsing {file_path}: {e}")
            return {}

    @staticmethod
    def parse_requirements_txt(file_path: Path) -> Dict[str, str]:
        """Parse requirements.txt file."""
        deps = {}
        try:
            lines = file_path.read_text(encoding='utf-8').splitlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Simple parsing for standard requirements.txt
                # Handles: package==1.0.0, package>=1.0.0, package
                match = re.match(r'^([a-zA-Z0-9_\-]+)(?:[=<>!~]+)(.+)$', line)
                if match:
                    deps[match.group(1)] = match.group(2)
                else:
                    # Case for just package name or complex line
                    parts = re.split(r'[=<>!~]', line)
                    if parts:
                         deps[parts[0].strip()] = "latest"
        except Exception as e:
            print(f"[!] Error parsing {file_path}: {e}")
        return deps

    @staticmethod
    def detect_files(project_dir: Path) -> List[Path]:
        """Detect supported dependency files in the project."""
        files = []
        files.extend(list(project_dir.rglob("package.json")))
        files.extend(list(project_dir.rglob("requirements.txt")))
        # Exclude node_modules and venv
        return [f for f in files if "node_modules" not in f.parts and "venv" not in f.parts and ".venv" not in f.parts]
