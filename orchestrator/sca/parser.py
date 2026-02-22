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
    def parse_composer_json(file_path: Path) -> Dict[str, str]:
        """Parse composer.json (PHP)."""
        try:
            content = json.loads(file_path.read_text(encoding='utf-8'))
            deps = content.get('require', {})
            dev_deps = content.get('require-dev', {})
            return {**deps, **dev_deps}
        except Exception as e:
            print(f"[!] Error parsing {file_path}: {e}")
            return {}

    @staticmethod
    def parse_go_mod(file_path: Path) -> Dict[str, str]:
        """Parse go.mod (Go)."""
        deps = {}
        try:
            content = file_path.read_text(encoding='utf-8')
            # Simple regex for require ( ... ) block and single require lines
            # This is a basic parser, complex go.mod might need a real parser
            lines = content.splitlines()
            in_require = False
            for line in lines:
                line = line.strip()
                if line.startswith('require ('):
                    in_require = True
                    continue
                if line == ')':
                    in_require = False
                    continue
                
                if in_require or line.startswith('require '):
                    parts = line.replace('require ', '').strip().split()
                    if len(parts) >= 2:
                        deps[parts[0]] = parts[1]
        except Exception as e:
            print(f"[!] Error parsing {file_path}: {e}")
        return deps

    @staticmethod
    def parse_cargo_toml(file_path: Path) -> Dict[str, str]:
        """Parse Cargo.toml (Rust)."""
        deps = {}
        try:
            # We don't want to depend on 'toml' package just for this if possible,
            # but standard library doesn't have TOML. 
            # Let's try simple line parsing for [dependencies] section
            # Ideally user should install 'tomli' or 'toml' but we want to keep deps minimal?
            # Actually scanner-engine uses Rust, so orchestrator might not have toml lib.
            # Let's try a very naive parser or assume toml is installed if we want robustness.
            # For now: Naive regex parser for [dependencies] block.
            content = file_path.read_text(encoding='utf-8')
            lines = content.splitlines()
            section = None
            for line in lines:
                line = line.strip()
                if line.startswith('[') and line.endswith(']'):
                    section = line[1:-1].strip()
                    continue
                
                if section in ['dependencies', 'dev-dependencies'] and '=' in line:
                    parts = line.split('=', 1)
                    key = parts[0].strip()
                    val = parts[1].strip().strip('"').strip("'")
                    # Handle inline tables: version = { version = "1.0", features = [...] }
                    if val.startswith('{'):
                         # Try to extract version from { version = "..." }
                         v_match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', val)
                         if v_match:
                             deps[key] = v_match.group(1)
                         else:
                             deps[key] = "unknown" # Complex structure
                    else:
                        deps[key] = val
        except Exception as e:
            print(f"[!] Error parsing {file_path}: {e}")
        return deps

    @staticmethod
    def parse_pom_xml(file_path: Path) -> Dict[str, str]:
        """Parse pom.xml (Java/Maven)."""
        deps = {}
        try:
            # Naive XML parsing to avoid lxml dependency if possible
            # Look for <dependency> blocks
            content = file_path.read_text(encoding='utf-8')
            # Remove comments
            content = re.sub(r'<!--.*?-->', '', content, flags=re.DOTALL)
            
            dependencies = re.findall(r'<dependency>(.*?)</dependency>', content, re.DOTALL)
            for dep in dependencies:
                g_match = re.search(r'<groupId>(.*?)</groupId>', dep)
                a_match = re.search(r'<artifactId>(.*?)</artifactId>', dep)
                v_match = re.search(r'<version>(.*?)</version>', dep)
                
                if g_match and a_match:
                    group = g_match.group(1).strip()
                    artifact = a_match.group(1).strip()
                    version = v_match.group(1).strip() if v_match else "latest"
                    # Handle variable substitution like ${project.version} - simplified
                    if '${' in version:
                        version = "dynamic"
                    
                    deps[f"{group}:{artifact}"] = version
        except Exception as e:
            print(f"[!] Error parsing {file_path}: {e}")
        return deps

    @staticmethod
    def parse_csproj(file_path: Path) -> Dict[str, str]:
        """Parse .csproj (C#/.NET)."""
        deps = {}
        try:
            content = file_path.read_text(encoding='utf-8')
            # Remove comments
            content = re.sub(r'<!--.*?-->', '', content, flags=re.DOTALL)
            
            # Match <PackageReference Include="Name" Version="Version" />
            # Also handles Version as child element if needed, but attribute is most common
            refs = re.findall(r'<PackageReference\s+[^>]*>', content)
            for ref in refs:
                inc_match = re.search(r'Include\s*=\s*["\']([^"\']+)["\']', ref, re.IGNORECASE)
                ver_match = re.search(r'Version\s*=\s*["\']([^"\']+)["\']', ref, re.IGNORECASE)
                
                if inc_match:
                    name = inc_match.group(1)
                    version = ver_match.group(1) if ver_match else "latest"
                    deps[name] = version
        except Exception as e:
            print(f"[!] Error parsing {file_path}: {e}")
        return deps

    @staticmethod
    def detect_files(project_dir: Path) -> List[Path]:
        """Detect supported dependency files in the project."""
        files = []
        files.extend(list(project_dir.rglob("package.json")))
        files.extend(list(project_dir.rglob("requirements.txt")))
        files.extend(list(project_dir.rglob("composer.json")))
        files.extend(list(project_dir.rglob("go.mod")))
        files.extend(list(project_dir.rglob("Cargo.toml")))
        files.extend(list(project_dir.rglob("pom.xml")))
        files.extend(list(project_dir.rglob("*.csproj")))
        
        # Exclude node_modules, venv, target, vendor
        excluded = ["node_modules", "venv", ".venv", "target", "vendor", ".git", "bin", "obj"]
        return [f for f in files if not any(ex in f.parts for ex in excluded)]
