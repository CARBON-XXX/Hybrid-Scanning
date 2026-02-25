"""OpenAPI / Swagger Specification Parser"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass
class APIEndpoint:
    path: str
    method: str
    summary: str
    parameters: list[dict[str, Any]]
    request_body: dict[str, Any] | None
    responses: dict[str, Any]


class OpenAPIParser:
    """Parses OpenAPI v2/v3 specifications."""

    def __init__(self, spec_path: str | Path):
        self.spec_path = Path(spec_path)
        self.spec: dict[str, Any] = self._load_spec()

    def _load_spec(self) -> dict[str, Any]:
        """Load JSON or YAML spec."""
        if not self.spec_path.exists():
            raise FileNotFoundError(f"Spec file not found: {self.spec_path}")

        try:
            content = self.spec_path.read_text(encoding="utf-8")
            if self.spec_path.suffix in [".yaml", ".yml"]:
                return yaml.safe_load(content)
            else:
                return json.loads(content)
        except Exception as e:
            raise ValueError(f"Failed to parse OpenAPI spec: {e}") from e

    def get_endpoints(self) -> list[APIEndpoint]:
        """Extract all endpoints from the spec."""
        endpoints = []
        paths = self.spec.get("paths", {})

        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() not in [
                    "get",
                    "post",
                    "put",
                    "delete",
                    "patch",
                    "head",
                    "options",
                ]:
                    continue

                # Resolve parameters (merging path-level and method-level)
                path_params = methods.get("parameters", [])
                method_params = details.get("parameters", [])
                all_params = path_params + method_params

                endpoints.append(
                    APIEndpoint(
                        path=path,
                        method=method.upper(),
                        summary=details.get("summary", ""),
                        parameters=all_params,
                        request_body=details.get("requestBody"),
                        responses=details.get("responses", {}),
                    )
                )
        return endpoints

    def get_base_url(self) -> str:
        """Attempt to determine base URL from spec."""
        # OpenAPI v3
        servers = self.spec.get("servers", [])
        if servers:
            return servers[0].get("url", "")

        # OpenAPI v2 (Swagger)
        host = self.spec.get("host")
        base_path = self.spec.get("basePath", "/")
        schemes = self.spec.get("schemes", ["http"])
        if host:
            return f"{schemes[0]}://{host}{base_path}"

        return ""
