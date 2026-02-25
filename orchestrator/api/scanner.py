"""Async API Security Scanner"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

import httpx
from rich.console import Console

from orchestrator.api.parser import APIEndpoint
from orchestrator.llm.client import DeepSeekClient

console = Console()


class APIScanner:
    """Async API Vulnerability Scanner"""

    def __init__(self, base_url: str, llm_client: DeepSeekClient | None = None):
        self.base_url = base_url.rstrip("/")
        self.llm = llm_client
        self.client = httpx.AsyncClient(verify=False, timeout=10.0)

    async def close(self):
        await self.client.aclose()

    async def scan_endpoint(self, endpoint: APIEndpoint) -> list[dict[str, Any]]:
        """Scan a single API endpoint for vulnerabilities."""
        findings = []
        console.print(f"  [>] Scanning {endpoint.method} {endpoint.path}...")

        # 1. BOLA / IDOR Test (if path parameters exist)
        if "{" in endpoint.path and "}" in endpoint.path:
            # bola_findings = await self._test_bola(endpoint)
            # findings.extend(bola_findings)
            pass

        # 2. LLM-driven Logic Test (if enabled)
        if self.llm is not None:
            llm_findings = await self._llm_logic_test(endpoint)
            findings.extend(llm_findings)

        return findings

    async def _llm_logic_test(self, endpoint: APIEndpoint) -> list[dict[str, Any]]:
        """Use LLM to generate specific test payloads for this endpoint."""
        findings: list[dict[str, Any]] = []
        if self.llm is None:
            return findings

        try:
            # Prepare context for LLM
            ep_data = asdict(endpoint)

            # Generate payloads
            resp_json = await self.llm.generate_api_payloads(ep_data)

            try:
                # Extract JSON from potential markdown
                if "```json" in resp_json:
                    resp_json = resp_json.split("```json")[1].split("```")[0].strip()
                elif "```" in resp_json:
                    resp_json = resp_json.split("```")[1].split("```")[0].strip()

                data = json.loads(resp_json)
            except json.JSONDecodeError:
                console.print(f"    [!] Failed to parse LLM response for {endpoint.path}")
                return []

            test_cases = data.get("test_cases", [])
            if not test_cases:
                return []

            console.print(f"    [*] LLM generated {len(test_cases)} test cases")

            for case in test_cases:
                payload = case.get("payload", {})
                case.get("risk", "Medium")
                desc = case.get("description", "")

                # Construct URL (replace path params if any)
                # Simple heuristic: if payload keys match path params, use them
                url = f"{self.base_url}{endpoint.path}"
                req_data = payload.copy()

                # Basic path param substitution
                for k, v in payload.items():
                    placeholder = f"{{{k}}}"
                    if placeholder in url:
                        url = url.replace(placeholder, str(v))
                        if k in req_data:
                            del req_data[k]  # Remove from body/query if used in path

                # Execute Request
                try:
                    resp = await self._send_request(endpoint.method, url, req_data)

                    # Analysis (Simplified: 500 = Error, 200 + Sensitive = Leak?)
                    # Real DAST needs more complex analysis.
                    # Here we just flag 500s or explicit success criteria if we had them.
                    # For now, let's flag if status is 500 (Server Error) or if LLM predicted a high risk and we got 200 (Success?)
                    # This is very naive. A better way is to ask LLM to analyze the response.

                    if resp.status_code >= 500:
                        findings.append(
                            {
                                "rule_id": "API-LLM-500",
                                "title": f"Server Error triggered by {case.get('name')}",
                                "severity": "Medium",
                                "description": f"Payload triggered 500 error.\nPayload: {payload}\nDesc: {desc}",
                                "file_path": f"{endpoint.method} {endpoint.path}",
                                "line": 0,
                                "source": "llm-api",
                            }
                        )

                    # Note: We really should feed the response back to LLM for analysis,
                    # but for MVP let's keep it simple or maybe one more step.

                except Exception as req_err:
                    console.print(f"    [!] Request failed: {req_err}")

        except Exception as e:
            console.print(f"    [!] LLM Logic Test Error: {e}")

        return findings

    async def _send_request(self, method: str, url: str, data: dict[str, Any]) -> httpx.Response:
        """Send HTTP request."""
        if method.upper() in ["GET", "DELETE"]:
            return await self.client.request(method, url, params=data)
        else:
            return await self.client.request(method, url, json=data)

    async def scan_spec(self, endpoints: list[APIEndpoint]) -> list[dict[str, Any]]:
        """Scan all endpoints defined in the spec."""
        all_findings = []
        console.print(f"[*] Scanning {len(endpoints)} API endpoints...")

        for ep in endpoints:
            try:
                findings = await self.scan_endpoint(ep)
                all_findings.extend(findings)
            except Exception as e:
                console.print(f"[red][!] Error scanning {ep.path}: {e}[/red]")

        return all_findings
