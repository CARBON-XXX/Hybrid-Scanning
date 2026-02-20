"""漏洞推理引擎 - 整合 SAST + DAST 结果，由 LLM 做最终研判"""
from __future__ import annotations

import json
from typing import Any

from orchestrator.llm.client import DeepSeekClient


class VulnReasoner:
    """漏洞推理器

    职责：
    1. 整合 SAST 静态分析结果和 DAST 动态扫描结果
    2. 调用 LLM 进行交叉验证和深度分析
    3. 对漏洞进行去重、排序和优先级评定
    """

    def __init__(self, llm_client: DeepSeekClient) -> None:
        self._llm = llm_client

    async def analyze_dast_results(
        self,
        fingerprint: dict[str, Any],
        open_ports: list[dict[str, Any]],
        found_paths: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """分析 DAST 扫描结果

        将指纹、端口、路径信息送入 LLM，推理潜在攻击面和漏洞
        """
        result_json = await self._llm.analyze_scan_results(
            fingerprint_data=fingerprint,
            open_ports=open_ports,
            found_paths=found_paths,
        )
        try:
            return json.loads(result_json)
        except json.JSONDecodeError:
            return {"error": "LLM 返回的不是合法 JSON", "raw": result_json}

    async def correlate_findings(
        self,
        sast_findings: list[dict[str, Any]],
        dast_analysis: dict[str, Any],
    ) -> dict[str, Any]:
        """交叉关联 SAST 和 DAST 结果

        将静态发现与动态发现进行关联分析，
        例如 SAST 发现 SQL 注入代码 + DAST 发现相关端点 => 高置信度漏洞
        """
        messages = [
            {
                "role": "system",
                "content": (
                    "你是一名高级安全分析师。你的任务是将静态代码分析(SAST)结果"
                    "与动态扫描(DAST)结果进行交叉关联，判断哪些漏洞是真实可利用的，"
                    "哪些可能是误报。输出 JSON 格式。"
                ),
            },
            {
                "role": "user",
                "content": (
                    "## SAST 发现\n"
                    f"```json\n{json.dumps(sast_findings, indent=2, ensure_ascii=False)}\n```\n\n"
                    "## DAST 分析\n"
                    f"```json\n{json.dumps(dast_analysis, indent=2, ensure_ascii=False)}\n```\n\n"
                    "请输出关联分析结果：\n"
                    "```json\n"
                    "{\n"
                    '  "confirmed_vulns": [\n'
                    "    {\n"
                    '      "title": "漏洞标题",\n'
                    '      "severity": "Critical|High|Medium|Low",\n'
                    '      "confidence": "High|Medium|Low",\n'
                    '      "sast_evidence": "SAST 证据",\n'
                    '      "dast_evidence": "DAST 证据",\n'
                    '      "correlation": "关联说明",\n'
                    '      "exploitability": "可利用性评估"\n'
                    "    }\n"
                    "  ],\n"
                    '  "likely_false_positives": ["可能的误报及原因"],\n'
                    '  "needs_manual_review": ["需要人工复核的项目"]\n'
                    "}\n"
                    "```"
                ),
            },
        ]

        result_json = await self._llm.chat(messages, json_mode=True)
        try:
            return json.loads(result_json)
        except json.JSONDecodeError:
            return {"error": "LLM 返回的不是合法 JSON", "raw": result_json}

    async def prioritize_findings(
        self, findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """对漏洞发现进行优先级排序

        基于 CVSS-like 评分逻辑：
        - 严重程度 (severity)
        - 置信度 (confidence)
        - 可利用性 (exploitability)
        """
        severity_score = {"Critical": 40, "High": 30, "Medium": 20, "Low": 10, "Info": 0}
        confidence_score = {"High": 30, "Medium": 20, "Low": 10}

        for f in findings:
            score = severity_score.get(f.get("severity", ""), 0)
            score += confidence_score.get(f.get("confidence", ""), 0)
            if f.get("llm_verified"):
                score += 20  # LLM 确认加分
            f["priority_score"] = score

        findings.sort(key=lambda f: f.get("priority_score", 0), reverse=True)
        return findings
