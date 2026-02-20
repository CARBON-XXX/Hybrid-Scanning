"""LLM Prompt 模板库 - 安全分析专用"""
from __future__ import annotations

import json
from typing import Any


class PromptTemplates:
    """所有 Prompt 模板的集中管理"""

    SYSTEM_ROLE = (
        "你是一名资深的网络安全工程师和代码审计专家。"
        "你的任务是对用户提供的代码或扫描结果进行安全分析，"
        "识别出真实、可利用的安全漏洞，并给出严格的技术评估。\n\n"
        "规则：\n"
        "1. 只报告你有高置信度的漏洞，不要猜测或编造。\n"
        "2. 每个漏洞必须给出：漏洞类型、严重程度（Critical/High/Medium/Low/Info）、"
        "影响描述、具体代码位置（行号）、修复建议。\n"
        "3. 使用 CWE 编号标识漏洞类型。\n"
        "4. 你的输出必须是合法的 JSON。"
    )

    @staticmethod
    def code_audit(code: str, language: str, context: str = "") -> list[dict[str, str]]:
        """源代码审计 Prompt"""
        user_content = (
            f"请审计以下 {language} 代码的安全性。\n\n"
        )
        if context:
            user_content += f"上下文信息：{context}\n\n"
        user_content += (
            f"```{language}\n{code}\n```\n\n"
            "请以 JSON 格式输出，结构如下：\n"
            "```json\n"
            "{\n"
            '  "findings": [\n'
            "    {\n"
            '      "id": "VULN-001",\n'
            '      "cwe": "CWE-89",\n'
            '      "title": "SQL 注入",\n'
            '      "severity": "Critical",\n'
            '      "confidence": "High",\n'
            '      "line_start": 42,\n'
            '      "line_end": 45,\n'
            '      "code_snippet": "...",\n'
            '      "description": "...",\n'
            '      "impact": "...",\n'
            '      "remediation": "..."\n'
            "    }\n"
            "  ],\n"
            '  "summary": "简要总结"\n'
            "}\n"
            "```"
        )

        return [
            {"role": "system", "content": PromptTemplates.SYSTEM_ROLE},
            {"role": "user", "content": user_content},
        ]

    @staticmethod
    def scan_analysis(
        fingerprint_data: dict[str, Any],
        open_ports: list[dict[str, Any]],
        found_paths: list[dict[str, Any]],
    ) -> list[dict[str, str]]:
        """扫描结果综合分析 Prompt"""
        user_content = (
            "请分析以下自动化扫描结果，识别潜在的安全风险和可利用漏洞。\n\n"
            "## 指纹识别结果\n"
            f"```json\n{json.dumps(fingerprint_data, indent=2, ensure_ascii=False)}\n```\n\n"
            "## 开放端口\n"
            f"```json\n{json.dumps(open_ports, indent=2, ensure_ascii=False)}\n```\n\n"
            "## 发现的路径\n"
            f"```json\n{json.dumps(found_paths, indent=2, ensure_ascii=False)}\n```\n\n"
            "请基于以上信息，输出 JSON 格式的分析结果：\n"
            "```json\n"
            "{\n"
            '  "risk_assessment": "整体风险评级 (Critical/High/Medium/Low)",\n'
            '  "attack_surface": [\n'
            "    {\n"
            '      "entry_point": "入口点描述",\n'
            '      "technology": "涉及技术",\n'
            '      "potential_vulns": ["可能的漏洞类型"],\n'
            '      "severity": "严重程度",\n'
            '      "next_steps": ["建议的后续测试步骤"]\n'
            "    }\n"
            "  ],\n"
            '  "exposed_info": ["暴露的敏感信息"],\n'
            '  "recommendations": ["安全加固建议"]\n'
            "}\n"
            "```"
        )

        return [
            {"role": "system", "content": PromptTemplates.SYSTEM_ROLE},
            {"role": "user", "content": user_content},
        ]

    @staticmethod
    def report_summary(findings: list[dict[str, Any]]) -> list[dict[str, str]]:
        """生成报告摘要的 Prompt"""
        user_content = (
            "请根据以下漏洞发现列表，生成一份专业的安全评估摘要报告。\n"
            "报告需要包含：风险总览、关键发现、优先修复建议。\n\n"
            f"漏洞列表：\n```json\n{json.dumps(findings, indent=2, ensure_ascii=False)}\n```\n\n"
            "请直接输出 Markdown 格式的摘要报告，语言简洁专业。"
        )

        return [
            {"role": "system", "content": PromptTemplates.SYSTEM_ROLE},
            {"role": "user", "content": user_content},
        ]
