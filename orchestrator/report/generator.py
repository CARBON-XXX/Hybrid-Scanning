"""安全评估报告生成器"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from jinja2 import Template

from orchestrator.llm.client import DeepSeekClient


def _mask_secrets(cfg: dict) -> dict:
    """遮蔽配置中的敏感字段（如 API Key），防止报告泄露凭据"""
    import copy

    masked = copy.deepcopy(cfg)
    llm = masked.get("llm", {})
    if llm.get("api_key"):
        key = llm["api_key"]
        llm["api_key"] = key[:6] + "***" + key[-4:] if len(key) > 10 else "***"
    return masked


# 报告 Markdown 模板
REPORT_TEMPLATE = Template("""\
# Security Assessment Report

**目标**: {{ target }}
**扫描时间**: {{ scan_time }}
**引擎版本**: Hybrid Scanner v0.1.0

---

## Overview

| 指标 | 值 |
|------|-----|
| 发现漏洞总数 | {{ total_findings }} |
| Critical | {{ critical_count }} |
| High | {{ high_count }} |
| Medium | {{ medium_count }} |
| Low | {{ low_count }} |
| LLM 验证通过 | {{ llm_verified_count }} |
| 整体风险评级 | **{{ risk_level }}** |

---

## Executive Summary

{{ executive_summary }}

---

## Vulnerability Details

{% for finding in findings %}
### {{ loop.index }}. [{{ finding.severity }}] {{ finding.title }}

| 属性 | 值 |
|------|-----|
| 规则 ID | `{{ finding.rule_id }}` |
| CWE | {{ finding.cwe }} |
| 严重程度 | **{{ finding.severity }}** |
| 置信度 | {{ finding.confidence }} |
| 文件 | `{{ finding.file_path }}` |
| 行号 | {{ finding.line_start }} - {{ finding.line_end }} |
| LLM 验证 | {{ "CONFIRMED" if finding.llm_verified else "UNVERIFIED" }} |

**描述**: {{ finding.description }}

**代码片段**:
```
{{ finding.code_snippet }}
```

{% if finding.llm_analysis %}
**LLM 分析**: {{ finding.llm_analysis }}
{% endif %}

**修复建议**: {{ finding.remediation }}

---

{% endfor %}

{% if dast_analysis %}
## DAST Analysis

### 攻击面

{% for surface in dast_analysis.get('attack_surface', []) %}
- **{{ surface.entry_point }}** ({{ surface.technology }})
  - 潜在漏洞: {{ surface.potential_vulns | join(', ') }}
  - 严重程度: {{ surface.severity }}
{% endfor %}

### 暴露信息

{% for info in dast_analysis.get('exposed_info', []) %}
- {{ info }}
{% endfor %}

### 加固建议

{% for rec in dast_analysis.get('recommendations', []) %}
- {{ rec }}
{% endfor %}

---
{% endif %}

{% if correlation %}
## Cross-Correlation Analysis

### 已确认漏洞

{% for vuln in correlation.get('confirmed_vulns', []) %}
- **{{ vuln.title }}** [{{ vuln.severity }}]
  - SAST 证据: {{ vuln.sast_evidence }}
  - DAST 证据: {{ vuln.dast_evidence }}
  - 关联说明: {{ vuln.correlation }}
  - 可利用性: {{ vuln.exploitability }}
{% endfor %}

### 可能的误报

{% for fp in correlation.get('likely_false_positives', []) %}
- {{ fp }}
{% endfor %}

### 需要人工复核

{% for item in correlation.get('needs_manual_review', []) %}
- {{ item }}
{% endfor %}

---
{% endif %}

## Scan Configuration

```json
{{ config_json }}
```

---

*报告由 Hybrid Scanning Engine 自动生成*
*生成时间: {{ scan_time }}*
""")


class ReportGenerator:
    """安全评估报告生成器"""

    def __init__(self, output_dir: str | Path, llm_client: DeepSeekClient | None = None) -> None:
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._llm = llm_client

    async def generate(
        self,
        target: str,
        findings: list[dict[str, Any]],
        dast_analysis: dict[str, Any] | None = None,
        correlation: dict[str, Any] | None = None,
        config: dict[str, Any] | None = None,
    ) -> Path:
        """生成完整的安全评估报告

        Args:
            target: 扫描目标（URL 或项目路径）
            findings: 漏洞发现列表
            dast_analysis: DAST 分析结果
            correlation: 交叉关联分析结果
            config: 扫描配置

        Returns:
            报告文件路径
        """
        tz = timezone(timedelta(hours=8))
        scan_time = datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S CST")

        # 统计
        critical_count = sum(1 for f in findings if f.get("severity") == "Critical")
        high_count = sum(1 for f in findings if f.get("severity") == "High")
        medium_count = sum(1 for f in findings if f.get("severity") == "Medium")
        low_count = sum(1 for f in findings if f.get("severity") == "Low")
        llm_verified_count = sum(1 for f in findings if f.get("llm_verified"))

        # 风险评级
        if critical_count > 0:
            risk_level = "CRITICAL"
        elif high_count > 0:
            risk_level = "HIGH"
        elif medium_count > 0:
            risk_level = "MEDIUM"
        elif low_count > 0:
            risk_level = "LOW"
        else:
            risk_level = "CLEAN"

        # 生成执行摘要
        executive_summary = await self._generate_summary(findings)

        # 渲染报告
        report_content = REPORT_TEMPLATE.render(
            target=target,
            scan_time=scan_time,
            total_findings=len(findings),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            llm_verified_count=llm_verified_count,
            risk_level=risk_level,
            executive_summary=executive_summary,
            findings=findings,
            dast_analysis=dast_analysis,
            correlation=correlation,
            config_json=json.dumps(_mask_secrets(config or {}), indent=2, ensure_ascii=False),
        )

        # 保存文件
        timestamp = datetime.now(tz).strftime("%Y%m%d_%H%M%S")

        # Windows 文件名非法字符替换: < > : " / \ | ? *
        safe_target = target
        for char in ["<", ">", ":", '"', "/", "\\", "|", "?", "*"]:
            safe_target = safe_target.replace(char, "_")

        safe_target = safe_target[:50]
        filename = f"report_{safe_target}_{timestamp}.md"
        report_path = self._output_dir / filename

        report_path.write_text(report_content, encoding="utf-8-sig")

        # 同时输出 JSON 格式
        json_path = report_path.with_suffix(".json")
        json_data = {
            "target": target,
            "scan_time": scan_time,
            "risk_level": risk_level,
            "findings": findings,
            "dast_analysis": dast_analysis,
            "correlation": correlation,
            "statistics": {
                "total": len(findings),
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
                "llm_verified": llm_verified_count,
            },
        }
        json_path.write_text(
            json.dumps(json_data, indent=2, ensure_ascii=False),
            encoding="utf-8-sig",
        )

        return report_path

    async def _generate_summary(self, findings: list[dict[str, Any]]) -> str:
        """生成执行摘要"""
        if self._llm and findings:
            try:
                return await self._llm.generate_report_summary(findings)
            except Exception:
                pass

        # 降级：简单统计摘要
        total = len(findings)
        if total == 0:
            return "本次扫描未发现安全漏洞。"

        return (
            f"本次安全评估共发现 **{total}** 个潜在安全问题。"
            f"建议优先处理 Critical 和 High 级别的漏洞，"
            f"并对 LLM 未验证的发现进行人工复核。"
        )
