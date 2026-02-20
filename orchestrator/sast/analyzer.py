"""SAST 静态分析引擎 - 正则规则 + LLM 交叉验证"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from orchestrator.config import SASTConfig
from orchestrator.sast.rules import BUILTIN_RULES, VulnRule


@dataclass
class Finding:
    """单个漏洞发现"""
    rule_id: str
    cwe: str
    title: str
    severity: str
    confidence: str
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    description: str
    remediation: str
    llm_verified: bool = False
    llm_analysis: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "cwe": self.cwe,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "code_snippet": self.code_snippet,
            "description": self.description,
            "remediation": self.remediation,
            "llm_verified": self.llm_verified,
            "llm_analysis": self.llm_analysis,
        }


# 语言 -> 文件扩展名映射
LANG_EXTENSIONS: dict[str, list[str]] = {
    "python": [".py"],
    "javascript": [".js", ".jsx", ".ts", ".tsx"],
    "php": [".php"],
    "java": [".java"],
}


class SASTAnalyzer:
    """静态应用安全测试分析器

    工作流程：
    1. 遍历项目目录，收集目标语言的源文件
    2. 对每个文件运行正则规则引擎
    3. (可选) 将疑似漏洞代码片段送入 LLM 做交叉验证，减少误报
    """

    def __init__(self, config: SASTConfig, rules: Optional[list[VulnRule]] = None) -> None:
        self._config = config
        self._rules = rules or BUILTIN_RULES
        # 预编译所有正则
        for rule in self._rules:
            rule.compile()

    def collect_files(self, project_dir: str | Path) -> list[Path]:
        """收集项目目录下所有目标语言的源文件"""
        project_path = Path(project_dir)
        if not project_path.is_dir():
            raise ValueError(f"项目目录不存在: {project_dir}")

        target_exts: set[str] = set()
        for lang in self._config.languages:
            target_exts.update(LANG_EXTENSIONS.get(lang, []))

        files: list[Path] = []
        for f in project_path.rglob("*"):
            # 跳过排除目录
            if any(excluded in f.parts for excluded in self._config.exclude_dirs):
                continue
            if f.is_file() and f.suffix in target_exts:
                # 跳过过大的文件
                if f.stat().st_size <= self._config.max_file_size_kb * 1024:
                    files.append(f)
        return files

    def detect_language(self, file_path: Path) -> Optional[str]:
        """根据文件扩展名判断语言"""
        for lang, exts in LANG_EXTENSIONS.items():
            if file_path.suffix in exts:
                return lang
        return None

    def scan_file(self, file_path: Path) -> list[Finding]:
        """对单个文件进行正则规则扫描"""
        language = self.detect_language(file_path)
        if language is None:
            return []

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        lines = content.splitlines()
        findings: list[Finding] = []

        for rule in self._rules:
            if language not in rule.languages:
                continue

            compiled = rule.compile()
            for match in compiled.finditer(content):
                # 计算行号
                start_pos = match.start()
                line_num = content[:start_pos].count("\n") + 1

                # 提取上下文代码片段（前后各 2 行）
                ctx_start = max(0, line_num - 3)
                ctx_end = min(len(lines), line_num + 2)
                snippet = "\n".join(lines[ctx_start:ctx_end])

                findings.append(Finding(
                    rule_id=rule.rule_id,
                    cwe=rule.cwe,
                    title=rule.title,
                    severity=rule.severity.value,
                    confidence=rule.confidence,
                    file_path=str(file_path),
                    line_start=line_num,
                    line_end=min(line_num + 1, len(lines)),
                    code_snippet=snippet,
                    description=rule.description,
                    remediation=rule.remediation,
                ))

        return findings

    def scan_project(self, project_dir: str | Path) -> list[Finding]:
        """扫描整个项目目录"""
        files = self.collect_files(project_dir)
        all_findings: list[Finding] = []
        for f in files:
            all_findings.extend(self.scan_file(f))
        return all_findings

    async def scan_project_with_llm(
        self,
        project_dir: str | Path,
        llm_client: Any,
        max_llm_calls: int = 50,
        on_progress: Any = None,
    ) -> list[Finding]:
        """扫描项目并使用 LLM 交叉验证结果

        流程：正则扫描 -> 按严重程度排序 -> 取 top-N 送 LLM 验证
        这样可以控制 LLM API 调用成本，同时大幅降低误报率
        """
        import json
        import sys

        findings = self.scan_project(project_dir)

        # 按严重程度排序（Critical > High > Medium > Low > Info）
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        findings.sort(key=lambda f: severity_order.get(f.severity, 5))

        # 取前 N 条送 LLM 验证
        to_verify = findings[:max_llm_calls]
        total = len(to_verify)

        if total == 0:
            return findings

        # ---- 连通性测试：先发一个轻量请求确认 API 可用 ----
        _log = on_progress or (lambda msg: print(msg, file=sys.stderr))
        _log(f"[*] LLM cross-validation: {total} findings queued")
        _log("[*] Testing API connectivity...")
        try:
            test_resp = await llm_client.chat(
                [{"role": "user", "content": "respond OK"}],
                max_tokens=8,
            )
            _log(f"[+] API connected (response: {test_resp.strip()[:20]})")
        except Exception as e:
            _log(f"[-] API connection FAILED: {e}")
            _log("[!] Falling back to regex-only mode (no LLM verification)")
            return findings

        # ---- 逐条验证 ----
        verified_count = 0
        failed_count = 0

        async def verify_finding(idx: int, finding: Finding) -> Finding:
            nonlocal verified_count, failed_count
            try:
                language = "unknown"
                for lang, exts in LANG_EXTENSIONS.items():
                    if Path(finding.file_path).suffix in exts:
                        language = lang
                        break

                result_json = await llm_client.analyze_code(
                    code=finding.code_snippet,
                    language=language,
                    context=f"文件: {finding.file_path}, 规则命中: {finding.rule_id} ({finding.title})",
                )
                result = json.loads(result_json)
                llm_findings = result.get("findings", [])

                if llm_findings:
                    finding.llm_verified = True
                    finding.llm_analysis = result.get("summary", "LLM confirmed")
                    verified_count += 1
                else:
                    finding.llm_verified = False
                    finding.llm_analysis = "LLM: likely false positive"
                    finding.confidence = "Low"

                _log(f"    [{idx+1}/{total}] {finding.rule_id} {finding.title} -> {'CONFIRMED' if finding.llm_verified else 'UNCONFIRMED'}")

            except json.JSONDecodeError:
                finding.llm_analysis = "LLM returned invalid JSON"
                failed_count += 1
                _log(f"    [{idx+1}/{total}] {finding.rule_id} -> JSON parse error")
            except Exception as e:
                finding.llm_analysis = f"LLM error: {e}"
                failed_count += 1
                _log(f"    [{idx+1}/{total}] {finding.rule_id} -> ERROR: {e}")

            return finding

        # 并发度限制为 3，避免 API rate limit
        sem = asyncio.Semaphore(3)

        async def throttled_verify(idx: int, finding: Finding) -> Finding:
            async with sem:
                return await verify_finding(idx, finding)

        verified = await asyncio.gather(
            *[throttled_verify(i, f) for i, f in enumerate(to_verify)]
        )

        _log(f"[+] LLM verification complete: {verified_count} confirmed, {failed_count} errors, {total - verified_count - failed_count} unconfirmed")

        # 合并：已验证的 + 未验证的
        verified_ids = {id(f) for f in to_verify}
        result = list(verified)
        result.extend(f for f in findings if id(f) not in verified_ids)

        return result
