"""SAST 静态分析引擎 - 双引擎架构（正则快扫 + LLM 深度审计）"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
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
    source: str = "regex"       # "regex" | "llm" | "both"

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
            "source": self.source,
        }


# 语言 -> 文件扩展名映射
LANG_EXTENSIONS: dict[str, list[str]] = {
    "python": [".py"],
    "javascript": [".js", ".jsx", ".ts", ".tsx"],
    "php": [".php"],
    "java": [".java"],
    "go": [".go"],
    "rust": [".rs"],
    "cpp": [".c", ".cpp", ".cxx", ".cc", ".h", ".hpp"],
    "csharp": [".cs"],
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

        # 第三方压缩库后缀，跳过以减少误报
        VENDOR_SUFFIXES = (".min.js", ".min.css", ".bundle.js", ".chunk.js")

        files: list[Path] = []
        for f in project_path.rglob("*"):
            # 跳过排除目录
            if any(excluded in f.parts for excluded in self._config.exclude_dirs):
                continue
            if f.is_file() and f.suffix in target_exts:
                # 跳过第三方压缩/打包文件
                if f.name.endswith(VENDOR_SUFFIXES):
                    continue
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

    # ================================================================
    # LLM 独立深度审计
    # ================================================================

    async def llm_audit_file(
        self,
        file_path: Path,
        llm_client: Any,
    ) -> list[Finding]:
        """用 LLM 对单个文件进行独立深度审计，不依赖正则规则"""
        import json

        language = self.detect_language(file_path) or "unknown"
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        # 大文件分块：每块最多 400 行，复用 20 行上下文
        chunks = self._split_into_chunks(content, max_lines=400, overlap=20)
        all_findings: list[Finding] = []

        for chunk_code, line_offset in chunks:
            try:
                result_json = await llm_client.deep_audit_file(
                    code=chunk_code,
                    language=language,
                    file_path=str(file_path),
                )
                # LLM 可能返回 markdown 包裹的 JSON
                result_json = self._extract_json(result_json)
                result = json.loads(result_json)
                for f in result.get("findings", []):
                    line_start = f.get("line_start", 0) + line_offset
                    line_end = f.get("line_end", line_start) + line_offset
                    all_findings.append(Finding(
                        rule_id="LLM-AUDIT",
                        cwe=f.get("cwe", "CWE-000"),
                        title=f.get("title", "LLM-discovered vulnerability"),
                        severity=f.get("severity", "Medium"),
                        confidence=f.get("confidence", "Medium"),
                        file_path=str(file_path),
                        line_start=line_start,
                        line_end=line_end,
                        code_snippet=f.get("code_snippet", ""),
                        description=f.get("description", ""),
                        remediation=f.get("remediation", ""),
                        llm_verified=True,
                        llm_analysis=f.get("impact", "LLM deep audit finding"),
                        source="llm",
                    ))
            except json.JSONDecodeError:
                continue
            except Exception:
                continue

        return all_findings

    @staticmethod
    def _split_into_chunks(
        content: str, max_lines: int = 400, overlap: int = 20
    ) -> list[tuple[str, int]]:
        """将文件内容分块，返回 (chunk_text, line_offset) 列表"""
        lines = content.splitlines(keepends=True)
        if len(lines) <= max_lines:
            return [(content, 0)]

        chunks: list[tuple[str, int]] = []
        start = 0
        while start < len(lines):
            end = min(start + max_lines, len(lines))
            chunk = "".join(lines[start:end])
            chunks.append((chunk, start))
            start = end - overlap
            if start + overlap >= len(lines):
                break
        return chunks

    @staticmethod
    def _extract_json(text: str) -> str:
        """从 LLM 响应中提取 JSON（处理 markdown 代码块包裹）"""
        import re
        # 尝试提取 ```json ... ``` 中的内容
        m = re.search(r"```(?:json)?\s*\n?(\{.*?\})\s*```", text, re.DOTALL)
        if m:
            return m.group(1)
        # 尝试直接找第一个 { ... }
        m = re.search(r"(\{.*\})", text, re.DOTALL)
        if m:
            return m.group(1)
        return text

    # ================================================================
    # 双引擎主流程
    # ================================================================

    @staticmethod
    def _merge_findings(
        regex_findings: list[Finding],
        llm_findings: list[Finding],
    ) -> list[Finding]:
        """合并正则 + LLM 发现，按 (文件, 行号±5, CWE) 去重"""
        merged: list[Finding] = []
        used_llm: set[int] = set()

        for rf in regex_findings:
            matched_llm = False
            for i, lf in enumerate(llm_findings):
                if i in used_llm:
                    continue
                # 同文件、行号相近、同 CWE 视为重复
                same_file = Path(rf.file_path).name == Path(lf.file_path).name
                near_line = abs(rf.line_start - lf.line_start) <= 5
                same_cwe = rf.cwe == lf.cwe
                if same_file and near_line and same_cwe:
                    # 合并：保留正则的规则ID，加上 LLM 的深度分析
                    rf.llm_verified = True
                    rf.llm_analysis = lf.description or lf.llm_analysis
                    rf.source = "both"
                    used_llm.add(i)
                    matched_llm = True
                    break
            merged.append(rf)

        # LLM 独立发现的（正则没捕获到的）
        for i, lf in enumerate(llm_findings):
            if i not in used_llm:
                merged.append(lf)

        return merged

    async def scan_project_with_llm(
        self,
        project_dir: str | Path,
        llm_client: Any,
        max_llm_calls: int = 50,
        on_progress: Any = None,
    ) -> list[Finding]:
        """双引擎扫描：正则快扫 + LLM 深度审计 -> 合并去重

        流程：
        1. 正则引擎快速扫描所有文件
        2. LLM 引擎独立对每个文件做深度语义审计
        3. 合并两个引擎的结果，按文件+行号+CWE 去重
        4. 正则+LLM 共同发现 -> source=both（高置信）
           仅正则发现 -> source=regex
           仅 LLM 发现 -> source=llm（正则无法覆盖的逻辑漏洞）
        """
        import sys

        _log = on_progress or (lambda msg: print(msg, file=sys.stderr))

        # ---- 连通性测试 ----
        _log("[*] Testing API connectivity...")
        try:
            test_resp = await llm_client.chat(
                [{"role": "user", "content": "respond OK"}],
                max_tokens=8,
            )
            _log(f"[+] API connected ({llm_client.model_name})")
        except Exception as e:
            _log(f"[-] API connection FAILED: {e}")
            _log("[!] Falling back to regex-only mode")
            return self.scan_project(project_dir)

        files = self.collect_files(project_dir)

        # ==== Engine 1: 正则快扫 ====
        _log(f"[*] Engine 1/2: Regex fast scan ({len(files)} files)...")
        regex_findings = self.scan_project(project_dir)
        _log(f"    -> {len(regex_findings)} pattern matches")

        # ==== Engine 2: LLM 深度审计 ====
        _log(f"[*] Engine 2/2: LLM deep audit ({len(files)} files)...")
        sem = asyncio.Semaphore(2)  # LLM 审计并发度限制

        llm_findings_all: list[Finding] = []
        audit_errors = 0

        async def audit_one_file(idx: int, fp: Path) -> list[Finding]:
            nonlocal audit_errors
            async with sem:
                try:
                    results = await self.llm_audit_file(fp, llm_client)
                    status = f"{len(results)} vulns" if results else "clean"
                    _log(f"    [{idx+1}/{len(files)}] {fp.name} -> {status}")
                    return results
                except Exception as e:
                    audit_errors += 1
                    _log(f"    [{idx+1}/{len(files)}] {fp.name} -> ERROR: {e}")
                    return []

        tasks = [audit_one_file(i, f) for i, f in enumerate(files)]
        results_per_file = await asyncio.gather(*tasks)
        for file_findings in results_per_file:
            llm_findings_all.extend(file_findings)

        _log(f"    -> {len(llm_findings_all)} LLM-discovered issues ({audit_errors} errors)")

        # ==== 合并去重 ====
        _log("[*] Merging results (deduplication by file + line + CWE)...")
        merged = self._merge_findings(regex_findings, llm_findings_all)

        # 统计
        src_both = sum(1 for f in merged if f.source == "both")
        src_regex = sum(1 for f in merged if f.source == "regex")
        src_llm = sum(1 for f in merged if f.source == "llm")
        _log(f"[+] Final: {len(merged)} findings (regex={src_regex}, llm={src_llm}, both={src_both})")

        # 排序
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        merged.sort(key=lambda f: severity_order.get(f.severity, 5))

        return merged
