"""Hybrid Scanning Engine - 主入口

混合型漏洞扫描引擎：Rust 高并发探测 + Python LLM 推理
用于开发者对自身项目/网站进行自动化安全测试
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from orchestrator.config import AppConfig
from orchestrator.dast.scanner_bridge import ScannerBridge
from orchestrator.llm.client import DeepSeekClient
from orchestrator.reasoning.vuln_reasoner import VulnReasoner
from orchestrator.report.generator import ReportGenerator
from orchestrator.sast.analyzer import SASTAnalyzer

app = typer.Typer(
    name="hybrid-scanner",
    help="Hybrid Scanning Engine - 混合型漏洞扫描引擎",
    add_completion=False,
)
console = Console()


def load_config(config_path: str) -> AppConfig:
    """加载配置文件"""
    return AppConfig.from_yaml(config_path)


@app.command("sast")
def cmd_sast(
    project_dir: str = typer.Argument(..., help="待扫描的项目目录路径"),
    config_path: str = typer.Option("./config.yaml", "--config", "-c", help="配置文件路径"),
    use_llm: bool = typer.Option(False, "--llm", help="启用 LLM 交叉验证 (deepseek-chat)"),
    reasoning: bool = typer.Option(False, "--reasoning", "-r", help="使用深度思考模型 (deepseek-reasoner / R1)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="报告输出目录"),
) -> None:
    """SAST - 静态代码安全分析"""
    config = load_config(config_path)
    if output:
        config.report_output_dir = output
    if reasoning:
        config.llm.model = "deepseek-reasoner"
        use_llm = True

    asyncio.run(_run_sast(config, project_dir, use_llm))


@app.command("dast")
def cmd_dast(
    target_url: str = typer.Argument(..., help="目标 URL（如 http://localhost:8080）"),
    config_path: str = typer.Option("./config.yaml", "--config", "-c", help="配置文件路径"),
    port_scan: bool = typer.Option(False, "--ports", "-p", help="执行端口扫描"),
    port_range: str = typer.Option("1-1024", "--port-range", help="端口范围（如 1-65535）"),
    dir_bust: bool = typer.Option(True, "--dirs", "-d", help="执行目录爆破"),
    fingerprint: bool = typer.Option(True, "--fingerprint", "-f", help="执行指纹识别"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="报告输出目录"),
) -> None:
    """DAST - 动态扫描分析 (需先编译 Rust 扫描引擎)"""
    config = load_config(config_path)
    if output:
        config.report_output_dir = output

    asyncio.run(_run_dast(config, target_url, port_scan, port_range, dir_bust, fingerprint))


@app.command("full")
def cmd_full(
    target_url: str = typer.Argument(..., help="目标 URL"),
    project_dir: str = typer.Argument(..., help="项目源代码目录"),
    config_path: str = typer.Option("./config.yaml", "--config", "-c", help="配置文件路径"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="报告输出目录"),
) -> None:
    """FULL - 全量扫描 (SAST + DAST + LLM 交叉关联)"""
    config = load_config(config_path)
    if output:
        config.report_output_dir = output

    asyncio.run(_run_full(config, target_url, project_dir))


@app.command("init")
def cmd_init(
    config_path: str = typer.Option("./config.yaml", "--config", "-c", help="配置文件路径"),
) -> None:
    """INIT - 生成默认配置文件"""
    config = AppConfig()
    config.to_yaml(config_path)
    console.print(f"[green][+] 已生成默认配置文件: {config_path}[/green]")
    console.print("[yellow][!] 请编辑配置文件，填入 DeepSeek API Key[/yellow]")


# ============================================================
# 内部异步执行逻辑
# ============================================================

async def _run_sast(config: AppConfig, project_dir: str, use_llm: bool) -> None:
    """执行 SAST 扫描"""
    _print_banner()
    console.print(Panel("SAST :: Static Application Security Testing", style="bold blue"))

    analyzer = SASTAnalyzer(config.sast)

    files = analyzer.collect_files(project_dir)
    console.print(f"[*] Collected {len(files)} source files from [bold]{project_dir}[/bold]")

    if use_llm and config.llm.api_key:
        llm_client = DeepSeekClient(config.llm)
        console.print(f"[*] Mode: regex scan + LLM cross-validation [bold]({llm_client.model_name})[/bold]")

        def _llm_log(msg: str) -> None:
            console.print(f"[dim]{msg}[/dim]")

        findings = await analyzer.scan_project_with_llm(
            project_dir, llm_client, on_progress=_llm_log,
        )
    else:
        if use_llm and not config.llm.api_key:
            console.print("[yellow][!] --llm specified but no API key in config.yaml[/yellow]")
        console.print("[*] Mode: regex-only scan")
        findings = analyzer.scan_project(project_dir)

    console.print(f"[bold][+] Scan complete: {len(findings)} potential issues identified[/bold]")

    _print_findings_table(findings)

    # 生成报告
    llm_client = DeepSeekClient(config.llm) if config.llm.api_key else None
    generator = ReportGenerator(config.report_output_dir, llm_client)
    findings_dicts = [f.to_dict() if hasattr(f, "to_dict") else f for f in findings]
    report_path = await generator.generate(
        target=project_dir,
        findings=findings_dicts,
        config=config.model_dump(),
    )
    console.print(f"\n[green][+] Report saved: {report_path}[/green]")


async def _run_dast(
    config: AppConfig,
    target_url: str,
    do_port_scan: bool,
    port_range: str,
    do_dir_bust: bool,
    do_fingerprint: bool,
) -> None:
    """执行 DAST 扫描"""
    _print_banner()
    console.print(Panel("DAST :: Dynamic Application Security Testing", style="bold green"))

    fingerprint_data: dict = {}
    open_ports: list = []
    found_paths: list = []

    try:
        async with ScannerBridge(config.scanner) as bridge:
            if do_fingerprint:
                console.print("[bold][*] Fingerprinting target...[/bold]")
                fingerprint_data = await bridge.fingerprint(target_url)
                _print_fingerprint(fingerprint_data)

            if do_port_scan:
                parts = port_range.split("-")
                start, end = int(parts[0]), int(parts[1])
                console.print(f"[bold][*] Port scanning ({start}-{end})...[/bold]")
                result = await bridge.port_scan(
                    target=target_url.split("://")[-1].split("/")[0].split(":")[0],
                    port_start=start,
                    port_end=end,
                )
                open_ports = result.get("open_ports", [])
                console.print(f"    [+] {len(open_ports)} open ports detected")

            if do_dir_bust:
                console.print("[bold][*] Directory bruteforcing...[/bold]")
                result = await bridge.dir_bust(target_url)
                found_paths = result.get("found_paths", [])
                console.print(f"    [+] {len(found_paths)} valid paths discovered")

    except FileNotFoundError as e:
        console.print(f"[red][-] FATAL: {e}[/red]")
        return

    # LLM 分析
    dast_analysis = None
    if config.llm.api_key and (fingerprint_data or open_ports or found_paths):
        console.print("[bold][*] LLM reasoning engine engaged...[/bold]")
        llm_client = DeepSeekClient(config.llm)
        reasoner = VulnReasoner(llm_client)
        dast_analysis = await reasoner.analyze_dast_results(
            fingerprint=fingerprint_data,
            open_ports=open_ports,
            found_paths=found_paths,
        )

    # 生成报告
    llm_client = DeepSeekClient(config.llm) if config.llm.api_key else None
    generator = ReportGenerator(config.report_output_dir, llm_client)
    report_path = await generator.generate(
        target=target_url,
        findings=[],
        dast_analysis=dast_analysis,
        config=config.model_dump(),
    )
    console.print(f"\n[green][+] Report saved: {report_path}[/green]")


async def _run_full(config: AppConfig, target_url: str, project_dir: str) -> None:
    """执行全量扫描：SAST + DAST + 交叉关联"""
    _print_banner()
    console.print(Panel("FULL ASSESSMENT :: SAST + DAST + LLM Correlation", style="bold magenta"))

    if not config.llm.api_key:
        console.print("[yellow][!] LLM API Key not configured, skipping LLM analysis[/yellow]")

    # ---- SAST ----
    console.print("\n[bold blue]--- Phase 1: SAST Static Analysis ---[/bold blue]")
    analyzer = SASTAnalyzer(config.sast)

    if config.llm.api_key:
        llm_client = DeepSeekClient(config.llm)
        sast_findings = await analyzer.scan_project_with_llm(project_dir, llm_client)
    else:
        sast_findings = analyzer.scan_project(project_dir)
        llm_client = None

    sast_dicts = [f.to_dict() if hasattr(f, "to_dict") else f for f in sast_findings]
    console.print(f"    [+] SAST identified {len(sast_dicts)} potential issues")

    # ---- DAST ----
    console.print("\n[bold green]--- Phase 2: DAST Dynamic Scanning ---[/bold green]")
    fingerprint_data: dict = {}
    open_ports: list = []
    found_paths: list = []
    dast_analysis = None

    try:
        async with ScannerBridge(config.scanner) as bridge:
            fingerprint_data = await bridge.fingerprint(target_url)
            _print_fingerprint(fingerprint_data)

            result = await bridge.dir_bust(target_url)
            found_paths = result.get("found_paths", [])
            console.print(f"    [+] {len(found_paths)} valid paths discovered")
    except FileNotFoundError as e:
        console.print(f"[yellow][!] DAST skipped: {e}[/yellow]")

    # ---- LLM 综合推理 ----
    correlation = None
    if llm_client:
        console.print("\n[bold magenta]--- Phase 3: LLM Cross-Correlation ---[/bold magenta]")
        reasoner = VulnReasoner(llm_client)

        if fingerprint_data or found_paths:
            dast_analysis = await reasoner.analyze_dast_results(
                fingerprint=fingerprint_data,
                open_ports=open_ports,
                found_paths=found_paths,
            )

        if sast_dicts and dast_analysis:
            correlation = await reasoner.correlate_findings(sast_dicts, dast_analysis)

    # ---- 报告 ----
    console.print("\n[bold]--- Generating Report ---[/bold]")
    generator = ReportGenerator(config.report_output_dir, llm_client)
    report_path = await generator.generate(
        target=f"{target_url} | {project_dir}",
        findings=sast_dicts,
        dast_analysis=dast_analysis,
        correlation=correlation,
        config=config.model_dump(),
    )
    console.print(f"\n[green][+] Report saved: {report_path}[/green]")


# ============================================================
# 输出辅助函数
# ============================================================

def _print_banner() -> None:
    """打印专业化启动横幅"""
    banner = (
        "[bold white]"
        "\n"
        "  ╦ ╦╦ ╦╔╗ ╦═╗╦╔╦╗  ╔═╗╔═╗╔═╗╔╗╔╔╗╔╔═╗╦═╗\n"
        "  ╠═╣╚╦╝╠╩╗╠╦╝║ ║║  ╚═╗║  ╠═╣║║║║║║║╣ ╠╦╝\n"
        "  ╩ ╩ ╩ ╚═╝╩╚═╩═╩╝  ╚═╝╚═╝╩ ╩╝╚╝╝╚╝╚═╝╩╚═\n"
        "[/bold white]"
        "[dim]  Hybrid Scanning Engine v0.1.0[/dim]\n"
        "[dim]  Rust Concurrency Layer + Python LLM Reasoning[/dim]\n"
    )
    console.print(banner)


def _print_findings_table(findings: list) -> None:
    """以表格形式展示漏洞发现"""
    if not findings:
        console.print("[green][+] No vulnerabilities detected.[/green]")
        return

    table = Table(title="Vulnerability Findings", show_lines=True)
    table.add_column("ID", style="cyan", width=10)
    table.add_column("SEVERITY", width=10)
    table.add_column("TITLE", width=28)
    table.add_column("FILE", width=35)
    table.add_column("LINE", width=8)
    table.add_column("LLM", width=8)

    severity_colors = {
        "Critical": "bold red",
        "High": "red",
        "Medium": "yellow",
        "Low": "green",
        "Info": "blue",
    }

    for f in findings:
        if hasattr(f, "to_dict"):
            d = f.to_dict()
        else:
            d = f

        sev = d.get("severity", "Info")
        color = severity_colors.get(sev, "white")
        llm_mark = "PASS" if d.get("llm_verified") else "--"

        table.add_row(
            d.get("rule_id", ""),
            f"[{color}]{sev}[/{color}]",
            d.get("title", ""),
            d.get("file_path", "")[-30:],
            str(d.get("line_start", "")),
            llm_mark,
        )

    console.print(table)


def _print_fingerprint(data: dict) -> None:
    """展示指纹识别结果"""
    if data.get("type") == "error":
        console.print(f"[red]    [-] Fingerprint failed: {data.get('message')}[/red]")
        return

    console.print(f"    [+] HTTP {data.get('status_code', '?')}")
    if data.get("server"):
        console.print(f"    [+] Server: {data['server']}")

    techs = data.get("technologies", [])
    if techs:
        console.print("    [+] Technology stack:")
        for t in techs:
            ver = f" v{t['version']}" if t.get("version") else ""
            conf = f"{t['confidence']:.0%}"
            console.print(f"        | {t['name']}{ver} (confidence: {conf})")


if __name__ == "__main__":
    app()
