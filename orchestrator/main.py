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
from orchestrator.iac.scanner import DockerfileScanner, KubernetesScanner
from orchestrator.api.parser import OpenAPIParser
from orchestrator.api.scanner import APIScanner
from orchestrator.llm.client import DeepSeekClient
from orchestrator.reasoning.vuln_reasoner import VulnReasoner
from orchestrator.report.generator import ReportGenerator
from orchestrator.sast.analyzer import SASTAnalyzer
from orchestrator.sca.parser import DependencyParser

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
    use_llm: bool = typer.Option(False, "--llm", help="启用 LLM 双引擎 (DeepSeek-V3.2 非思考)"),
    reasoning: bool = typer.Option(False, "--reasoning", "-r", help="使用 DeepSeek-V3.2 思考模式"),
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
    active_scan: bool = typer.Option(False, "--active", "-a", help="执行主动漏洞扫描 (SQLi, XSS, CMDi)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="报告输出目录"),
) -> None:
    """DAST - 动态扫描分析 (需先编译 Rust 扫描引擎)"""
    config = load_config(config_path)
    if output:
        config.report_output_dir = output

    asyncio.run(_run_dast(config, target_url, port_scan, port_range, dir_bust, fingerprint, active_scan))


@app.command("full")
def cmd_full(
    target_url: str = typer.Argument(..., help="目标 URL"),
    project_dir: str = typer.Argument(..., help="项目源代码目录"),
    config_path: str = typer.Option("./config.yaml", "--config", "-c", help="配置文件路径"),
    active_scan: bool = typer.Option(True, "--active", "-a", help="执行主动漏洞扫描 (SQLi, XSS, CMDi)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="报告输出目录"),
) -> None:
    """FULL - 全量扫描 (SAST + DAST + LLM 交叉关联)"""
    config = load_config(config_path)
    if output:
        config.report_output_dir = output

    asyncio.run(_run_full(config, target_url, project_dir, active_scan))


@app.command("api")
def cmd_api(
    spec_path: str = typer.Argument(..., help="OpenAPI/Swagger 规范文件路径"),
    target_url: Optional[str] = typer.Option(None, help="目标 API 基础 URL (覆盖 spec 中的 server)"),
    config_path: str = typer.Option("./config.yaml", "--config", "-c", help="配置文件路径"),
    use_llm: bool = typer.Option(False, "--llm", help="启用 LLM 辅助生成 Payload"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="报告输出目录"),
) -> None:
    """API - 接口安全测试 (BOLA, IDOR, Injection)"""
    config = load_config(config_path)
    if output:
        config.report_output_dir = output
    
    asyncio.run(_run_api(config, spec_path, target_url, use_llm))


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

async def _run_api(config: AppConfig, spec_path: str, target_url: Optional[str], use_llm: bool) -> None:
    """执行 API 安全扫描"""
    _print_banner()
    console.print(Panel("API Security Testing :: BOLA/IDOR + Logic Analysis", style="bold magenta"))

    try:
        parser = OpenAPIParser(spec_path)
        endpoints = parser.get_endpoints()
        base_url = target_url or parser.get_base_url()
        
        if not base_url:
            console.print("[red][!] No base URL found in spec or provided via --target-url[/red]")
            return

        console.print(f"[*] Parsed {len(endpoints)} endpoints from [bold]{spec_path}[/bold]")
        console.print(f"[*] Target Base URL: [bold]{base_url}[/bold]")

        llm_client = None
        if use_llm and config.llm.api_key:
            llm_client = DeepSeekClient(config.llm)
            console.print(f"[*] LLM Logic Analysis: [green]Enabled ({llm_client.model_name})[/green]")
        elif use_llm and not config.llm.api_key:
            console.print("[yellow][!] --llm specified but no API key in config.yaml[/yellow]")
            console.print("[*] LLM Logic Analysis: [dim]Disabled[/dim]")
        else:
            console.print("[*] LLM Logic Analysis: [dim]Disabled[/dim]")

        scanner = APIScanner(base_url, llm_client)
        findings = await scanner.scan_spec(endpoints)
        await scanner.close()

        console.print(f"[bold][+] API Scan complete: {len(findings)} potential issues identified[/bold]")
        _print_findings_table(findings)

        # Generate Report
        generator = ReportGenerator(config.report_output_dir, llm_client)
        report_path = await generator.generate(
            target=f"API: {base_url}",
            findings=findings,
            config=config.model_dump(),
        )
        console.print(f"\n[green][+] Report saved: {report_path}[/green]")

    except Exception as e:
        console.print(f"[red][-] API Scan Failed: {e}[/red]")


async def _run_sca(config: AppConfig, project_dir: str, llm_client: Optional[DeepSeekClient]) -> list[dict]:
    """执行 SCA 依赖安全扫描"""
    if not config.sca.enabled:
        return []
    
    console.print(Panel("Phase: SCA (Software Composition Analysis)", style="bold cyan"))
    findings = []
    p_dir = Path(project_dir)
    
    # 1. 发现依赖文件
    dep_files = DependencyParser.detect_files(p_dir)
    if not dep_files:
        console.print("[dim]No dependency files found (package.json, requirements.txt)[/dim]")
        return []
        
    console.print(f"[*] Found {len(dep_files)} dependency files")
    
    for f in dep_files:
        ecosystem = "npm"
        deps = {}
        
        if f.name == "package.json":
            ecosystem = "npm"
            deps = DependencyParser.parse_package_json(f)
        elif f.name == "requirements.txt":
            ecosystem = "pypi"
            deps = DependencyParser.parse_requirements_txt(f)
        elif f.name == "composer.json":
            ecosystem = "packagist"
            deps = DependencyParser.parse_composer_json(f)
        elif f.name == "go.mod":
            ecosystem = "go"
            deps = DependencyParser.parse_go_mod(f)
        elif f.name == "Cargo.toml":
            ecosystem = "crates.io"
            deps = DependencyParser.parse_cargo_toml(f)
        elif f.name == "pom.xml":
            ecosystem = "maven"
            deps = DependencyParser.parse_pom_xml(f)
        elif f.suffix == ".csproj":
            ecosystem = "nuget"
            deps = DependencyParser.parse_csproj(f)
            
        if not deps:
            continue
            
        console.print(f"    [+] {f.name}: {len(deps)} dependencies parsed")
        
        # 仅当有 LLM 时进行漏洞分析
        if llm_client and deps:
            console.print(f"    [*] Analyzing {f.name} with LLM...")
            try:
                result_json = await llm_client.analyze_dependencies(deps, ecosystem)
                data = json.loads(result_json)
                for item in data.get("findings", []):
                    findings.append({
                        "rule_id": "SCA-VULN",
                        "title": item.get("title", "Known Vulnerability"),
                        "severity": item.get("severity", "High"),
                        "file_path": str(f),
                        "line_start": 0,
                        "line_end": 0,
                        "code_snippet": f"{item.get('package')}@{item.get('version')}",
                        "description": item.get("description", "") + f"\nVuln ID: {item.get('vuln_id')}",
                        "remediation": item.get("remediation", ""),
                        "source": "llm-sca",
                        "llm_verified": True
                    })
            except Exception as e:
                console.print(f"[red][!] SCA LLM analysis failed for {f.name}: {e}[/red]")
    
    console.print(f"    [+] SCA identified {len(findings)} issues")
    return findings


async def _run_iac(config: AppConfig, project_dir: str, llm_client: Optional[DeepSeekClient]) -> list[dict]:
    """执行 IaC 基础设施即代码扫描"""
    if not config.iac.enabled:
        return []

    console.print(Panel("Phase: IaC (Infrastructure as Code)", style="bold yellow"))
    findings = []
    p_dir = Path(project_dir)
    
    # ---- Dockerfile Scanning ----
    docker_scanner = DockerfileScanner()
    docker_files = docker_scanner.detect_files(p_dir)
    
    if docker_files:
        console.print(f"[*] Found {len(docker_files)} Dockerfiles")
        for f in docker_files:
            # 1. 正则规则扫描
            regex_findings = docker_scanner.scan(f)
            findings.extend(regex_findings)
            
            # 2. LLM 深度审计
            if llm_client:
                console.print(f"    [*] Auditing {f.name} with LLM...")
                try:
                    content = f.read_text(encoding="utf-8")
                    result_json = await llm_client.audit_iac_config(content, "Dockerfile")
                    data = json.loads(result_json)
                    for item in data.get("findings", []):
                        findings.append({
                            "rule_id": item.get("id", "IAC-LLM"),
                            "title": item.get("title", "IaC Misconfiguration"),
                            "severity": item.get("severity", "Medium"),
                            "file_path": str(f),
                            "line_start": item.get("line", 0),
                            "line_end": item.get("line", 0),
                            "code_snippet": "...",
                            "description": item.get("description", ""),
                            "remediation": item.get("remediation", ""),
                            "source": "llm-iac",
                            "llm_verified": True
                        })
                except Exception as e:
                     console.print(f"[red][!] IaC LLM audit failed for {f.name}: {e}[/red]")

    # ---- Kubernetes Scanning ----
    k8s_scanner = KubernetesScanner()
    k8s_files = k8s_scanner.detect_files(p_dir)

    if k8s_files:
        console.print(f"[*] Found {len(k8s_files)} Kubernetes manifests")
        for f in k8s_files:
            # 1. Regex Scan
            regex_findings = k8s_scanner.scan(f)
            findings.extend(regex_findings)

            # 2. LLM Audit
            if llm_client:
                console.print(f"    [*] Auditing {f.name} with LLM...")
                try:
                    content = f.read_text(encoding="utf-8")
                    result_json = await llm_client.audit_iac_config(content, "Kubernetes Manifest")
                    data = json.loads(result_json)
                    for item in data.get("findings", []):
                        findings.append({
                            "rule_id": item.get("id", "IAC-K8S-LLM"),
                            "title": item.get("title", "K8s Misconfiguration"),
                            "severity": item.get("severity", "Medium"),
                            "file_path": str(f),
                            "line_start": item.get("line", 0),
                            "line_end": item.get("line", 0),
                            "code_snippet": "...",
                            "description": item.get("description", ""),
                            "remediation": item.get("remediation", ""),
                            "source": "llm-iac",
                            "llm_verified": True
                        })
                except Exception as e:
                     console.print(f"[red][!] K8s LLM audit failed for {f.name}: {e}[/red]")

    if not findings:
        console.print("[dim]No IaC issues found[/dim]")

    console.print(f"    [+] IaC identified {len(findings)} issues")
    return findings


async def _run_sast(config: AppConfig, project_dir: str, use_llm: bool) -> None:
    """执行 SAST 扫描 (包含 SCA + IaC)"""
    _print_banner()
    console.print(Panel("SAST :: Static Application Security Testing", style="bold blue"))

    analyzer = SASTAnalyzer(config.sast)

    files = analyzer.collect_files(project_dir)
    console.print(f"[*] Collected {len(files)} source files from [bold]{project_dir}[/bold]")

    llm_client = None
    if use_llm and config.llm.api_key:
        llm_client = DeepSeekClient(config.llm)
        console.print(f"[*] Mode: [bold]Dual-Engine[/bold] (Regex + LLM Deep Audit) [{llm_client.model_name}]")
    elif use_llm and not config.llm.api_key:
        console.print("[yellow][!] --llm specified but no API key in config.yaml[/yellow]")
        console.print("[*] Mode: regex-only scan")
    else:
        console.print("[*] Mode: regex-only scan")

    # 1. Code SAST
    if llm_client:
        def _llm_log(msg: str) -> None:
            console.print(f"[dim]{msg}[/dim]")
        sast_findings = await analyzer.scan_project_with_llm(
            project_dir, llm_client, on_progress=_llm_log,
        )
    else:
        sast_findings = analyzer.scan_project(project_dir)

    # 转换 SAST findings 为 dict
    all_findings = [f.to_dict() if hasattr(f, "to_dict") else f for f in sast_findings]

    # 2. SCA
    if config.sca.enabled:
        sca_findings = await _run_sca(config, project_dir, llm_client)
        all_findings.extend(sca_findings)

    # 3. IaC
    if config.iac.enabled:
        iac_findings = await _run_iac(config, project_dir, llm_client)
        all_findings.extend(iac_findings)

    console.print(f"[bold][+] Scan complete: {len(all_findings)} potential issues identified[/bold]")

    _print_findings_table(all_findings)

    # 生成报告
    generator = ReportGenerator(config.report_output_dir, llm_client)
    report_path = await generator.generate(
        target=project_dir,
        findings=all_findings,
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
    do_active_scan: bool,
) -> None:
    """执行 DAST 扫描"""
    _print_banner()
    console.print(Panel("DAST :: Dynamic Application Security Testing", style="bold green"))

    fingerprint_data: dict = {}
    open_ports: list = []
    found_paths: list = []
    active_vulns: list = []

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

            if do_active_scan:
                console.print("[bold][*] Active Vulnerability Scanning (SQLi, XSS, CMDi)...[/bold]")
                # 针对发现的每个路径都尝试进行漏洞扫描（如果路径带有参数）
                # 这里简化处理，直接对 target_url 进行扫描，如果 target_url 只是根目录，
                # 可能需要结合 found_paths 中的结果。
                # 暂时只扫描用户提供的 target_url (假设带有参数) + 发现的有参数的路径
                
                targets_to_scan = {target_url}
                for path_entry in found_paths:
                    path = path_entry.get("path", "")
                    if "?" in path:
                         # 拼接完整 URL
                        full_url = target_url.rstrip("/") + "/" + path.lstrip("/")
                        targets_to_scan.add(full_url)
                
                console.print(f"    [*] Scanning {len(targets_to_scan)} endpoints...")
                
                for url in targets_to_scan:
                    res = await bridge.active_scan(url)
                    vulns = res.get("vulnerabilities", [])
                    if vulns:
                        active_vulns.extend(vulns)
                        for v in vulns:
                            console.print(f"    [red][!] Found {v['name']} at {v['location']}[/red]")
                
                if not active_vulns:
                     console.print("    [green][+] No active vulnerabilities found via payloads[/green]")

    except FileNotFoundError as e:
        console.print(f"[red][-] FATAL: {e}[/red]")
        return

    # LLM 分析
    dast_analysis = None
    if config.llm.api_key and (fingerprint_data or open_ports or found_paths or active_vulns):
        console.print("[bold][*] LLM reasoning engine engaged...[/bold]")
        llm_client = DeepSeekClient(config.llm)
        reasoner = VulnReasoner(llm_client)
        dast_analysis = await reasoner.analyze_dast_results(
            fingerprint=fingerprint_data,
            open_ports=open_ports,
            found_paths=found_paths,
            active_vulns=active_vulns,
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


async def _run_full(config: AppConfig, target_url: str, project_dir: str, do_active_scan: bool = True) -> None:
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
    
    # SCA
    if config.sca.enabled:
        sca_findings = await _run_sca(config, project_dir, llm_client)
        sast_dicts.extend(sca_findings)

    # IaC
    if config.iac.enabled:
        iac_findings = await _run_iac(config, project_dir, llm_client)
        sast_dicts.extend(iac_findings)

    console.print(f"    [+] Combined SAST/SCA/IaC identified {len(sast_dicts)} potential issues")

    # ---- DAST ----
    console.print("\n[bold green]--- Phase 2: DAST Dynamic Scanning ---[/bold green]")
    fingerprint_data: dict = {}
    open_ports: list = []
    found_paths: list = []
    active_vulns: list = []
    dast_analysis = None

    try:
        async with ScannerBridge(config.scanner) as bridge:
            fingerprint_data = await bridge.fingerprint(target_url)
            _print_fingerprint(fingerprint_data)

            result = await bridge.dir_bust(target_url)
            found_paths = result.get("found_paths", [])
            console.print(f"    [+] {len(found_paths)} valid paths discovered")

            if do_active_scan:
                console.print("[bold][*] Active Vulnerability Scanning...[/bold]")
                targets_to_scan = {target_url}
                for path_entry in found_paths:
                    path = path_entry.get("path", "")
                    if "?" in path:
                        full_url = target_url.rstrip("/") + "/" + path.lstrip("/")
                        targets_to_scan.add(full_url)
                
                console.print(f"    [*] Scanning {len(targets_to_scan)} endpoints...")
                for url in targets_to_scan:
                    res = await bridge.active_scan(url)
                    vulns = res.get("vulnerabilities", [])
                    if vulns:
                        active_vulns.extend(vulns)
                        for v in vulns:
                            console.print(f"    [red][!] Found {v['name']} at {v['location']}[/red]")

    except FileNotFoundError as e:
        console.print(f"[yellow][!] DAST skipped: {e}[/yellow]")

    # ---- LLM 综合推理 ----
    correlation = None
    if llm_client:
        console.print("\n[bold magenta]--- Phase 3: LLM Cross-Correlation ---[/bold magenta]")
        reasoner = VulnReasoner(llm_client)

        if fingerprint_data or found_paths or active_vulns:
            dast_analysis = await reasoner.analyze_dast_results(
                fingerprint=fingerprint_data,
                open_ports=open_ports,
                found_paths=found_paths,
                active_vulns=active_vulns,
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
    table.add_column("ID", style="cyan", width=12)
    table.add_column("SEVERITY", width=10)
    table.add_column("TITLE", width=28)
    table.add_column("FILE", width=30)
    table.add_column("LINE", width=6)
    table.add_column("SOURCE", width=8)

    severity_colors = {
        "Critical": "bold red",
        "High": "red",
        "Medium": "yellow",
        "Low": "green",
        "Info": "blue",
    }

    source_styles = {
        "both": "[bold green]BOTH[/bold green]",
        "regex": "[dim]REGEX[/dim]",
        "llm": "[bold cyan]LLM[/bold cyan]",
        "llm-sca": "[bold magenta]SCA-LLM[/bold magenta]",
        "llm-iac": "[bold yellow]IaC-LLM[/bold yellow]",
        "llm-api": "[bold blue]API-LLM[/bold blue]",
        "iac": "[yellow]IaC[/yellow]",
    }

    for f in findings:
        if hasattr(f, "to_dict"):
            d = f.to_dict()
        else:
            d = f

        sev = d.get("severity", "Info")
        color = severity_colors.get(sev, "white")
        
        # 处理 Source 显示
        src = d.get("source", "regex")
        if d.get("type") == "IaC" and "source" not in d:
            src = "iac"
            
        src_display = source_styles.get(src, src)

        table.add_row(
            d.get("rule_id", ""),
            f"[{color}]{sev}[/{color}]",
            d.get("title", ""),
            str(d.get("file_path", ""))[-30:],
            str(d.get("line_start", "") or d.get("line", "")),
            src_display,
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
