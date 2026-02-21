# Hybrid Scanning Engine

> **One Binary. One Command. Full-Stack Security.**

```
pip install + cargo build → 30 秒部署
一条命令 → SAST + DAST + 主动漏洞扫描 + LLM 智能分析
```

传统安全测试需要 **Nmap + Gobuster + SQLMap + Burp Suite + SonarQube** 五套工具、数小时配置。  
Hybrid Scanner 用 **一个 Rust 二进制 + 一个 Python CLI** 替代它们全部。

---

## Why Hybrid?

| 痛点 | 传统方案 | Hybrid 方案 |
|------|----------|-------------|
| 扫描一个目标需要 5+ 工具 | Nmap → Gobuster → SQLMap → Burp → SonarQube | `python -m orchestrator.main full` **一条命令** |
| SonarQube 需要 JVM + 数据库 | 2GB+ 内存，Docker 部署 | **单文件二进制** < 10MB，零依赖 |
| Burp Suite Pro 年费 $449 | 还需要手动配置爬虫和插件 | **完全免费开源** + LLM 自动分析 |
| 误报率高，人工复核成本大 | Bandit/Semgrep 纯规则匹配 | **Regex + LLM 双引擎** 交叉验证 |
| 无法理解业务逻辑漏洞 | 规则引擎的天花板 | **DeepSeek V3.2** 语义级深度审计 |
| 报告分散在各工具中 | 手动汇总 | **统一 Markdown + JSON** 报告 |

---

## Industry Comparison

### SAST 静态分析对比

| 维度 | **Hybrid Scanner** | SonarQube | Semgrep | Bandit | Snyk Code |
|------|-------------------|-----------|---------|--------|-----------|
| **部署复杂度** | `pip install` | JVM + PostgreSQL + Docker | pip install | pip install | SaaS 注册 |
| **启动时间** | < 1s | 30s ~ 2min | < 1s | < 1s | 云端 |
| **内存占用** | < 50MB | 2GB+ | ~200MB | ~30MB | 云端 |
| **检测引擎** | Regex + **LLM** | 规则 + Taint | AST 规则 | AST 规则 | ML + 规则 |
| **逻辑漏洞** | **LLM 可发现** | 不能 | 不能 | 不能 | 有限 |
| **误报处理** | LLM 自动验证 | 人工标记 | 人工标记 | 人工标记 | ML 辅助 |
| **自定义规则** | 正则 + Prompt | Java DSL | YAML | Python 插件 | 不支持 |
| **价格** | **免费** | 社区版免费/企业版 $15k+/yr | 免费/团队版 $40+/mo | 免费 | 免费/Pro $25+/mo |
| **语言支持** | Python/JS/PHP/Java | 30+ | 30+ | 仅 Python | 10+ |

**核心优势**: Hybrid 是目前唯一将 **LLM 深度语义审计** 内置到 SAST 流程中的开源工具，可以发现纯规则引擎无法覆盖的 CSRF、逻辑越权、不安全的业务流等问题。

### DAST 动态扫描对比

| 维度 | **Hybrid Scanner** | Burp Suite Pro | OWASP ZAP | Xray | Nuclei |
|------|-------------------|----------------|-----------|------|--------|
| **部署** | 单二进制 | Java GUI 安装 | Java GUI 安装 | 单二进制 | 单二进制 |
| **上手时间** | **1 分钟** (CLI) | 数小时 (学习 UI) | 1 小时 | 10 分钟 | 10 分钟 |
| **主动扫描** | SQLi + XSS + CMDi | 全覆盖 | 全覆盖 | PoC 模板 | PoC 模板 |
| **端口扫描** | **内置** (Rust async) | 不内置 | 不内置 | 不内置 | 不内置 |
| **目录爆破** | **内置** (Rust async) | 内置 | 内置 | 不内置 | 不内置 |
| **指纹识别** | **内置** | 内置 | 内置 | 内置 | 有限 |
| **LLM 分析** | **内置** | 不支持 | 不支持 | 不支持 | 不支持 |
| **SAST 集成** | **原生集成** | 需买 Enterprise | 第三方插件 | 不支持 | 不支持 |
| **价格** | **免费** | **$449/yr** | 免费 | 社区免费 | 免费 |
| **扫描速度** | Rust 异步，毫秒级 | 中等 | 中等 | 快 | 快 |

**核心优势**: Hybrid 是唯一同时包含 **端口扫描 + 目录爆破 + 指纹识别 + 主动漏洞扫描 + 代码审计 + LLM 推理** 的单一工具，且完全免费。

### 一图流：工具替代关系

```
传统工作流 (5-7 个工具):                Hybrid (1 个工具):
┌──────────┐                          ┌──────────────────────┐
│  Nmap    │ ─ 端口扫描 ──────────┐   │                      │
├──────────┤                      │   │   hybrid-scanner     │
│ Gobuster │ ─ 目录爆破 ──────────┤   │                      │
├──────────┤                      │   │   $ python -m        │
│ WhatWeb  │ ─ 指纹识别 ──────────┤   │   orchestrator.main  │
├──────────┤                      ├──▶│   full               │
│ SQLMap   │ ─ 漏洞注入 ──────────┤   │   http://target      │
├──────────┤                      │   │   ./source-code      │
│ SonarQube│ ─ 代码审计 ──────────┤   │                      │
├──────────┤                      │   │   --active            │
│ Burp Pro │ ─ 综合扫描 ──────────┘   │                      │
└──────────┘                          └──────────────────────┘
 安装: 2h+ | 配置: 1h+ | 费用: $449+     安装: 30s | 配置: 0 | 费用: $0
```

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│              CLI Interface (Typer + Rich)         │
│           sast / dast / full / init              │
├──────────────┬───────────────────────────────────┤
│  SAST Engine │    DAST Bridge (IPC)              │
│  Regex + LLM │    JSON Lines stdin/stdout        │
├──────────────┼───────────────────────────────────┤
│  LLM Client  │    Rust Scanner Engine            │
│  DeepSeek    │    Port / Dir / Fingerprint       │
│  V3.2        │    Active Vuln (SQLi/XSS/CMDi)   │
├──────────────┴───────────────────────────────────┤
│         Report Generator (Markdown + JSON)       │
│         UTF-8 BOM | API Key 自动遮蔽             │
└──────────────────────────────────────────────────┘
```

---

## Directory Structure

```
.
├── scanner-engine/              # Rust high-concurrency scanner
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs              # IPC dispatcher
│       ├── ipc.rs               # JSON Lines protocol definitions
│       ├── port_scanner.rs      # Async TCP Connect scanner
│       ├── dir_buster.rs        # HTTP path bruteforcer
│       ├── fingerprint.rs       # Technology stack fingerprinting
│       └── active_scanner.rs   # SQLi / XSS / CMDi payload scanner
│
├── orchestrator/                # Python orchestration layer
│   ├── main.py                  # CLI entry point
│   ├── config.py                # Pydantic configuration management
│   ├── llm/
│   │   ├── client.py            # DeepSeek API client (chat + reasoner)
│   │   └── prompts.py           # Security analysis prompt templates
│   ├── sast/
│   │   ├── analyzer.py          # Static analysis engine
│   │   └── rules.py             # 30+ built-in vulnerability rules
│   ├── dast/
│   │   └── scanner_bridge.py    # Rust engine IPC bridge
│   ├── reasoning/
│   │   └── vuln_reasoner.py     # LLM vulnerability reasoning engine
│   └── report/
│       └── generator.py         # Markdown + JSON report generator
│
├── vuln-app/                    # Intentionally vulnerable Flask app (test target)
│   ├── app.py                   # 18+ embedded vulnerabilities
│   ├── models.py                # SQLAlchemy data models
│   └── config.py                # Hardcoded credentials (intentional)
│
├── wordlists/                   # Dictionary files for directory bruteforcing
├── config.yaml                  # Main configuration (API key goes here)
└── reports/                     # Generated scan reports
```

---

## Quick Start

### 1. Build the Rust Scanner Engine

```bash
cd scanner-engine
cargo build --release
```

### 2. Install Python Dependencies

```bash
pip install -r orchestrator/requirements.txt
```

### 3. Configure

```bash
# Generate default config
python -m orchestrator.main init

# Edit config.yaml and set your DeepSeek API key
# config.yaml -> llm.api_key: "sk-your-key-here"
```

### 4. Run Scans

```bash
# SAST - regex-only (毫秒级)
python -m orchestrator.main sast ./your-project

# SAST - 双引擎 (Regex + LLM 深度审计)
python -m orchestrator.main sast ./your-project --llm

# SAST - 思考模式 (DeepSeek V3.2 Reasoner)
python -m orchestrator.main sast ./your-project --reasoning

# DAST - 端口 + 目录 + 指纹
python -m orchestrator.main dast http://target:8080

# DAST - 主动漏洞扫描 (SQLi/XSS/CMDi)
python -m orchestrator.main dast "http://target:8080/search?q=test" --active

# Full - SAST + DAST + 主动扫描 + LLM 关联 (一条命令搞定)
python -m orchestrator.main full http://target:8080 ./your-project --active
```

---

## Built-in Detection Rules

The SAST engine ships with **30+ rules** covering OWASP Top 10 and common vulnerability patterns:

| Rule ID | CWE | Category | Severity |
|---------|-----|----------|----------|
| SAST-001 ~ 006 | CWE-89 | SQL Injection (f-string, +=, format, concatenation) | Critical |
| SAST-010 ~ 013 | CWE-78 | OS Command Injection (shell=True, os.system, os.popen) | Critical |
| SAST-020 ~ 022 | CWE-22 | Path Traversal / Arbitrary File Read | High |
| SAST-030 ~ 031 | CWE-918 | Server-Side Request Forgery (SSRF) | High |
| SAST-040 ~ 041 | CWE-79 | Cross-Site Scripting (XSS) | High |
| SAST-050 | CWE-502 | Insecure Deserialization (pickle, yaml.load) | Critical |
| SAST-060 | CWE-798 | Hardcoded Credentials / Secrets | High |
| SAST-070 | CWE-327 | Weak Cryptographic Hash (MD5, SHA1) | Medium |
| SAST-080 ~ 082 | CWE-1336 | Server-Side Template Injection (SSTI) | Critical |
| SAST-091 | CWE-434 | Insecure File Upload | High |
| SAST-100 | CWE-611 | XML External Entity (XXE) | High |
| SAST-110 | CWE-489 | Debug Mode Enabled in Production | High |
| SAST-120 | CWE-200 | Sensitive Information Exposure (Exception Details) | Medium |
| SAST-130 ~ 131 | CWE-639 | Insecure Direct Object Reference (IDOR) | High |
| SAST-140 ~ 141 | CWE-200 | System/Config Information Leakage | High |

---

## LLM Integration

Both modes use **DeepSeek-V3.2**:

| Mode | Model ID | Flag | Use Case |
|------|----------|------|----------|
| V3.2 Non-Thinking | `deepseek-chat` | `--llm` | Fast dual-engine scan, low cost |
| V3.2 Thinking | `deepseek-reasoner` | `--reasoning` | Deep chain-of-thought analysis, higher accuracy |

The LLM verification pipeline:
1. **Connectivity test** before starting (fail-fast with clear error)
2. **Concurrent verification** with rate limiting (Semaphore = 3)
3. **Per-finding progress** output (CONFIRMED / UNCONFIRMED / ERROR)
4. **Graceful fallback** to regex-only mode on API failure

---

## Test Target (vuln-app)

The included Flask application contains **18+ intentional vulnerabilities** for testing:

- SQL Injection (f-string, string concatenation, += append)
- OS Command Injection (subprocess shell=True, os.system, os.popen)
- Path Traversal / Arbitrary File Read (send_file, open)
- Server-Side Request Forgery (requests.get with user-controlled URL)
- Server-Side Template Injection (render_template_string)
- Insecure Deserialization (pickle.loads, yaml.load)
- Cross-Site Scripting (f-string template rendering)
- Insecure File Upload (no filename validation)
- Hardcoded Credentials and Secrets
- Weak Password Hashing (MD5)
- Debug Mode in Production
- IDOR / Missing Authorization Checks
- System Information Leakage

### Run the test target

```bash
pip install -r vuln-app/requirements.txt
python vuln-app/app.py
# Access at http://localhost:5000
# Default credentials: admin / admin123
```

---

## Sample Output

### SAST 双引擎扫描

```
╦ ╦╦ ╦╔╗ ╦═╗╦╔╦╗  ╔═╗╔═╗╔═╗╔╗╔╔╗╔╔═╗╦═╗
╠═╣╚╦╝╠╩╗╠╦╝║ ║║  ╚═╗║  ╠═╣║║║║║║║╣ ╠╦╝
╩ ╩ ╩ ╚═╝╩╚═╩═╩╝  ╚═╝╚═╝╩ ╩╝╚╝╝╚╝╚═╝╩╚═

SAST :: Static Application Security Testing

[*] Collected 3 source files
[*] Mode: Dual-Engine (Regex + LLM Deep Audit) [DeepSeek-V3.2]
[*] Testing API connectivity...
[+] API connected (DeepSeek-V3.2)
[*] Engine 1/2: Regex fast scan (3 files)...
    -> 0 pattern matches
[*] Engine 2/2: LLM deep audit (3 files)...
    [1/3] safe.js -> clean                    ← LLM 识别安全代码，零误报
    [2/3] suggestion.js -> 2 vulns            ← LLM 发现 DOM XSS + 输入验证缺失
    [3/3] Codecraft_main.py -> 4 vulns        ← LLM 发现 CSRF + CORS + 路径穿越
    -> 6 LLM-discovered issues (0 errors)
[*] Merging results (deduplication by file + line + CWE)...
[+] Final: 6 findings (regex=0, llm=6, both=0)
[+] Report saved: reports/report_xxx.md
```

### DAST 主动扫描

```
DAST :: Dynamic Application Security Testing

[*] Fingerprinting target...
    [+] HTTP 200
    [+] Server: Werkzeug/3.1.5 Python/3.13.7
[*] Directory bruteforcing...
    [+] 88 valid paths discovered
[*] Active Vulnerability Scanning (SQLi, XSS, CMDi)...
    [*] Scanning 1 endpoints...
    [!] Found Reflected XSS at q=<script>alert(1)</script>    ← 35ms 检出
[+] Report saved: reports/report_xxx.md
```

---

## Technology Stack

| Component | Technologies |
|-----------|-------------|
| Scanner Engine | Rust, tokio, reqwest, serde, serde_json |
| Orchestrator | Python 3.11+, Typer, Rich, Pydantic, Jinja2 |
| LLM Client | OpenAI SDK (DeepSeek compatible) |
| IPC | JSON Lines over stdin/stdout |
| Report | Markdown + JSON |

---

## Configuration

All settings are managed via `config.yaml`:

```yaml
llm:
  api_key: ""                    # DeepSeek API Key
  base_url: "https://api.deepseek.com"
  model: "deepseek-chat"         # or "deepseek-reasoner"
  max_tokens: 4096
  temperature: 0.1

scanner:
  binary_path: "./scanner-engine/target/release/scanner-engine.exe"
  port_scan_concurrency: 500
  timeout_ms: 3000

sast:
  max_file_size_kb: 512
  languages: [python, javascript, php, java]
  exclude_dirs: [node_modules, .git, __pycache__, venv]
```

---

## Disclaimer

This tool is intended for authorized security testing only. Do not use against systems you do not own or have explicit permission to test.

---

*Built with Rust + Python + DeepSeek LLM*
