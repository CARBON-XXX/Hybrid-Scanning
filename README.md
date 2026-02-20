# Hybrid Scanning Engine

**Rust Concurrency Layer + Python LLM Reasoning**

A **lightweight, all-in-one** vulnerability scanning engine that combines Rust's high-performance network probing with Python-based static analysis and DeepSeek V3.2 LLM reasoning.

> **Why this engine?**
> Instead of juggling 5 different tools (Nmap, Gobuster, SQLMap, Bandit, etc.), use **one lightweight CLI** to perform a full-stack security assessment.

---

## Key Features

- **🚀 Lightweight & Fast**: Core scanning engine written in **Rust** (tokio-based async concurrency). No heavy JVM or complex database required.
- **🛡️ Dual-Engine SAST**: Traditional Regex scanning (millisecond speed) + **DeepSeek LLM Deep Audit** (semantic understanding) to find logic bugs.
- **⚡ Active DAST**: Built-in payloads for **SQL Injection, XSS, and Command Injection** detection.
- **🧠 Intelligent Correlation**: LLM analyzes both static code and dynamic responses to reduce false positives.
- **📂 One-Stop Shop**: Port scanning, Directory bruteforce, Fingerprinting, and Code Audit in a single workflow.

---

## Architecture

```
+--------------------------------------------------+
|              CLI Interface (Typer + Rich)         |
|         sast / dast / full / init                |
+-------------+------------------------------------+
|  SAST Engine |    DAST Bridge (IPC)              |
|  Regex + LLM |    JSON Lines stdin/stdout        |
+-------------+------------------------------------+
|  LLM Client  |    Rust Scanner Engine            |
|  DeepSeek    |    Port / Dir / Fingerprint       |
|  V3.2        |    Active Vuln Scanner (SQLi/XSS) |
+-------------+------------------------------------+
|         Report Generator (Markdown + JSON)       |
+--------------------------------------------------+
```

### Component Comparison

| Feature | Hybrid Scanner | Traditional Tools |
|---------|----------------|-------------------|
| **Port Scan** | Rust Async (Fast) | Nmap |
| **Dir Busting** | Rust Async (Fast) | Gobuster / Dirsearch |
| **Fingerprint** | Built-in | WhatWeb / Wappalyzer |
| **Active Scan** | Built-in (Lightweight) | SQLMap / Xray / OWASP ZAP |
| **Code Audit** | Regex + LLM | SonarQube / Bandit / Semgrep |
| **Report** | Unified (MD/JSON) | Fragmented |

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
│       └── fingerprint.rs       # Technology stack fingerprinting
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
# SAST - regex-only static analysis
python -m orchestrator.main sast ./your-project

# SAST + LLM cross-validation (deepseek-chat)
python -m orchestrator.main sast ./your-project --llm

# SAST + deep reasoning model (deepseek-reasoner / R1)
python -m orchestrator.main sast ./your-project --reasoning

# DAST - dynamic scanning via Rust engine
python -m orchestrator.main dast http://target:8080

# Full assessment (SAST + DAST + LLM correlation)
python -m orchestrator.main full http://target:8080 ./your-project
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

```
  HYBRID SCANNER
  Hybrid Scanning Engine v0.1.0
  Rust Concurrency Layer + Python LLM Reasoning

  SAST :: Static Application Security Testing

[*] Collected 3 source files from ./vuln-app
[*] Mode: regex scan + LLM cross-validation (deepseek-chat)
[*] LLM cross-validation: 37 findings queued
[*] Testing API connectivity...
[+] API connected
    [1/37] SAST-002 SQL Injection -> CONFIRMED
    [2/37] SAST-006 SQL Injection (+= append) -> CONFIRMED
    ...
[+] LLM verification complete: 30 confirmed, 0 errors
[+] Scan complete: 37 potential issues identified
[+] Report saved: reports/report.md
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
