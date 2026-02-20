use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Write};

/// IPC 协议：Python <-> Rust 通过 JSON Lines over stdin/stdout 通信
/// 每行一个 JSON 对象，以换行符分隔

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Request {
    #[serde(rename = "port_scan")]
    PortScan {
        target: String,
        ports: PortRange,
        concurrency: usize,
        timeout_ms: u64,
    },
    #[serde(rename = "dir_bust")]
    DirBust {
        target_url: String,
        wordlist: Vec<String>,
        concurrency: usize,
        timeout_ms: u64,
        extensions: Vec<String>,
    },
    #[serde(rename = "fingerprint")]
    Fingerprint {
        target_url: String,
        timeout_ms: u64,
    },
    #[serde(rename = "active_scan")]
    ActiveScan {
        target_url: String,
        scan_types: Vec<String>, // "sqli", "xss", "cmdi"
        concurrency: usize,
        timeout_ms: u64,
    },
    #[serde(rename = "shutdown")]
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Response {
    #[serde(rename = "port_scan_result")]
    PortScanResult {
        target: String,
        open_ports: Vec<PortInfo>,
        scan_duration_ms: u64,
    },
    #[serde(rename = "dir_bust_result")]
    DirBustResult {
        target_url: String,
        found_paths: Vec<DirEntry>,
        scan_duration_ms: u64,
    },
    #[serde(rename = "fingerprint_result")]
    FingerprintResult {
        target_url: String,
        server: Option<String>,
        technologies: Vec<Technology>,
        headers: Vec<(String, String)>,
        status_code: u16,
    },
    #[serde(rename = "active_scan_result")]
    ActiveScanResult {
        target_url: String,
        vulnerabilities: Vec<Vulnerability>,
        scan_duration_ms: u64,
    },
    #[serde(rename = "error")]
    Error {
        message: String,
    },
    #[serde(rename = "progress")]
    Progress {
        task: String,
        current: usize,
        total: usize,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PortInfo {
    pub port: u16,
    pub state: String,
    pub service_hint: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DirEntry {
    pub path: String,
    pub status_code: u16,
    pub content_length: u64,
    pub redirect_to: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Technology {
    pub name: String,
    pub version: Option<String>,
    pub confidence: f32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Vulnerability {
    pub name: String,
    pub severity: String,
    pub description: String,
    pub evidence: String, // Payload or response snippet
    pub location: String, // URL or parameter
}

/// 从 stdin 读取一行 JSON 请求
pub fn read_request() -> io::Result<Option<Request>> {
    let stdin = io::stdin();
    let mut line = String::new();
    let bytes_read = stdin.lock().read_line(&mut line)?;
    if bytes_read == 0 {
        return Ok(None); // EOF
    }
    let req: Request = serde_json::from_str(line.trim())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some(req))
}

/// 向 stdout 写入一行 JSON 响应
pub fn write_response(resp: &Response) -> io::Result<()> {
    let json = serde_json::to_string(resp)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    writeln!(handle, "{}", json)?;
    handle.flush()?;
    Ok(())
}
