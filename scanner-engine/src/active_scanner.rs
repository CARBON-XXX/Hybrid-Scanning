use crate::ipc::Vulnerability;
use reqwest::redirect::Policy;
use reqwest::Client;
use std::time::Duration;
use tracing::{error, info, warn};
use url::Url;

const SQL_ERRORS: &[&str] = &[
    "SQL syntax",
    "mysql_fetch",
    "valid MySQL result",
    "ODBC SQL Server Driver",
    "PostgreSQL query failed",
    "Warning: pg_query",
    "SQLite/JDBCDriver",
    "SQLite.Exception",
    "System.Data.SQLite.SQLiteException",
    "Warning: sqlite_",
    "Warning: SQLite3::",
    "SQL command not properly ended",
    "ORA-00933",
];

const SQLI_PAYLOADS: &[&str] = &[
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1 --",
    "\" OR 1=1 --",
    "' UNION SELECT 1,2,3 --",
];

const XSS_PAYLOADS: &[&str] = &[
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><img src=x onerror=alert(1)>",
    "javascript:alert(1)",
];

const CMDI_PAYLOADS: &[&str] = &[
    "; id",
    "| id",
    "& id",
    "`id`",
    "$(id)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
];

fn build_client(timeout: Duration) -> Client {
    // 不使用 danger_accept_invalid_certs（rustls-tls 下可能导致 build 失败）
    // 禁用自动重定向跟随（防止登录重定向吞掉漏洞响应）
    Client::builder()
        .timeout(timeout)
        .redirect(Policy::none())
        .build()
        .expect("Failed to build reqwest Client")
}

pub async fn scan(
    target_url: &str,
    scan_types: &[String],
    _concurrency: usize,
    timeout: Duration,
) -> Vec<Vulnerability> {
    let mut vulnerabilities = Vec::new();

    let Ok(mut parsed_url) = Url::parse(target_url) else {
        error!("Failed to parse URL: {}", target_url);
        return vulnerabilities;
    };

    let pairs: Vec<(String, String)> = parsed_url.query_pairs().into_owned().collect();
    if pairs.is_empty() {
        warn!(
            "No query parameters found for {}, skipping active scan",
            target_url
        );
        return vulnerabilities;
    }

    info!(
        "Active scan: {} with {} parameter(s), types: {:?}",
        target_url,
        pairs.len(),
        scan_types,
    );

    let client = build_client(timeout);

    let scan_sqli = scan_types.iter().any(|t| t == "sqli" || t == "all");
    let scan_xss = scan_types.iter().any(|t| t == "xss" || t == "all");
    let scan_cmdi = scan_types.iter().any(|t| t == "cmdi" || t == "all");

    for (param_name, original_value) in &pairs {
        info!("Testing parameter: {}={}", param_name, original_value);

        if scan_sqli {
            for payload in SQLI_PAYLOADS {
                if let Some(vuln) = check_sqli(&client, &mut parsed_url, param_name, payload).await
                {
                    info!(
                        "SQLi found: {} at {}={}",
                        vuln.evidence, param_name, payload
                    );
                    vulnerabilities.push(vuln);
                    break;
                }
            }
        }

        if scan_xss {
            for payload in XSS_PAYLOADS {
                if let Some(vuln) = check_xss(&client, &mut parsed_url, param_name, payload).await {
                    info!("XSS found at {}={}", param_name, payload);
                    vulnerabilities.push(vuln);
                    break;
                }
            }
        }

        if scan_cmdi {
            for payload in CMDI_PAYLOADS {
                if let Some(vuln) = check_cmdi(&client, &mut parsed_url, param_name, payload).await
                {
                    info!("CMDi found at {}={}", param_name, payload);
                    vulnerabilities.push(vuln);
                    break;
                }
            }
        }

        set_query_param(&mut parsed_url, param_name, original_value);
    }

    info!(
        "Active scan done: {} vulnerabilities found",
        vulnerabilities.len()
    );
    vulnerabilities
}

/// 发送 GET 请求并返回 (status_code, body_text)，显式记录错误
async fn fire_payload(client: &Client, url: &Url) -> Option<(u16, String)> {
    match client.get(url.clone()).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            match resp.text().await {
                Ok(text) => Some((status, text)),
                Err(e) => {
                    warn!("Failed to read response body for {}: {}", url, e);
                    None
                }
            }
        }
        Err(e) => {
            warn!("Request failed for {}: {}", url, e);
            None
        }
    }
}

async fn check_sqli(
    client: &Client,
    url: &mut Url,
    param: &str,
    payload: &str,
) -> Option<Vulnerability> {
    set_query_param(url, param, payload);

    if let Some((status, text)) = fire_payload(client, url).await {
        info!(
            "  [sqli] {}={} -> HTTP {} ({}B)",
            param,
            payload,
            status,
            text.len()
        );
        for error_msg in SQL_ERRORS {
            if text.contains(error_msg) {
                return Some(Vulnerability {
                    name: "SQL Injection".to_string(),
                    severity: "Critical".to_string(),
                    description: format!("Database error message found using payload: {}", payload),
                    evidence: error_msg.to_string(),
                    location: format!("{}={}", param, payload),
                });
            }
        }
    }
    None
}

async fn check_xss(
    client: &Client,
    url: &mut Url,
    param: &str,
    payload: &str,
) -> Option<Vulnerability> {
    set_query_param(url, param, payload);

    if let Some((status, text)) = fire_payload(client, url).await {
        let found = text.contains(payload);
        info!(
            "  [xss] {}={} -> HTTP {} ({}B) reflected={}",
            param,
            payload,
            status,
            text.len(),
            found
        );
        if found {
            return Some(Vulnerability {
                name: "Reflected XSS".to_string(),
                severity: "High".to_string(),
                description: format!("Payload reflected in response using payload: {}", payload),
                evidence: payload.to_string(),
                location: format!("{}={}", param, payload),
            });
        }
    }
    None
}

async fn check_cmdi(
    client: &Client,
    url: &mut Url,
    param: &str,
    payload: &str,
) -> Option<Vulnerability> {
    set_query_param(url, param, payload);

    if let Some((status, text)) = fire_payload(client, url).await {
        info!(
            "  [cmdi] {}={} -> HTTP {} ({}B)",
            param,
            payload,
            status,
            text.len()
        );

        if text.contains("uid=") && text.contains("gid=") {
            return Some(Vulnerability {
                name: "Command Injection".to_string(),
                severity: "Critical".to_string(),
                description: format!("Command execution output found using payload: {}", payload),
                evidence: "uid=... gid=...".to_string(),
                location: format!("{}={}", param, payload),
            });
        }
        if text.contains("root:x:0:0:") {
            return Some(Vulnerability {
                name: "Command Injection".to_string(),
                severity: "Critical".to_string(),
                description: format!(
                    "File content leak indicating command injection using payload: {}",
                    payload
                ),
                evidence: "root:x:0:0:".to_string(),
                location: format!("{}={}", param, payload),
            });
        }
    }
    None
}

fn set_query_param(url: &mut Url, key: &str, value: &str) {
    let mut pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
    for (k, v) in pairs.iter_mut() {
        if k == key {
            *v = value.to_string();
        }
    }
    url.query_pairs_mut().clear().extend_pairs(pairs);
}
