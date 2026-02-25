use crate::ipc::{PortInfo, PortRange, Response};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

/// TCP Connect 端口扫描器
/// 使用 tokio 异步并发，通过 Semaphore 控制最大并发数
pub async fn scan(
    target: &str,
    ports: &PortRange,
    concurrency: usize,
    timeout: Duration,
    progress_tx: tokio::sync::mpsc::Sender<Response>,
) -> Vec<PortInfo> {
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let total_ports = (ports.end - ports.start + 1) as usize;
    let mut handles = Vec::with_capacity(total_ports);

    for port in ports.start..=ports.end {
        let sem = semaphore.clone();
        let addr_str = format!("{}:{}", target, port);
        let tx = progress_tx.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let result = probe_port(&addr_str, port, timeout).await;

            // 每扫描 500 个端口报告一次进度
            if port % 500 == 0 {
                let _ = tx
                    .send(Response::Progress {
                        task: "port_scan".to_string(),
                        current: port as usize,
                        total: 0, // 由调用方填充
                    })
                    .await;
            }

            result
        });
        handles.push(handle);
    }

    let mut open_ports = Vec::new();
    for handle in handles {
        if let Ok(Some(info)) = handle.await {
            open_ports.push(info);
        }
    }

    open_ports.sort_by_key(|p| p.port);
    open_ports
}

async fn probe_port(addr_str: &str, port: u16, timeout_duration: Duration) -> Option<PortInfo> {
    let addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => {
            // 尝试 DNS 解析
            match tokio::net::lookup_host(addr_str).await {
                Ok(mut addrs) => match addrs.next() {
                    Some(a) => a,
                    None => return None,
                },
                Err(_) => return None,
            }
        }
    };

    match tokio::time::timeout(timeout_duration, TcpStream::connect(&addr)).await {
        Ok(Ok(_stream)) => {
            let service_hint = guess_service(port);
            Some(PortInfo {
                port,
                state: "open".to_string(),
                service_hint,
            })
        }
        _ => None,
    }
}

/// 根据常见端口号猜测服务类型
fn guess_service(port: u16) -> Option<String> {
    let service = match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        143 => "imap",
        443 => "https",
        445 => "smb",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        1521 => "oracle",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5900 => "vnc",
        6379 => "redis",
        8080 => "http-proxy",
        8443 => "https-alt",
        8888 => "http-alt",
        9200 => "elasticsearch",
        27017 => "mongodb",
        _ => return None,
    };
    Some(service.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guess_service() {
        assert_eq!(guess_service(80), Some("http".to_string()));
        assert_eq!(guess_service(443), Some("https".to_string()));
        assert_eq!(guess_service(12345), None);
    }
}
