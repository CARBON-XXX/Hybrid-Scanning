mod dir_buster;
mod fingerprint;
mod ipc;
mod port_scanner;

use ipc::{Request, Response};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, info};

#[tokio::main]
async fn main() {
    // 初始化 tracing 到 stderr（stdout 留给 IPC）
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    info!("Scanner engine started, waiting for commands via stdin...");

    loop {
        match ipc::read_request() {
            Ok(Some(request)) => {
                let response = handle_request(request).await;
                if let Err(e) = ipc::write_response(&response) {
                    error!("Failed to write response: {}", e);
                    break;
                }
                // Shutdown 命令后退出
                if matches!(response, Response::Error { .. }) {
                    // 继续处理下一个请求
                } else if let Response::Error { .. } = response {
                    // 错误也继续
                }
            }
            Ok(None) => {
                info!("EOF on stdin, shutting down");
                break;
            }
            Err(e) => {
                error!("Failed to read request: {}", e);
                let _ = ipc::write_response(&Response::Error {
                    message: format!("Invalid request: {}", e),
                });
            }
        }
    }
}

async fn handle_request(request: Request) -> Response {
    match request {
        Request::PortScan {
            target,
            ports,
            concurrency,
            timeout_ms,
        } => {
            info!(
                "Starting port scan on {} ({}-{})",
                target, ports.start, ports.end
            );
            let timeout = Duration::from_millis(timeout_ms);
            let start = std::time::Instant::now();

            // 创建进度通道（本模式下丢弃进度消息，仅返回最终结果）
            let (tx, mut _rx) = mpsc::channel::<Response>(128);

            let open_ports = port_scanner::scan(&target, &ports, concurrency, timeout, tx).await;
            let duration = start.elapsed().as_millis() as u64;

            info!("Port scan complete: {} open ports in {}ms", open_ports.len(), duration);

            Response::PortScanResult {
                target,
                open_ports,
                scan_duration_ms: duration,
            }
        }

        Request::DirBust {
            target_url,
            wordlist,
            concurrency,
            timeout_ms,
            extensions,
        } => {
            info!("Starting directory bust on {}", target_url);
            let timeout = Duration::from_millis(timeout_ms);
            let start = std::time::Instant::now();

            let (tx, mut _rx) = mpsc::channel::<Response>(128);

            let found_paths =
                dir_buster::bust(&target_url, &wordlist, &extensions, concurrency, timeout, tx)
                    .await;
            let duration = start.elapsed().as_millis() as u64;

            info!("Dir bust complete: {} paths found in {}ms", found_paths.len(), duration);

            Response::DirBustResult {
                target_url,
                found_paths,
                scan_duration_ms: duration,
            }
        }

        Request::Fingerprint {
            target_url,
            timeout_ms,
        } => {
            info!("Starting fingerprint on {}", target_url);
            let timeout = Duration::from_millis(timeout_ms);

            match fingerprint::identify(&target_url, timeout).await {
                Ok(resp) => resp,
                Err(e) => Response::Error { message: e },
            }
        }

        Request::Shutdown => {
            info!("Received shutdown command");
            std::process::exit(0);
        }
    }
}
