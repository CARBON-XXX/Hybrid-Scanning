use crate::ipc::{DirEntry, Response};
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// 目录/路径爆破模块
/// 对目标 URL 进行并发 HTTP 请求，探测有效路径
pub async fn bust(
    target_url: &str,
    wordlist: &[String],
    extensions: &[String],
    concurrency: usize,
    timeout: Duration,
    progress_tx: tokio::sync::mpsc::Sender<Response>,
) -> Vec<DirEntry> {
    let client = Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .build()
        .expect("Failed to build HTTP client");

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let client = Arc::new(client);

    // 构建完整的探测路径列表：每个 word + 每个 extension
    let mut paths: Vec<String> = Vec::new();
    for word in wordlist {
        paths.push(word.clone());
        for ext in extensions {
            paths.push(format!("{}.{}", word, ext));
        }
    }

    let total = paths.len();
    let mut handles = Vec::with_capacity(total);

    for (idx, path) in paths.into_iter().enumerate() {
        let sem = semaphore.clone();
        let client = client.clone();
        let base_url = target_url.trim_end_matches('/').to_string();
        let tx = progress_tx.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            let url = format!("{}/{}", base_url, path.trim_start_matches('/'));
            let result = probe_path(&client, &url, &path).await;

            // 每 200 条报告进度
            if idx % 200 == 0 {
                let _ = tx.send(Response::Progress {
                    task: "dir_bust".to_string(),
                    current: idx,
                    total,
                }).await;
            }

            result
        });
        handles.push(handle);
    }

    let mut found = Vec::new();
    for handle in handles {
        if let Ok(Some(entry)) = handle.await {
            found.push(entry);
        }
    }

    found.sort_by(|a, b| a.path.cmp(&b.path));
    found
}

async fn probe_path(client: &Client, url: &str, path: &str) -> Option<DirEntry> {
    let resp = client.get(url).send().await.ok()?;
    let status = resp.status().as_u16();

    // 过滤掉 404 和常见的 WAF 拦截页面
    if status == 404 || status == 403 || status == 503 {
        return None;
    }

    let redirect_to = if (300..400).contains(&status) {
        resp.headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    } else {
        None
    };

    let content_length = resp.content_length().unwrap_or(0);

    Some(DirEntry {
        path: path.to_string(),
        status_code: status,
        content_length,
        redirect_to,
    })
}
