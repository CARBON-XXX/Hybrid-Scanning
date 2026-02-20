use crate::ipc::{Response, Technology};
use reqwest::Client;
use std::time::Duration;

/// HTTP 指纹识别模块
/// 通过响应头、响应体特征识别目标技术栈
pub async fn identify(
    target_url: &str,
    timeout: Duration,
) -> Result<Response, String> {
    let client = Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let resp = client
        .get(target_url)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    let status_code = resp.status().as_u16();

    // 收集所有响应头
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    // 从 Server 头提取服务器信息
    let server = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("server"))
        .map(|(_, v)| v.clone());

    // 从 X-Powered-By 头提取技术栈
    let powered_by = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-powered-by"))
        .map(|(_, v)| v.clone());

    let body = resp.text().await.unwrap_or_default();

    let mut technologies = Vec::new();

    // ---- 基于响应头的指纹 ----
    if let Some(ref srv) = server {
        let srv_lower = srv.to_lowercase();
        if srv_lower.contains("nginx") {
            technologies.push(tech("Nginx", extract_version(srv, "nginx"), 0.95));
        }
        if srv_lower.contains("apache") {
            technologies.push(tech("Apache HTTPD", extract_version(srv, "apache"), 0.95));
        }
        if srv_lower.contains("iis") {
            technologies.push(tech("Microsoft IIS", extract_version(srv, "iis"), 0.95));
        }
        if srv_lower.contains("openresty") {
            technologies.push(tech("OpenResty", extract_version(srv, "openresty"), 0.90));
        }
        if srv_lower.contains("tomcat") {
            technologies.push(tech("Apache Tomcat", extract_version(srv, "tomcat"), 0.90));
        }
        if srv_lower.contains("jetty") {
            technologies.push(tech("Eclipse Jetty", extract_version(srv, "jetty"), 0.90));
        }
    }

    if let Some(ref pb) = powered_by {
        let pb_lower = pb.to_lowercase();
        if pb_lower.contains("php") {
            technologies.push(tech("PHP", extract_version(pb, "php"), 0.90));
        }
        if pb_lower.contains("asp.net") {
            technologies.push(tech("ASP.NET", None, 0.90));
        }
        if pb_lower.contains("express") {
            technologies.push(tech("Express.js", None, 0.85));
        }
        if pb_lower.contains("servlet") {
            technologies.push(tech("Java Servlet", None, 0.85));
        }
    }

    // ---- 基于响应体的指纹 ----
    let body_lower = body.to_lowercase();

    // 前端框架
    if body_lower.contains("wp-content") || body_lower.contains("wordpress") {
        technologies.push(tech("WordPress", None, 0.85));
    }
    if body_lower.contains("joomla") {
        technologies.push(tech("Joomla", None, 0.80));
    }
    if body_lower.contains("drupal") {
        technologies.push(tech("Drupal", None, 0.80));
    }
    if body_lower.contains("react") || body_lower.contains("__next") {
        technologies.push(tech("React / Next.js", None, 0.60));
    }
    if body_lower.contains("vue") || body_lower.contains("nuxt") {
        technologies.push(tech("Vue.js / Nuxt.js", None, 0.60));
    }

    // Java 中间件特征
    if body_lower.contains("weblogic") {
        technologies.push(tech("Oracle WebLogic", None, 0.85));
    }
    if body_lower.contains("jboss") || body_lower.contains("wildfly") {
        technologies.push(tech("JBoss / WildFly", None, 0.80));
    }

    // 常见 OA / 办公系统
    if body_lower.contains("seeyon") || body_lower.contains("致远") {
        technologies.push(tech("Seeyon OA (致远)", None, 0.85));
    }
    if body_lower.contains("tongda") || body_lower.contains("通达") {
        technologies.push(tech("Tongda OA (通达)", None, 0.85));
    }
    if body_lower.contains("weaver") || body_lower.contains("泛微") {
        technologies.push(tech("Weaver E-Cology (泛微)", None, 0.85));
    }
    if body_lower.contains("confluence") {
        technologies.push(tech("Atlassian Confluence", None, 0.90));
    }
    if body_lower.contains("jira") {
        technologies.push(tech("Atlassian Jira", None, 0.90));
    }
    if body_lower.contains("gitlab") {
        technologies.push(tech("GitLab", None, 0.90));
    }
    if body_lower.contains("jenkins") {
        technologies.push(tech("Jenkins", None, 0.90));
    }
    if body_lower.contains("grafana") {
        technologies.push(tech("Grafana", None, 0.85));
    }
    if body_lower.contains("zabbix") {
        technologies.push(tech("Zabbix", None, 0.85));
    }

    // 安全设备 / VPN
    if body_lower.contains("fortinet") || body_lower.contains("fortigate") {
        technologies.push(tech("Fortinet FortiGate", None, 0.85));
    }
    if body_lower.contains("sangfor") || body_lower.contains("深信服") {
        technologies.push(tech("Sangfor (深信服)", None, 0.80));
    }

    // ---- 基于特殊 Cookie 的指纹 ----
    for (k, v) in &headers {
        if k.eq_ignore_ascii_case("set-cookie") {
            let cookie_lower = v.to_lowercase();
            if cookie_lower.contains("jsessionid") {
                technologies.push(tech("Java (JSESSIONID)", None, 0.70));
            }
            if cookie_lower.contains("phpsessid") {
                technologies.push(tech("PHP (PHPSESSID)", None, 0.70));
            }
            if cookie_lower.contains("asp.net_sessionid") {
                technologies.push(tech("ASP.NET (SessionID)", None, 0.70));
            }
            if cookie_lower.contains("rememberme=deleteme") {
                technologies.push(tech("Apache Shiro", None, 0.90));
            }
        }
    }

    // 去重：按 name 去重，保留 confidence 最高的
    technologies.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
    technologies.dedup_by(|a, b| a.name == b.name);

    Ok(Response::FingerprintResult {
        target_url: target_url.to_string(),
        server,
        technologies,
        headers,
        status_code,
    })
}

fn tech(name: &str, version: Option<String>, confidence: f32) -> Technology {
    Technology {
        name: name.to_string(),
        version,
        confidence,
    }
}

fn extract_version(header_value: &str, keyword: &str) -> Option<String> {
    let lower = header_value.to_lowercase();
    if let Some(pos) = lower.find(keyword) {
        let after = &header_value[pos + keyword.len()..];
        // 尝试匹配 /x.y.z 或 x.y.z 格式的版本号
        let trimmed = after.trim_start_matches('/').trim();
        let version: String = trimmed
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        if !version.is_empty() {
            return Some(version);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_version() {
        assert_eq!(
            extract_version("nginx/1.21.3", "nginx"),
            Some("1.21.3".to_string())
        );
        assert_eq!(
            extract_version("Apache/2.4.51 (Ubuntu)", "apache"),
            Some("2.4.51".to_string())
        );
        assert_eq!(extract_version("Microsoft-IIS/10.0", "iis"), Some("10.0".to_string()));
    }
}
