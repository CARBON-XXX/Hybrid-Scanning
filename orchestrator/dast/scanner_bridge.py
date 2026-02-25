"""Python <-> Rust 扫描引擎 IPC 桥接层

通过 subprocess 启动 Rust 二进制，使用 JSON Lines over stdin/stdout 通信。
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from pathlib import Path
from typing import Any

from orchestrator.config import ScannerConfig


class ScannerBridge:
    """Rust 扫描引擎的 Python 侧 IPC 桥接

    生命周期：
    1. start()  -> 启动 Rust 子进程
    2. port_scan() / dir_bust() / fingerprint()  -> 发送命令并接收结果
    3. shutdown() -> 优雅关闭子进程
    """

    def __init__(self, config: ScannerConfig) -> None:
        self._config = config
        self._process: asyncio.subprocess.Process | None = None

    async def start(self) -> None:
        """启动 Rust 扫描引擎子进程"""
        binary = Path(self._config.binary_path)
        if not binary.exists():
            raise FileNotFoundError(
                f"扫描引擎二进制不存在: {binary}\n"
                f"请先编译: cd scanner-engine && cargo build --release"
            )

        self._process = await asyncio.create_subprocess_exec(
            str(binary),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=None,  # Direct stderr to console for debugging
        )

    async def _send_and_receive(self, request: dict[str, Any]) -> dict[str, Any]:
        """发送 JSON 请求并读取 JSON 响应"""
        if self._process is None or self._process.stdin is None or self._process.stdout is None:
            raise RuntimeError("扫描引擎未启动，请先调用 start()")

        request_line = json.dumps(request, ensure_ascii=False) + "\n"
        self._process.stdin.write(request_line.encode("utf-8"))
        await self._process.stdin.drain()

        response_line = await self._process.stdout.readline()
        if not response_line:
            # 检查 stderr 获取错误信息
            stderr_data = b""
            if self._process.stderr:
                with contextlib.suppress(TimeoutError):
                    stderr_data = await asyncio.wait_for(
                        self._process.stderr.read(4096), timeout=2.0
                    )
            raise RuntimeError(
                f"扫描引擎无响应。stderr: {stderr_data.decode('utf-8', errors='ignore')}"
            )

        return json.loads(response_line.decode("utf-8"))

    async def port_scan(
        self,
        target: str,
        port_start: int = 1,
        port_end: int = 65535,
        concurrency: int | None = None,
        timeout_ms: int | None = None,
    ) -> dict[str, Any]:
        """执行端口扫描

        Args:
            target: 目标 IP 或域名
            port_start: 起始端口
            port_end: 结束端口
            concurrency: 并发数（默认使用配置值）
            timeout_ms: 超时时间（默认使用配置值）

        Returns:
            扫描结果字典，包含 open_ports 列表
        """
        request = {
            "type": "port_scan",
            "target": target,
            "ports": {"start": port_start, "end": port_end},
            "concurrency": concurrency or self._config.port_scan_concurrency,
            "timeout_ms": timeout_ms or self._config.timeout_ms,
        }
        return await self._send_and_receive(request)

    async def dir_bust(
        self,
        target_url: str,
        wordlist: list[str] | None = None,
        extensions: list[str] | None = None,
        concurrency: int | None = None,
        timeout_ms: int | None = None,
    ) -> dict[str, Any]:
        """执行目录/路径爆破

        Args:
            target_url: 目标 URL（如 http://example.com）
            wordlist: 字典列表（默认从配置的字典文件加载）
            extensions: 扩展名列表（如 ["php", "jsp", "html"]）
            concurrency: 并发数
            timeout_ms: 超时时间

        Returns:
            爆破结果字典，包含 found_paths 列表
        """
        if wordlist is None:
            wordlist = self._load_wordlist()

        request = {
            "type": "dir_bust",
            "target_url": target_url,
            "wordlist": wordlist,
            "concurrency": concurrency or self._config.dir_bust_concurrency,
            "timeout_ms": timeout_ms or self._config.timeout_ms,
            "extensions": extensions or ["php", "jsp", "html", "json", "xml", "txt", "bak"],
        }
        return await self._send_and_receive(request)

    async def fingerprint(
        self,
        target_url: str,
        timeout_ms: int | None = None,
    ) -> dict[str, Any]:
        """执行 HTTP 指纹识别

        Args:
            target_url: 目标 URL
            timeout_ms: 超时时间

        Returns:
            指纹识别结果字典
        """
        request = {
            "type": "fingerprint",
            "target_url": target_url,
            "timeout_ms": timeout_ms or self._config.timeout_ms,
        }
        return await self._send_and_receive(request)

    async def active_scan(
        self,
        target_url: str,
        scan_types: list[str] | None = None,
        concurrency: int | None = None,
        timeout_ms: int | None = None,
    ) -> dict[str, Any]:
        """执行主动漏洞扫描 (DAST)

        Args:
            target_url: 目标 URL
            scan_types: 扫描类型列表 ["sqli", "xss", "cmdi"]，默认全部
            concurrency: 并发数
            timeout_ms: 超时时间

        Returns:
            主动扫描结果字典，包含 vulnerabilities 列表
        """
        request = {
            "type": "active_scan",
            "target_url": target_url,
            "scan_types": scan_types or ["all"],
            "concurrency": concurrency or 10,  # 默认并发 10
            "timeout_ms": timeout_ms or self._config.timeout_ms,
        }
        return await self._send_and_receive(request)

    async def shutdown(self) -> None:
        """优雅关闭扫描引擎"""
        if self._process and self._process.stdin:
            try:
                request = {"type": "shutdown"}
                request_line = json.dumps(request) + "\n"
                self._process.stdin.write(request_line.encode("utf-8"))
                await self._process.stdin.drain()
            except Exception:
                pass
            finally:
                try:
                    self._process.terminate()
                    await asyncio.wait_for(self._process.wait(), timeout=5.0)
                except (TimeoutError, ProcessLookupError):
                    self._process.kill()
                self._process = None

    def _load_wordlist(self) -> list[str]:
        """从配置的字典文件加载 wordlist"""
        path = Path(self._config.wordlist_path)
        if not path.exists():
            raise FileNotFoundError(f"字典文件不存在: {path}")
        words = []
        with open(path, encoding="utf-8") as f:
            for line in f:
                word = line.strip()
                if word and not word.startswith("#"):
                    words.append(word)
        return words

    async def __aenter__(self) -> ScannerBridge:
        await self.start()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.shutdown()
