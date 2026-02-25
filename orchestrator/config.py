"""全局配置管理模块"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class LLMConfig(BaseModel):
    """DeepSeek API 配置"""

    api_key: str = Field(default="", description="DeepSeek API Key")
    base_url: str = Field(default="https://api.deepseek.com", description="API base URL")
    model: str = Field(default="deepseek-chat", description="模型名称")
    max_tokens: int = Field(default=4096, description="最大输出 token 数")
    temperature: float = Field(default=0.1, description="生成温度，安全分析场景建议低温")


class ScannerConfig(BaseModel):
    """Rust 扫描引擎配置"""

    binary_path: str = Field(
        default="./scanner-engine/target/release/scanner-engine",
        description="Rust 扫描引擎二进制路径",
    )
    port_scan_concurrency: int = Field(default=500, description="端口扫描并发数")
    dir_bust_concurrency: int = Field(default=100, description="目录爆破并发数")
    timeout_ms: int = Field(default=3000, description="单次请求超时(ms)")
    wordlist_path: str = Field(default="./wordlists/common.txt", description="字典路径")


class SASTConfig(BaseModel):
    """静态分析配置"""

    max_file_size_kb: int = Field(default=512, description="最大单文件分析大小(KB)")
    languages: list[str] = Field(
        default=["python", "javascript", "php", "java", "go", "rust", "cpp", "csharp"],
        description="支持的语言列表",
    )
    exclude_dirs: list[str] = Field(
        default=["node_modules", ".git", "__pycache__", "venv", ".venv", "vendor"],
        description="排除的目录",
    )


class SCAConfig(BaseModel):
    """SCA 依赖安全配置"""

    enabled: bool = Field(default=True, description="是否启用 SCA 扫描")
    ignored_packages: list[str] = Field(default=[], description="忽略的包名")


class IaCConfig(BaseModel):
    """IaC 基础设施安全配置"""

    enabled: bool = Field(default=True, description="是否启用 IaC 扫描")
    dockerfile_patterns: list[str] = Field(
        default=["Dockerfile*"], description="Dockerfile 文件名模式"
    )


class AppConfig(BaseModel):
    """应用主配置"""

    llm: LLMConfig = Field(default_factory=LLMConfig)
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    sast: SASTConfig = Field(default_factory=SASTConfig)
    sca: SCAConfig = Field(default_factory=SCAConfig)
    iac: IaCConfig = Field(default_factory=IaCConfig)
    report_output_dir: str = Field(default="./reports", description="报告输出目录")

    @classmethod
    def from_yaml(cls, path: str | Path) -> AppConfig:
        """从 YAML 文件加载配置"""
        p = Path(path)
        if not p.exists():
            return cls()
        with open(p, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(**data)

    def to_yaml(self, path: str | Path) -> None:
        """保存配置到 YAML 文件"""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            yaml.dump(self.model_dump(), f, default_flow_style=False, allow_unicode=True)
