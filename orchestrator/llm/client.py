"""DeepSeek API 客户端 - 支持 DeepSeek-V3.2 思考/非思考模式"""
from __future__ import annotations

from typing import Any, Optional

from openai import AsyncOpenAI

from orchestrator.config import LLMConfig

# DeepSeek-V3.2 思考模式对应的模型名
REASONER_MODEL = "deepseek-reasoner"


class DeepSeekClient:
    """DeepSeek API 客户端

    支持 DeepSeek-V3.2 两种模式：
    - deepseek-chat    : V3.2 非思考模式，支持 temperature / json_mode / system role
    - deepseek-reasoner : V3.2 思考模式，不支持 temperature / top_p / json_mode，
                          system 角色需合并到 user 消息中
    """

    def __init__(self, config: LLMConfig) -> None:
        self._config = config
        self._client = AsyncOpenAI(
            api_key=config.api_key,
            base_url=config.base_url,
        )

    @property
    def is_reasoner(self) -> bool:
        return self._config.model == REASONER_MODEL

    @property
    def model_name(self) -> str:
        if self._config.model == REASONER_MODEL:
            return "DeepSeek-V3.2-Thinking"
        return "DeepSeek-V3.2"

    async def chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        json_mode: bool = False,
    ) -> str:
        """发送对话请求并返回助手回复内容

        自动根据模式调整参数：
        - V3.2 非思考 (deepseek-chat): 完整参数支持
        - V3.2 思考 (deepseek-reasoner): 移除不支持的参数，合并 system 到 user
        """
        final_messages = self._prepare_messages(messages)

        kwargs: dict[str, Any] = {
            "model": self._config.model,
            "messages": final_messages,
            "stream": False,
        }

        if self.is_reasoner:
            # V3.2 思考模式不支持 temperature, top_p, response_format, max_tokens
            # 改用 max_completion_tokens
            kwargs["max_completion_tokens"] = max_tokens or self._config.max_tokens
        else:
            # V3.2 非思考模式支持完整参数
            kwargs["temperature"] = temperature if temperature is not None else self._config.temperature
            kwargs["max_tokens"] = max_tokens if max_tokens is not None else self._config.max_tokens
            if json_mode:
                kwargs["response_format"] = {"type": "json_object"}

        response = await self._client.chat.completions.create(**kwargs)
        content = response.choices[0].message.content or ""

        # V3.2 思考模式额外返回 reasoning_content，这里只取最终结果
        return content

    def _prepare_messages(
        self, messages: list[dict[str, str]]
    ) -> list[dict[str, str]]:
        """V3.2 思考模式不支持 system role，需合并到第一条 user 消息"""
        if not self.is_reasoner:
            return messages

        system_parts: list[str] = []
        other_messages: list[dict[str, str]] = []

        for msg in messages:
            if msg["role"] == "system":
                system_parts.append(msg["content"])
            else:
                other_messages.append(msg)

        if system_parts and other_messages:
            # 将 system 内容前置到第一条 user 消息
            prefix = "\n".join(system_parts) + "\n\n"
            first = other_messages[0]
            if first["role"] == "user":
                other_messages[0] = {
                    "role": "user",
                    "content": prefix + first["content"],
                }
            else:
                other_messages.insert(0, {"role": "user", "content": prefix})

        return other_messages

    async def analyze_code(
        self,
        code: str,
        language: str,
        context: str = "",
    ) -> str:
        """使用 LLM 分析代码中的安全漏洞（验证模式：针对已知片段）

        Args:
            code: 源代码内容
            language: 编程语言
            context: 额外的上下文信息（如文件路径、项目描述等）

        Returns:
            LLM 的分析结果（JSON 格式字符串）
        """
        from .prompts import PromptTemplates

        messages = PromptTemplates.code_audit(code, language, context)
        return await self.chat(messages, json_mode=True)

    async def deep_audit_file(
        self,
        code: str,
        language: str,
        file_path: str,
    ) -> str:
        """LLM 独立深度审计（审计模式：独立发现漏洞，不依赖正则）

        Args:
            code: 完整源文件内容
            language: 编程语言
            file_path: 文件路径（提供上下文）

        Returns:
            LLM 审计结果（JSON 格式字符串）
        """
        from .prompts import PromptTemplates

        messages = PromptTemplates.deep_audit(code, language, file_path)
        # 深度审计需要更多 token
        return await self.chat(messages, json_mode=True, max_tokens=8192)

    async def analyze_scan_results(
        self,
        fingerprint_data: dict[str, Any],
        open_ports: list[dict[str, Any]],
        found_paths: list[dict[str, Any]],
    ) -> str:
        """使用 LLM 综合分析扫描结果，推理潜在漏洞

        Args:
            fingerprint_data: 指纹识别结果
            open_ports: 开放端口列表
            found_paths: 发现的路径列表

        Returns:
            LLM 的综合分析结果（JSON 格式字符串）
        """
        from .prompts import PromptTemplates

        messages = PromptTemplates.scan_analysis(fingerprint_data, open_ports, found_paths)
        return await self.chat(messages, json_mode=True)

    async def analyze_dependencies(
        self,
        dependencies: dict[str, str],
        ecosystem: str,
    ) -> str:
        """SCA 依赖安全分析

        Args:
            dependencies: 依赖包名和版本号字典
            ecosystem: 生态系统名称 (e.g. "npm", "pypi")

        Returns:
            SCA 分析结果（JSON 格式字符串）
        """
        from .prompts import PromptTemplates

        messages = PromptTemplates.sca_analysis(dependencies, ecosystem)
        return await self.chat(messages, json_mode=True)

    async def audit_iac_config(
        self,
        content: str,
        file_type: str,
    ) -> str:
        """IaC 基础设施代码审计

        Args:
            content: 配置文件内容
            file_type: 文件类型 (e.g. "Dockerfile", "Kubernetes Manifest")

        Returns:
            IaC 审计结果（JSON 格式字符串）
        """
        from .prompts import PromptTemplates

        messages = PromptTemplates.iac_analysis(content, file_type)
        return await self.chat(messages, json_mode=True)

    async def generate_api_payloads(self, endpoint: dict[str, Any]) -> str:
        """生成 API 安全测试 Payload

        Args:
            endpoint: API 端点定义字典

        Returns:
            测试用例列表（JSON 格式字符串）
        """
        from .prompts import PromptTemplates

        messages = PromptTemplates.api_security_test(endpoint)
        return await self.chat(messages, json_mode=True)

    async def generate_report_summary(self, findings: list[dict[str, Any]]) -> str:
        """使用 LLM 生成漏洞报告摘要

        Args:
            findings: 所有发现的漏洞列表

        Returns:
            报告摘要文本
        """
        from .prompts import PromptTemplates

        messages = PromptTemplates.report_summary(findings)
        return await self.chat(messages, temperature=0.3)
