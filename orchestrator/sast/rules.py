"""内置漏洞检测规则库 - 基于正则 + AST 模式匹配"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class VulnRule:
    """单条漏洞检测规则"""
    rule_id: str
    cwe: str
    title: str
    severity: Severity
    languages: list[str]
    pattern: str  # 正则表达式
    description: str
    remediation: str
    confidence: str = "Medium"  # High / Medium / Low
    _compiled: Optional[re.Pattern[str]] = field(default=None, repr=False)

    def compile(self) -> re.Pattern[str]:
        if self._compiled is None:
            self._compiled = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
        return self._compiled


# ============================================================
# 内置规则集
# ============================================================

BUILTIN_RULES: list[VulnRule] = [
    # ============================================================
    # SQL 注入
    # ============================================================
    VulnRule(
        rule_id="SAST-001",
        cwe="CWE-89",
        title="SQL 注入 (直接拼接)",
        severity=Severity.CRITICAL,
        languages=["python", "php", "java", "javascript"],
        pattern=r"""(?:execute|query|cursor\.execute|\.raw\(|\.extra\()\s*\(\s*(?:f['\"]|['\"].*%s|['\"].*\+|['\"].*\.format\()""",
        description="检测到字符串拼接或格式化构造 SQL 语句，可能导致 SQL 注入漏洞",
        remediation="使用参数化查询或 ORM 提供的安全方法替代字符串拼接",
        confidence="High",
    ),
    VulnRule(
        rule_id="SAST-002",
        cwe="CWE-89",
        title="SQL 注入 (f-string 构造)",
        severity=Severity.CRITICAL,
        languages=["python"],
        pattern=r"""(?:sql|query|where|select|insert|update|delete)\s*(?:\+=|=)\s*f['\"].*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|AND|OR)\b""",
        description="使用 f-string 动态构造 SQL 语句，若拼入用户输入则构成 SQL 注入",
        remediation="使用参数化查询或 ORM 安全方法",
        confidence="High",
    ),
    VulnRule(
        rule_id="SAST-003",
        cwe="CWE-89",
        title="SQL 注入 (字符串拼接)",
        severity=Severity.CRITICAL,
        languages=["python", "javascript", "java"],
        pattern=r"""(?:sql|query)\s*(?:\+\=|\=)\s*['\"].*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b.*['\"].*\+""",
        description="通过字符串拼接构造 SQL 语句",
        remediation="使用参数化查询替代字符串拼接",
        confidence="High",
    ),
    VulnRule(
        rule_id="SAST-004",
        cwe="CWE-89",
        title="SQL 注入 (格式化字符串)",
        severity=Severity.CRITICAL,
        languages=["python"],
        pattern=r"""['\"].*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b.*(?:%s|%d|\{).*['\"].*%\s*\(""",
        description="使用 % 格式化构造 SQL 语句",
        remediation="使用参数化查询替代字符串格式化",
        confidence="High",
    ),
    VulnRule(
        rule_id="SAST-005",
        cwe="CWE-89",
        title="PHP SQL 注入",
        severity=Severity.CRITICAL,
        languages=["php"],
        pattern=r"""(?:mysql_query|mysqli_query|pg_query)\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)""",
        description="直接将用户输入拼入 SQL 查询",
        remediation="使用 PDO 预编译语句 (prepared statements)",
        confidence="High",
    ),

    # ============================================================
    # 命令注入
    # ============================================================
    VulnRule(
        rule_id="SAST-010",
        cwe="CWE-78",
        title="OS 命令注入 (直接拼接)",
        severity=Severity.CRITICAL,
        languages=["python", "php", "java", "javascript"],
        pattern=r"""(?:os\.system|os\.popen|subprocess\.call|subprocess\.Popen|subprocess\.run|exec\(|shell_exec|system\(|passthru|popen)\s*\(.*(?:\+|\.format|f['\"]|\$_(?:GET|POST|REQUEST))""",
        description="用户输入被直接拼接到系统命令中，可能导致命令注入",
        remediation="使用参数列表传递命令和参数，避免 shell=True；对输入进行严格校验",
        confidence="High",
    ),
    VulnRule(
        rule_id="SAST-011",
        cwe="CWE-78",
        title="OS 命令注入 (shell=True)",
        severity=Severity.CRITICAL,
        languages=["python"],
        pattern=r"""subprocess\.(?:run|call|Popen)\s*\([^)]*shell\s*=\s*True""",
        description="subprocess 使用 shell=True，若命令字符串包含用户输入则构成命令注入",
        remediation="避免 shell=True，使用参数列表形式传递命令",
        confidence="High",
    ),
    VulnRule(
        rule_id="SAST-012",
        cwe="CWE-78",
        title="OS 命令注入 (f-string 命令构造)",
        severity=Severity.CRITICAL,
        languages=["python"],
        pattern=r"""(?:os\.system|os\.popen|subprocess\.run|subprocess\.call|subprocess\.Popen)\s*\(\s*$""",
        description="系统命令函数调用参数在下一行，需检查是否包含用户可控输入",
        remediation="使用参数列表传递命令和参数",
        confidence="Medium",
    ),
    VulnRule(
        rule_id="SAST-013",
        cwe="CWE-78",
        title="OS 命令注入 (变量传入)",
        severity=Severity.CRITICAL,
        languages=["python"],
        pattern=r"""(?:os\.system|os\.popen)\s*\(\s*(?:cmd|command|cmd_str|shell_cmd|exec_cmd)\s*\)""",
        description="系统命令函数通过变量传入命令字符串，若变量包含用户输入则构成命令注入",
        remediation="使用参数列表传递命令，避免通过变量传入完整命令字符串",
        confidence="Medium",
    ),

    # ============================================================
    # 路径遍历 / 任意文件读取
    # ============================================================
    VulnRule(
        rule_id="SAST-020",
        cwe="CWE-22",
        title="路径遍历 (直接用户输入)",
        severity=Severity.HIGH,
        languages=["python", "php", "java", "javascript"],
        pattern=r"""(?:open|file_get_contents|fopen|readFile|createReadStream|FileInputStream)\s*\(.*(?:request\.|req\.|params\.|query\.|body\.|\$_(?:GET|POST|REQUEST))""",
        description="文件操作使用了未经验证的用户输入作为路径参数",
        remediation="对文件路径进行白名单校验，规范化路径后检查前缀",
        confidence="High",
    ),
    VulnRule(
        rule_id="SAST-021",
        cwe="CWE-22",
        title="任意文件读取 (send_file / send_from_directory)",
        severity=Severity.HIGH,
        languages=["python"],
        pattern=r"""send_file\s*\(.*(?:request\.|filepath|filename|path|file)""",
        description="send_file 的路径参数可能包含用户可控输入，导致任意文件下载",
        remediation="使用 send_from_directory 并严格校验文件名，禁止路径穿越字符",
        confidence="Medium",
    ),
    VulnRule(
        rule_id="SAST-022",
        cwe="CWE-22",
        title="任意文件读取 (变量路径)",
        severity=Severity.HIGH,
        languages=["python"],
        pattern=r"""(?:open|send_file)\s*\(\s*(?:filepath|filename|file_path|fpath|fname)\s*[,)]""",
        description="文件操作使用变量作为路径，若变量来源于用户输入则构成路径遍历",
        remediation="对文件路径做白名单校验和规范化",
        confidence="Medium",
    ),

    # ============================================================
    # SSRF
    # ============================================================
    VulnRule(
        rule_id="SAST-030",
        cwe="CWE-918",
        title="SSRF (直接用户输入)",
        severity=Severity.HIGH,
        languages=["python", "php", "java", "javascript"],
        pattern=r"""(?:requests\.get|requests\.post|urllib\.request\.urlopen|file_get_contents|curl_exec|fetch|HttpURLConnection|httpx\.get|httpx\.post)\s*\(.*(?:request\.|req\.|params\.|query\.|body\.|\$_(?:GET|POST|REQUEST))""",
        description="HTTP 请求的目标 URL 由用户输入控制，可能导致 SSRF",
        remediation="对用户提供的 URL 进行严格的白名单校验，禁止访问内网地址段",
        confidence="High",
    ),
    VulnRule(
        rule_id="SAST-031",
        cwe="CWE-918",
        title="SSRF (变量 URL)",
        severity=Severity.HIGH,
        languages=["python"],
        pattern=r"""(?:requests\.get|requests\.post|httpx\.get|httpx\.post)\s*\(\s*(?:target_url|url|callback_url|redirect_url|endpoint|api_url)\s*[,)]""",
        description="HTTP 请求的目标 URL 通过变量传入，若变量来源于用户输入则构成 SSRF",
        remediation="对 URL 进行白名单校验，禁止访问内网地址段 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)",
        confidence="Medium",
    ),

    # ============================================================
    # XSS
    # ============================================================
    VulnRule(
        rule_id="SAST-040",
        cwe="CWE-79",
        title="反射型 XSS (直接回显)",
        severity=Severity.MEDIUM,
        languages=["python", "php", "javascript"],
        pattern=r"""(?:innerHTML|outerHTML|document\.write|\.html\(|echo\s|print\s|render_template_string)\s*.*(?:request\.|req\.|params\.|query\.|body\.|\$_(?:GET|POST|REQUEST))""",
        description="用户输入被直接插入到 HTML 输出中，未经转义",
        remediation="使用模板引擎的自动转义功能；对输出进行 HTML 实体编码",
        confidence="Medium",
    ),
    VulnRule(
        rule_id="SAST-041",
        cwe="CWE-79",
        title="反射型 XSS (f-string 模板)",
        severity=Severity.HIGH,
        languages=["python"],
        pattern=r"""render_template_string\s*\(\s*f['\"]""",
        description="render_template_string 使用 f-string 构建模板，用户输入可能被插入到 HTML 中未经转义",
        remediation="使用 render_template 加载独立模板文件，通过模板变量传递数据",
        confidence="High",
    ),

    # ============================================================
    # 反序列化
    # ============================================================
    VulnRule(
        rule_id="SAST-050",
        cwe="CWE-502",
        title="不安全的反序列化",
        severity=Severity.CRITICAL,
        languages=["python", "php", "java"],
        pattern=r"""(?:pickle\.loads|pickle\.load\s*\(|yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)|unserialize\s*\(|ObjectInputStream|XMLDecoder|readObject\(\))""",
        description="使用了不安全的反序列化方法，可能导致远程代码执行",
        remediation="Python: 使用 yaml.safe_load 替代 yaml.load；避免 pickle 处理不可信数据。PHP: 避免 unserialize 不可信数据。Java: 使用白名单 ObjectInputFilter",
        confidence="High",
    ),

    # ============================================================
    # 硬编码密钥
    # ============================================================
    VulnRule(
        rule_id="SAST-060",
        cwe="CWE-798",
        title="硬编码凭证 / 密钥",
        severity=Severity.HIGH,
        languages=["python", "php", "java", "javascript"],
        pattern=r"""(?:password|passwd|secret|api_key|apikey|access_token|private_key|db_password|secret_key)\s*=\s*['\"][^'\"]{8,}['\"]""",
        description="源代码中检测到硬编码的密钥或凭证",
        remediation="使用环境变量或密钥管理服务存储敏感凭证",
        confidence="Medium",
    ),

    # ============================================================
    # 弱加密
    # ============================================================
    VulnRule(
        rule_id="SAST-070",
        cwe="CWE-327",
        title="使用弱加密/哈希算法",
        severity=Severity.MEDIUM,
        languages=["python", "php", "java", "javascript"],
        pattern=r"""(?:hashlib\.md5|hashlib\.sha1|md5\s*\(|sha1\s*\(|DES\s*\(|RC4\s*\()""",
        description="使用了已知存在弱点的加密或哈希算法",
        remediation="使用 SHA-256 及以上强度的哈希算法；使用 AES-256 进行对称加密",
        confidence="Medium",
    ),

    # ============================================================
    # SSTI
    # ============================================================
    VulnRule(
        rule_id="SAST-080",
        cwe="CWE-1336",
        title="服务端模板注入 (SSTI)",
        severity=Severity.CRITICAL,
        languages=["python", "php", "java"],
        pattern=r"""render_template_string\s*\(.*(?:request\.|req\.|params\.)""",
        description="render_template_string 的模板内容包含用户可控输入，可能导致 SSTI -> RCE",
        remediation="禁止将用户输入直接作为模板内容；使用 render_template 加载文件模板",
        confidence="High",
    ),
    VulnRule(
        rule_id="SAST-081",
        cwe="CWE-1336",
        title="SSTI (模板变量注入)",
        severity=Severity.CRITICAL,
        languages=["python", "php", "java"],
        pattern=r"""(?:Template\s*\(|Environment\s*\(.*\)\.from_string|Velocity\.evaluate|FreeMarker|Smarty).*(?:request\.|req\.|params\.)""",
        description="模板引擎从用户输入构造模板，可能导致 SSTI",
        remediation="使用沙箱化模板引擎，禁止用户控制模板内容",
        confidence="High",
    ),

    # ============================================================
    # 文件上传
    # ============================================================
    VulnRule(
        rule_id="SAST-090",
        cwe="CWE-434",
        title="不安全的文件上传",
        severity=Severity.HIGH,
        languages=["python", "php", "java", "javascript"],
        pattern=r"""(?:move_uploaded_file|\.save\s*\(|\.write\s*\(|multer|FileUpload).*(?:\.filename|\.name|original_name|\$_FILES)""",
        description="文件上传处理中缺少对文件类型、大小、路径的严格校验",
        remediation="校验文件扩展名白名单、MIME 类型；限制文件大小；存储路径随机化",
        confidence="Medium",
    ),
    VulnRule(
        rule_id="SAST-091",
        cwe="CWE-434",
        title="不安全的文件上传 (未校验文件名)",
        severity=Severity.HIGH,
        languages=["python"],
        pattern=r"""filename\s*=\s*(?:file|request\.files).*\.filename""",
        description="直接使用客户端提供的文件名而未通过 secure_filename 校验",
        remediation="使用 werkzeug.utils.secure_filename 清理文件名，并校验文件扩展名白名单",
        confidence="Medium",
    ),

    # ============================================================
    # XXE
    # ============================================================
    VulnRule(
        rule_id="SAST-100",
        cwe="CWE-611",
        title="XML 外部实体注入 (XXE)",
        severity=Severity.HIGH,
        languages=["python", "php", "java"],
        pattern=r"""(?:etree\.parse|XMLParser|SAXParser|DocumentBuilder|simplexml_load|DOMDocument).*(?:request\.|req\.|params\.|\$_)""",
        description="XML 解析器未禁用外部实体，可能导致 XXE",
        remediation="禁用 XML 解析器的外部实体和 DTD 处理",
        confidence="Medium",
    ),

    # ============================================================
    # SSTI (变量传入)
    # ============================================================
    VulnRule(
        rule_id="SAST-082",
        cwe="CWE-1336",
        title="SSTI (变量模板内容)",
        severity=Severity.CRITICAL,
        languages=["python"],
        pattern=r"""render_template_string\s*\(\s*(?:template|content|tpl|tmpl|template_content|body|html|markup)\s*[,)]""",
        description="render_template_string 的模板内容通过变量传入，若变量来源于用户输入则构成 SSTI",
        remediation="禁止将用户输入作为模板内容，使用 render_template 加载文件模板",
        confidence="High",
    ),

    # ============================================================
    # IDOR / 越权访问
    # ============================================================
    VulnRule(
        rule_id="SAST-130",
        cwe="CWE-639",
        title="疑似 IDOR / 越权访问",
        severity=Severity.HIGH,
        languages=["python"],
        pattern=r"""(?:query\.get_or_404|query\.get|filter_by\s*\().*(?:delete|update|commit)(?!.*(?:session\[.user_id.\]|current_user|owner_id|author_id|user_id\s*==))""",
        description="数据操作未校验资源归属，任意用户可操作其他用户的资源",
        remediation="在所有资源操作前校验当前用户是否为资源所有者",
        confidence="Medium",
    ),
    VulnRule(
        rule_id="SAST-131",
        cwe="CWE-639",
        title="越权访问 (DELETE 无归属校验)",
        severity=Severity.HIGH,
        languages=["python"],
        pattern=r"""db\.session\.delete\s*\(.*query\.get""",
        description="执行删除操作前未校验资源归属权，可能导致任意用户删除其他用户资源",
        remediation="在删除前检查 resource.owner_id == current_user.id",
        confidence="Medium",
    ),

    # ============================================================
    # 敏感端点未授权
    # ============================================================
    VulnRule(
        rule_id="SAST-140",
        cwe="CWE-200",
        title="敏感信息泄露 (系统信息暴露)",
        severity=Severity.HIGH,
        languages=["python"],
        pattern=r"""(?:platform\.node|platform\.platform|platform\.python_version|platform\.machine|os\.uname|os\.environ)\s*\(""",
        description="代码中获取了系统信息（主机名、OS、架构等），若通过 API 返回则构成信息泄露",
        remediation="不应通过 API 暴露系统信息，如需监控应仅限管理员访问",
        confidence="Medium",
    ),
    VulnRule(
        rule_id="SAST-141",
        cwe="CWE-200",
        title="配置信息泄露 (DB URI 暴露)",
        severity=Severity.HIGH,
        languages=["python"],
        pattern=r"""app\.config\s*\[.*(?:DATABASE_URI|SECRET_KEY|PASSWORD|API_KEY|TOKEN)""",
        description="通过 API 返回了数据库连接串、密钥等配置信息",
        remediation="禁止在 API 响应中暴露内部配置信息",
        confidence="High",
    ),

    # ============================================================
    # SQL 注入 (字符串拼接 +=)
    # ============================================================
    VulnRule(
        rule_id="SAST-006",
        cwe="CWE-89",
        title="SQL 注入 (f-string += 拼接)",
        severity=Severity.CRITICAL,
        languages=["python"],
        pattern=r"""(?:sql|query|where_clause)\s*\+=\s*f['\"].*(?:AND|OR|WHERE|LIKE|ORDER|GROUP|HAVING)\b""",
        description="使用 += 拼接 f-string 到 SQL 语句，若拼入用户输入则构成 SQL 注入",
        remediation="使用参数化查询替代字符串拼接",
        confidence="High",
    ),

    # ============================================================
    # Flask/Django 调试模式
    # ============================================================
    VulnRule(
        rule_id="SAST-110",
        cwe="CWE-489",
        title="生产环境调试模式开启",
        severity=Severity.HIGH,
        languages=["python"],
        pattern=r"""\.run\s*\([^)]*debug\s*=\s*True""",
        description="Flask/Django 开启了 debug 模式，生产环境中将暴露敏感信息和交互式调试器",
        remediation="生产环境中必须关闭 debug 模式，使用环境变量控制",
        confidence="High",
    ),

    # ============================================================
    # 信息泄露
    # ============================================================
    VulnRule(
        rule_id="SAST-120",
        cwe="CWE-200",
        title="敏感信息泄露 (异常详情)",
        severity=Severity.MEDIUM,
        languages=["python", "php", "java", "javascript"],
        pattern=r"""(?:return|jsonify|json\.dumps|print|response\.write).*(?:str\s*\(\s*e\s*\)|traceback|stacktrace|exception\.getMessage)""",
        description="异常信息被直接返回给客户端，可能泄露内部实现细节",
        remediation="对客户端返回统一的错误信息，详细异常信息仅记录到服务端日志",
        confidence="Low",
    ),
]
