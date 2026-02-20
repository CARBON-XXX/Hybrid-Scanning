"""企业资产管理系统 - 主应用

包含完整的用户管理、资产管理、报告管理、系统运维功能。
本应用 **故意包含多种安全漏洞**，用于安全扫描引擎的测试验证。
"""
import hashlib
import os
import pickle
import sqlite3
import subprocess
import yaml

import requests
from flask import (
    Flask, request, redirect, url_for, session,
    render_template_string, jsonify, send_file, abort,
)
from werkzeug.utils import secure_filename

from config import Config
from models import db, User, Asset, Report, AuditLog


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    with app.app_context():
        db.create_all()
        _seed_data()

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(app.config["BACKUP_DIR"], exist_ok=True)

    register_routes(app)
    return app


def _seed_data():
    if User.query.count() == 0:
        admin = User(
            username="admin",
            password=hashlib.md5("admin123".encode()).hexdigest(),
            email="admin@enterprise.local",
            role="admin",
            department="IT Security",
        )
        auditor = User(
            username="auditor",
            password=hashlib.md5("audit2024".encode()).hexdigest(),
            email="auditor@enterprise.local",
            role="auditor",
            department="Internal Audit",
        )
        user = User(
            username="zhangsan",
            password=hashlib.md5("zhang@2024".encode()).hexdigest(),
            email="zhangsan@enterprise.local",
            role="user",
            department="R&D",
        )
        db.session.add_all([admin, auditor, user])

        assets = [
            Asset(name="Web-Server-01", asset_type="server", ip_address="10.0.1.10",
                  hostname="web01.internal", os_info="Ubuntu 22.04 LTS", location="机房A-01",
                  status="active", risk_level="high", owner_id=1),
            Asset(name="DB-Master", asset_type="database", ip_address="10.0.2.20",
                  hostname="db-master.internal", os_info="CentOS 7", location="机房A-02",
                  status="active", risk_level="critical", owner_id=1),
            Asset(name="Core-Switch-01", asset_type="network", ip_address="10.0.0.1",
                  hostname="core-sw01", os_info="Cisco IOS 15.2", location="机房A-Core",
                  status="active", risk_level="critical", owner_id=1),
            Asset(name="OA-System", asset_type="application", ip_address="10.0.3.30",
                  hostname="oa.enterprise.local", os_info="Windows Server 2019", location="机房B-01",
                  status="active", risk_level="medium", owner_id=3),
            Asset(name="VPN-Gateway", asset_type="network", ip_address="10.0.0.254",
                  hostname="vpn.enterprise.local", os_info="FortiOS 7.2", location="DMZ",
                  status="active", risk_level="high", owner_id=1),
        ]
        db.session.add_all(assets)
        db.session.commit()


# ============================================================
# 路由注册
# ============================================================

def register_routes(app: Flask):

    # --------------------------------------------------------
    # 认证模块
    # --------------------------------------------------------

    @app.route("/")
    def index():
        if "user_id" not in session:
            return redirect(url_for("login"))
        return redirect(url_for("dashboard"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template_string(LOGIN_TEMPLATE)

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # [VULN: SQL注入] 直接拼接用户输入到 SQL 查询
        conn = sqlite3.connect("instance/enterprise.db")
        cursor = conn.cursor()
        query = f"SELECT id, username, role FROM users WHERE username='{username}' AND password='{hashlib.md5(password.encode()).hexdigest()}'"
        cursor.execute(query)
        row = cursor.fetchone()
        conn.close()

        if row:
            session["user_id"] = row[0]
            session["username"] = row[1]
            session["role"] = row[2]
            return redirect(url_for("dashboard"))

        return render_template_string(LOGIN_TEMPLATE, error="用户名或密码错误")

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # --------------------------------------------------------
    # 仪表盘
    # --------------------------------------------------------

    @app.route("/dashboard")
    def dashboard():
        if "user_id" not in session:
            return redirect(url_for("login"))
        asset_count = Asset.query.count()
        critical_assets = Asset.query.filter_by(risk_level="critical").count()
        user_count = User.query.count()
        report_count = Report.query.count()
        return render_template_string(
            DASHBOARD_TEMPLATE,
            username=session.get("username"),
            role=session.get("role"),
            asset_count=asset_count,
            critical_assets=critical_assets,
            user_count=user_count,
            report_count=report_count,
        )

    # --------------------------------------------------------
    # 资产管理模块
    # --------------------------------------------------------

    @app.route("/api/assets", methods=["GET"])
    def api_list_assets():
        if "user_id" not in session:
            return jsonify({"error": "unauthorized"}), 401

        keyword = request.args.get("keyword", "")
        asset_type = request.args.get("type", "")

        # [VULN: SQL注入] 搜索功能拼接用户输入
        conn = sqlite3.connect("instance/enterprise.db")
        cursor = conn.cursor()
        sql = "SELECT id, name, asset_type, ip_address, status, risk_level FROM assets WHERE 1=1"
        if keyword:
            sql += f" AND (name LIKE '%{keyword}%' OR ip_address LIKE '%{keyword}%')"
        if asset_type:
            sql += f" AND asset_type='{asset_type}'"
        cursor.execute(sql)
        rows = cursor.fetchall()
        conn.close()

        assets = [
            {"id": r[0], "name": r[1], "type": r[2], "ip": r[3], "status": r[4], "risk": r[5]}
            for r in rows
        ]
        return jsonify({"assets": assets, "total": len(assets)})

    @app.route("/api/assets", methods=["POST"])
    def api_create_asset():
        if "user_id" not in session:
            return jsonify({"error": "unauthorized"}), 401

        data = request.get_json()
        asset = Asset(
            name=data.get("name", ""),
            asset_type=data.get("asset_type", "server"),
            ip_address=data.get("ip_address", ""),
            hostname=data.get("hostname", ""),
            os_info=data.get("os_info", ""),
            location=data.get("location", ""),
            status="active",
            risk_level=data.get("risk_level", "low"),
            owner_id=session["user_id"],
            notes=data.get("notes", ""),
        )
        db.session.add(asset)
        db.session.commit()
        return jsonify({"id": asset.id, "message": "创建成功"})

    @app.route("/api/assets/<int:asset_id>", methods=["DELETE"])
    def api_delete_asset(asset_id: int):
        if "user_id" not in session:
            return jsonify({"error": "unauthorized"}), 401
        # [VULN: 越权] 未校验资产归属，任意用户可删除任意资产
        asset = Asset.query.get_or_404(asset_id)
        db.session.delete(asset)
        db.session.commit()
        return jsonify({"message": "删除成功"})

    # --------------------------------------------------------
    # 报告管理模块
    # --------------------------------------------------------

    @app.route("/api/reports", methods=["GET"])
    def api_list_reports():
        if "user_id" not in session:
            return jsonify({"error": "unauthorized"}), 401
        reports = Report.query.order_by(Report.created_at.desc()).all()
        return jsonify({
            "reports": [
                {"id": r.id, "title": r.title, "type": r.report_type,
                 "severity": r.severity, "created_at": str(r.created_at)}
                for r in reports
            ]
        })

    @app.route("/api/reports", methods=["POST"])
    def api_create_report():
        if "user_id" not in session:
            return jsonify({"error": "unauthorized"}), 401

        data = request.get_json()
        report = Report(
            title=data.get("title", ""),
            content=data.get("content", ""),
            report_type=data.get("report_type", "assessment"),
            severity=data.get("severity", "info"),
            author_id=session["user_id"],
        )
        db.session.add(report)
        db.session.commit()
        return jsonify({"id": report.id, "message": "报告已创建"})

    @app.route("/report/preview")
    def report_preview():
        """报告预览功能"""
        if "user_id" not in session:
            return redirect(url_for("login"))

        # [VULN: SSTI 模板注入] 用户输入直接作为模板内容渲染
        template_content = request.args.get("content", "")
        if template_content:
            return render_template_string(template_content)
        return render_template_string("<p>请提供报告内容进行预览</p>")

    # --------------------------------------------------------
    # 文件管理模块
    # --------------------------------------------------------

    @app.route("/api/upload", methods=["POST"])
    def api_upload():
        if "user_id" not in session:
            return jsonify({"error": "unauthorized"}), 401

        if "file" not in request.files:
            return jsonify({"error": "未选择文件"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "文件名为空"}), 400

        # [VULN: 不安全的文件上传] 仅依赖客户端文件名，未校验文件类型和内容
        filename = file.filename
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(save_path)

        return jsonify({
            "message": "上传成功",
            "filename": filename,
            "path": save_path,
        })

    @app.route("/api/download")
    def api_download():
        if "user_id" not in session:
            return jsonify({"error": "unauthorized"}), 401

        # [VULN: 路径遍历 / 任意文件读取] 用户控制的文件路径未做校验
        filepath = request.args.get("file", "")
        if not filepath:
            return jsonify({"error": "请指定文件路径"}), 400

        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True)
        return jsonify({"error": "文件不存在"}), 404

    @app.route("/api/file/read")
    def api_file_read():
        """读取服务器上的日志/配置文件"""
        if "user_id" not in session:
            return jsonify({"error": "unauthorized"}), 401

        # [VULN: 任意文件读取] 直接用用户输入打开文件
        filename = request.args.get("name", "")
        try:
            with open(filename, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(65536)
            return jsonify({"filename": filename, "content": content})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # --------------------------------------------------------
    # 系统运维模块
    # --------------------------------------------------------

    @app.route("/api/system/ping", methods=["POST"])
    def api_ping():
        """网络连通性检测"""
        if "user_id" not in session:
            return jsonify({"error": "unauthorized"}), 401

        data = request.get_json()
        target = data.get("target", "")

        # [VULN: 命令注入] 直接将用户输入拼接到系统命令
        result = subprocess.run(
            f"ping -n 4 {target}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return jsonify({
            "target": target,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        })

    @app.route("/api/system/nslookup", methods=["POST"])
    def api_nslookup():
        """DNS 查询"""
        if "user_id" not in session:
            return jsonify({"error": "unauthorized"}), 401

        data = request.get_json()
        domain = data.get("domain", "")

        # [VULN: 命令注入] 同上
        output = os.popen(f"nslookup {domain}").read()
        return jsonify({"domain": domain, "result": output})

    @app.route("/api/system/backup", methods=["POST"])
    def api_backup():
        """数据库备份"""
        if session.get("role") != "admin":
            return jsonify({"error": "权限不足"}), 403

        data = request.get_json()
        backup_name = data.get("name", "backup")

        # [VULN: 命令注入] 备份文件名用户可控
        backup_path = os.path.join(app.config["BACKUP_DIR"], backup_name)
        cmd = f"copy instance\\enterprise.db {backup_path}"
        os.system(cmd)

        return jsonify({"message": "备份完成", "path": backup_path})

    # --------------------------------------------------------
    # 内部服务代理
    # --------------------------------------------------------

    @app.route("/api/proxy")
    def api_proxy():
        """内部服务请求代理"""
        if "user_id" not in session:
            return jsonify({"error": "unauthorized"}), 401

        # [VULN: SSRF] 用户控制请求目标 URL
        target_url = request.args.get("url", "")
        if not target_url:
            return jsonify({"error": "请指定目标 URL"}), 400

        try:
            resp = requests.get(target_url, timeout=10)
            return jsonify({
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:10000],
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/webhook", methods=["POST"])
    def api_webhook():
        """接收外部 Webhook 回调"""
        data = request.get_json()
        callback_url = data.get("callback_url", "")

        # [VULN: SSRF] Webhook 回调地址用户可控
        if callback_url:
            try:
                requests.post(callback_url, json={"status": "received"}, timeout=5)
            except Exception:
                pass

        return jsonify({"message": "webhook processed"})

    # --------------------------------------------------------
    # 数据导入导出
    # --------------------------------------------------------

    @app.route("/api/import/yaml", methods=["POST"])
    def api_import_yaml():
        """YAML 配置导入"""
        if "user_id" not in session:
            return jsonify({"error": "unauthorized"}), 401

        content = request.get_data(as_text=True)

        # [VULN: 不安全的反序列化] yaml.load 未使用 SafeLoader
        data = yaml.load(content, Loader=yaml.FullLoader)
        return jsonify({"imported": data})

    @app.route("/api/import/data", methods=["POST"])
    def api_import_data():
        """序列化数据导入"""
        if "user_id" not in session:
            return jsonify({"error": "unauthorized"}), 401

        if "file" not in request.files:
            return jsonify({"error": "缺少文件"}), 400

        file = request.files["file"]
        # [VULN: 不安全的反序列化] pickle 加载不可信数据
        data = pickle.loads(file.read())
        return jsonify({"message": "导入完成", "count": len(data) if isinstance(data, list) else 1})

    # --------------------------------------------------------
    # 用户管理 (管理员)
    # --------------------------------------------------------

    @app.route("/api/users", methods=["GET"])
    def api_list_users():
        if session.get("role") != "admin":
            return jsonify({"error": "权限不足"}), 403

        keyword = request.args.get("q", "")

        # [VULN: SQL注入] 用户搜索
        conn = sqlite3.connect("instance/enterprise.db")
        cursor = conn.cursor()
        sql = f"SELECT id, username, email, role, department, is_active FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
        cursor.execute(sql)
        rows = cursor.fetchall()
        conn.close()

        users = [
            {"id": r[0], "username": r[1], "email": r[2], "role": r[3],
             "department": r[4], "is_active": bool(r[5])}
            for r in rows
        ]
        return jsonify({"users": users})

    @app.route("/api/users/<int:user_id>/password", methods=["PUT"])
    def api_reset_password(user_id: int):
        """重置用户密码"""
        if session.get("role") != "admin":
            return jsonify({"error": "权限不足"}), 403

        data = request.get_json()
        new_password = data.get("password", "")

        # [VULN: 弱哈希] 使用 MD5 存储密码
        user = User.query.get_or_404(user_id)
        user.password = hashlib.md5(new_password.encode()).hexdigest()
        db.session.commit()
        return jsonify({"message": f"用户 {user.username} 密码已重置"})

    # --------------------------------------------------------
    # 搜索功能
    # --------------------------------------------------------

    @app.route("/search")
    def search():
        if "user_id" not in session:
            return redirect(url_for("login"))

        query = request.args.get("q", "")
        results = []

        if query:
            # [VULN: XSS] 搜索关键词直接回显到页面
            return render_template_string(
                f'<h2>搜索结果: {query}</h2>'
                '<p>共找到 {{ count }} 条结果</p>'
                '{% for r in results %}<div>{{ r }}</div>{% endfor %}',
                count=len(results),
                results=results,
            )

        return render_template_string('<form action="/search"><input name="q" placeholder="搜索资产..."><button>搜索</button></form>')

    # --------------------------------------------------------
    # 审计日志
    # --------------------------------------------------------

    @app.route("/api/audit/export")
    def api_audit_export():
        """导出审计日志"""
        if session.get("role") not in ("admin", "auditor"):
            return jsonify({"error": "权限不足"}), 403

        format_type = request.args.get("format", "json")

        logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(1000).all()
        data = [
            {"id": l.id, "user_id": l.user_id, "action": l.action,
             "target": l.target, "ip": l.ip_address, "time": str(l.timestamp)}
            for l in logs
        ]

        if format_type == "json":
            return jsonify({"logs": data})
        else:
            # 简易 CSV 导出
            csv_lines = ["id,user_id,action,target,ip,time"]
            for d in data:
                csv_lines.append(f"{d['id']},{d['user_id']},{d['action']},{d['target']},{d['ip']},{d['time']}")
            return "\n".join(csv_lines), 200, {"Content-Type": "text/csv"}

    # --------------------------------------------------------
    # 健康检查 & 系统信息
    # --------------------------------------------------------

    @app.route("/api/health")
    def api_health():
        return jsonify({"status": "ok", "version": "1.2.0"})

    @app.route("/api/system/info")
    def api_system_info():
        """系统信息（不需要认证 - 信息泄露）"""
        # [VULN: 信息泄露] 未授权访问敏感系统信息
        import platform
        return jsonify({
            "hostname": platform.node(),
            "os": platform.platform(),
            "python": platform.python_version(),
            "arch": platform.machine(),
            "db_uri": app.config["SQLALCHEMY_DATABASE_URI"],
        })


# ============================================================
# HTML 模板（内嵌简化版本）
# ============================================================

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><title>企业资产管理系统 - 登录</title>
<style>
body{font-family:system-ui;background:#f0f2f5;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.login-box{background:#fff;padding:40px;border-radius:8px;box-shadow:0 2px 20px rgba(0,0,0,.1);width:360px}
h2{text-align:center;color:#1a1a1a;margin-bottom:30px}
input{width:100%;padding:12px;margin:8px 0;border:1px solid #d9d9d9;border-radius:4px;box-sizing:border-box;font-size:14px}
button{width:100%;padding:12px;background:#1677ff;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:15px;margin-top:16px}
button:hover{background:#4096ff}
.error{color:#ff4d4f;text-align:center;margin-top:12px;font-size:13px}
.footer{text-align:center;color:#999;margin-top:20px;font-size:12px}
</style></head>
<body>
<div class="login-box">
<h2>Enterprise Asset Manager</h2>
<form method="POST">
<input name="username" placeholder="用户名" required>
<input name="password" type="password" placeholder="密码" required>
<button type="submit">登  录</button>
</form>
{% if error %}<p class="error">{{ error }}</p>{% endif %}
<p class="footer">v1.2.0 | IT Security Department</p>
</div>
</body></html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><title>仪表盘 - 企业资产管理系统</title>
<style>
body{font-family:system-ui;background:#f0f2f5;margin:0;padding:0}
.nav{background:#001529;color:#fff;padding:0 24px;display:flex;align-items:center;height:48px}
.nav h3{margin:0;flex:1}
.nav a{color:#ffffffa6;text-decoration:none;margin-left:16px;font-size:13px}
.nav a:hover{color:#fff}
.content{padding:24px;max-width:1200px;margin:0 auto}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
.card{background:#fff;padding:24px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.card h4{margin:0 0 8px;color:#666;font-size:13px;font-weight:normal}
.card .value{font-size:28px;font-weight:600;color:#1a1a1a}
.card.critical .value{color:#ff4d4f}
.section{background:#fff;padding:24px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.08);margin-bottom:16px}
.section h3{margin-top:0;color:#1a1a1a}
</style></head>
<body>
<div class="nav">
<h3>Enterprise Asset Manager</h3>
<span>{{ username }} ({{ role }})</span>
<a href="/search">搜索</a>
<a href="/api/assets">资产API</a>
<a href="/api/reports">报告API</a>
<a href="/logout">退出</a>
</div>
<div class="content">
<div class="cards">
<div class="card"><h4>资产总数</h4><div class="value">{{ asset_count }}</div></div>
<div class="card critical"><h4>高危资产</h4><div class="value">{{ critical_assets }}</div></div>
<div class="card"><h4>系统用户</h4><div class="value">{{ user_count }}</div></div>
<div class="card"><h4>安全报告</h4><div class="value">{{ report_count }}</div></div>
</div>
<div class="section">
<h3>功能模块</h3>
<p>资产管理 | 安全报告 | 系统运维 | 审计日志 | 用户管理 | 数据导入导出</p>
</div>
</div>
</body></html>
"""


if __name__ == "__main__":
    application = create_app()
    application.run(host="0.0.0.0", port=5000, debug=True)
