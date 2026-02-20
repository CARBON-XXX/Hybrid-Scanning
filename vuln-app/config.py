"""应用配置 - 企业资产管理系统"""
import os

class Config:
    SECRET_KEY = "hardcoded_secret_key_2024_enterprise"
    SQLALCHEMY_DATABASE_URI = "sqlite:///enterprise.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    ADMIN_PASSWORD = "admin@123456"
    API_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.hardcoded_token"
    INTERNAL_API_BASE = "http://127.0.0.1:5000"
    BACKUP_DIR = os.path.join(os.path.dirname(__file__), "backups")
    LOG_FILE = os.path.join(os.path.dirname(__file__), "app.log")
    DB_PASSWORD = "mysql_root_P@ssw0rd_2024"
