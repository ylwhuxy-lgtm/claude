# -*- coding: utf-8 -*-
"""
智盾网络安全态势感知与智能防御系统 - 日志管理工具
提供统一的日志记录、轮转和格式化功能
"""

import logging
import os
import sys
import time
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from typing import Optional


class ColorFormatter(logging.Formatter):
    """彩色日志格式化器"""

    COLORS = {
        logging.DEBUG: "\033[36m",      # 青色
        logging.INFO: "\033[32m",       # 绿色
        logging.WARNING: "\033[33m",    # 黄色
        logging.ERROR: "\033[31m",      # 红色
        logging.CRITICAL: "\033[35m",   # 紫色
    }
    RESET = "\033[0m"

    def __init__(self, fmt: Optional[str] = None):
        if fmt is None:
            fmt = "%(asctime)s [%(levelname)-8s] %(name)-20s: %(message)s"
        super().__init__(fmt, datefmt="%Y-%m-%d %H:%M:%S")

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelno, "")
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


class SecurityEventFormatter(logging.Formatter):
    """安全事件日志格式化器

    输出结构化的安全事件日志，便于SIEM系统采集
    """

    def __init__(self):
        fmt = (
            "%(asctime)s|%(levelname)s|%(name)s|%(event_type)s|"
            "%(src_ip)s|%(dst_ip)s|%(message)s"
        )
        super().__init__(fmt, datefmt="%Y-%m-%dT%H:%M:%S%z")

    def format(self, record: logging.LogRecord) -> str:
        if not hasattr(record, 'event_type'):
            record.event_type = "SYSTEM"
        if not hasattr(record, 'src_ip'):
            record.src_ip = "-"
        if not hasattr(record, 'dst_ip'):
            record.dst_ip = "-"
        return super().format(record)


class LogManager:
    """日志管理器

    功能：
    1. 多级别日志输出（控制台+文件）
    2. 日志文件自动轮转
    3. 安全事件专用日志
    4. 审计日志独立记录
    5. 结构化日志格式支持
    """

    DEFAULT_FORMAT = "%(asctime)s [%(levelname)-8s] %(name)-20s: %(message)s"
    DEFAULT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
    BACKUP_COUNT = 30

    def __init__(self, log_dir: str = "./logs", level: str = "INFO"):
        self.log_dir = log_dir
        self.level = getattr(logging, level.upper(), logging.INFO)
        self._loggers = {}

        os.makedirs(log_dir, exist_ok=True)
        self._setup_root_logger()
        self._setup_security_logger()
        self._setup_audit_logger()

    def _setup_root_logger(self):
        """配置根日志器"""
        root_logger = logging.getLogger("zhidun")
        root_logger.setLevel(self.level)
        root_logger.handlers.clear()

        # 控制台处理器
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(self.level)
        console_handler.setFormatter(ColorFormatter())
        root_logger.addHandler(console_handler)

        # 文件处理器 - 按大小轮转
        file_handler = RotatingFileHandler(
            os.path.join(self.log_dir, "zhidun.log"),
            maxBytes=self.MAX_FILE_SIZE,
            backupCount=self.BACKUP_COUNT,
            encoding='utf-8'
        )
        file_handler.setLevel(self.level)
        file_handler.setFormatter(logging.Formatter(
            self.DEFAULT_FORMAT, datefmt=self.DEFAULT_DATE_FORMAT
        ))
        root_logger.addHandler(file_handler)

        # 错误日志单独输出
        error_handler = RotatingFileHandler(
            os.path.join(self.log_dir, "zhidun_error.log"),
            maxBytes=self.MAX_FILE_SIZE,
            backupCount=self.BACKUP_COUNT,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(logging.Formatter(
            self.DEFAULT_FORMAT, datefmt=self.DEFAULT_DATE_FORMAT
        ))
        root_logger.addHandler(error_handler)

        self._loggers["root"] = root_logger

    def _setup_security_logger(self):
        """配置安全事件日志器"""
        sec_logger = logging.getLogger("zhidun.security")
        sec_logger.setLevel(logging.INFO)

        sec_handler = TimedRotatingFileHandler(
            os.path.join(self.log_dir, "security_events.log"),
            when='midnight',
            interval=1,
            backupCount=90,
            encoding='utf-8'
        )
        sec_handler.setFormatter(SecurityEventFormatter())
        sec_logger.addHandler(sec_handler)

        self._loggers["security"] = sec_logger

    def _setup_audit_logger(self):
        """配置审计日志器"""
        audit_logger = logging.getLogger("zhidun.audit")
        audit_logger.setLevel(logging.INFO)

        audit_handler = TimedRotatingFileHandler(
            os.path.join(self.log_dir, "audit.log"),
            when='midnight',
            interval=1,
            backupCount=365,  # 审计日志保留1年
            encoding='utf-8'
        )
        audit_handler.setFormatter(logging.Formatter(
            "%(asctime)s|AUDIT|%(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S"
        ))
        audit_logger.addHandler(audit_handler)

        self._loggers["audit"] = audit_logger

    def get_logger(self, name: str) -> logging.Logger:
        """获取指定名称的日志器"""
        logger_name = f"zhidun.{name}" if not name.startswith("zhidun") else name
        return logging.getLogger(logger_name)

    def log_security_event(self, event_type: str, message: str,
                           src_ip: str = "-", dst_ip: str = "-",
                           level: int = logging.WARNING):
        """记录安全事件"""
        sec_logger = self._loggers.get("security")
        if sec_logger:
            sec_logger.log(level, message, extra={
                "event_type": event_type,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
            })

    def log_audit(self, user: str, action: str, resource: str,
                  result: str, ip: str = "-"):
        """记录审计事件"""
        audit_logger = self._loggers.get("audit")
        if audit_logger:
            audit_logger.info(f"{user}|{action}|{resource}|{result}|{ip}")

    def set_level(self, level: str):
        """动态调整日志级别"""
        self.level = getattr(logging, level.upper(), logging.INFO)
        for logger in self._loggers.values():
            logger.setLevel(self.level)
