# -*- coding: utf-8 -*-
"""
智盾网络安全态势感知与智能防御系统 - 系统配置
ZhiDun Network Security Situational Awareness and Intelligent Defense System
"""

import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum


class LogLevel(Enum):
    """日志级别枚举"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class ThreatLevel(Enum):
    """威胁等级枚举"""
    LOW = 1         # 低危
    MEDIUM = 2      # 中危
    HIGH = 3        # 高危
    CRITICAL = 4    # 严重
    EMERGENCY = 5   # 紧急


class DetectionMode(Enum):
    """检测模式枚举"""
    PASSIVE = "passive"       # 被动检测
    ACTIVE = "active"         # 主动检测
    HYBRID = "hybrid"         # 混合检测


@dataclass
class DatabaseConfig:
    """数据库配置"""
    host: str = "127.0.0.1"
    port: int = 5432
    name: str = "zhidun_security"
    user: str = "zhidun_admin"
    password: str = ""
    pool_size: int = 20
    max_overflow: int = 10
    echo: bool = False

    @property
    def connection_url(self) -> str:
        return f"postgresql+asyncpg://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"


@dataclass
class RedisConfig:
    """Redis缓存配置"""
    host: str = "127.0.0.1"
    port: int = 6379
    db: int = 0
    password: str = ""
    max_connections: int = 50
    key_prefix: str = "zhidun:"


@dataclass
class NetworkCaptureConfig:
    """网络流量采集配置"""
    interfaces: List[str] = field(default_factory=lambda: ["eth0"])
    promiscuous_mode: bool = True
    snap_length: int = 65535
    buffer_size: int = 10 * 1024 * 1024  # 10MB
    bpf_filter: str = ""
    packet_batch_size: int = 1000
    capture_timeout: int = 30


@dataclass
class DetectionEngineConfig:
    """检测引擎配置"""
    mode: DetectionMode = DetectionMode.HYBRID
    max_workers: int = 8
    rule_update_interval: int = 3600      # 规则更新间隔(秒)
    anomaly_threshold: float = 0.85       # 异常检测阈值
    correlation_window: int = 300         # 关联分析时间窗口(秒)
    ml_model_path: str = "./models/threat_detection"
    enable_deep_inspection: bool = True
    max_packet_queue_size: int = 100000


@dataclass
class ResponseConfig:
    """自动化响应配置"""
    auto_block_enabled: bool = True
    block_duration: int = 3600            # 默认封禁时长(秒)
    max_auto_blocks: int = 1000           # 最大自动封禁数
    whitelist_ips: List[str] = field(default_factory=list)
    escalation_threshold: ThreatLevel = ThreatLevel.HIGH
    notification_channels: List[str] = field(default_factory=lambda: ["email", "sms"])


@dataclass
class ThreatIntelConfig:
    """威胁情报配置"""
    enabled: bool = True
    update_interval: int = 1800           # 情报更新间隔(秒)
    sources: List[str] = field(default_factory=lambda: [
        "local_database",
        "community_feeds",
        "commercial_feeds"
    ])
    ioc_cache_ttl: int = 86400            # IoC缓存有效期(秒)
    max_ioc_entries: int = 1000000


@dataclass
class DashboardConfig:
    """可视化仪表盘配置"""
    host: str = "0.0.0.0"
    port: int = 8443
    ssl_enabled: bool = True
    ssl_cert_path: str = "./certs/server.crt"
    ssl_key_path: str = "./certs/server.key"
    session_timeout: int = 1800
    max_connections: int = 100
    refresh_interval: int = 5             # 数据刷新间隔(秒)


@dataclass
class SystemConfig:
    """系统主配置"""
    system_name: str = "智盾网络安全态势感知与智能防御系统"
    version: str = "1.0.0"
    log_level: LogLevel = LogLevel.INFO
    log_dir: str = "./logs"
    data_dir: str = "./data"
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    redis: RedisConfig = field(default_factory=RedisConfig)
    capture: NetworkCaptureConfig = field(default_factory=NetworkCaptureConfig)
    detection: DetectionEngineConfig = field(default_factory=DetectionEngineConfig)
    response: ResponseConfig = field(default_factory=ResponseConfig)
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)

    def validate(self) -> bool:
        """验证配置有效性"""
        if self.detection.anomaly_threshold < 0 or self.detection.anomaly_threshold > 1:
            raise ValueError("异常检测阈值必须在0到1之间")
        if self.detection.max_workers < 1:
            raise ValueError("检测引擎工作线程数不能小于1")
        if self.dashboard.port < 1 or self.dashboard.port > 65535:
            raise ValueError("仪表盘端口号无效")
        return True


def load_config(config_path: Optional[str] = None) -> SystemConfig:
    """加载系统配置"""
    config = SystemConfig()

    if config_path and os.path.exists(config_path):
        import json
        with open(config_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if 'database' in data:
                config.database = DatabaseConfig(**data['database'])
            if 'redis' in data:
                config.redis = RedisConfig(**data['redis'])
            if 'capture' in data:
                config.capture = NetworkCaptureConfig(**data['capture'])
            if 'detection' in data:
                config.detection = DetectionEngineConfig(**data['detection'])

    config.validate()
    return config
