# -*- coding: utf-8 -*-
"""
智盾网络安全态势感知与智能防御系统 V1.0
ZhiDun Network Security Situational Awareness and Intelligent Defense System

主程序入口 - 系统启动、模块编排与生命周期管理

版权所有 (C) 2026 智盾科技
"""

import asyncio
import logging
import signal
import sys
import time
from typing import Optional

from config.settings import SystemConfig, load_config
from core.traffic_capture import TrafficCaptureEngine
from core.threat_detector import ThreatDetectionEngine, ThreatAlert
from core.situation_awareness import SituationAwarenessEngine
from core.auto_response import AutoResponseEngine
from modules.threat_intelligence import ThreatIntelligenceEngine
from modules.user_auth import UserAuthManager
from modules.report_generator import ReportGenerator
from modules.dashboard_api import DashboardAPIServer
from models.ml_engine import MLDetectionEngine
from utils.logger import LogManager

logger = logging.getLogger(__name__)


class ZhiDunSystem:
    """智盾网络安全态势感知与智能防御系统

    系统主控类，负责各子系统的初始化、启动、协调和停止。

    系统架构：
    ┌─────────────────────────────────────────────────────────┐
    │                    可视化仪表盘层                         │
    │  (实时态势展示 / 告警管理 / 报告生成 / 系统管理)          │
    ├─────────────────────────────────────────────────────────┤
    │                    应用服务层                             │
    │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
    │  │ 态势感知 │ │ 威胁情报 │ │ 自动响应 │ │ 报告生成 │   │
    │  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │
    ├─────────────────────────────────────────────────────────┤
    │                    智能分析层                             │
    │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
    │  │ 签名检测 │ │ 行为分析 │ │ 异常评分 │ │ ML引擎   │   │
    │  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │
    ├─────────────────────────────────────────────────────────┤
    │                    数据采集层                             │
    │  ┌──────────┐ ┌──────────┐ ┌──────────┐               │
    │  │ 流量采集 │ │ 协议解析 │ │ 流跟踪   │               │
    │  └──────────┘ └──────────┘ └──────────┘               │
    └─────────────────────────────────────────────────────────┘

    核心工作流：
    1. 网络流量实时采集与深度解析
    2. 多维度威胁检测（签名+行为+ML）
    3. 威胁情报关联与态势评估
    4. 自动化响应处置
    5. 可视化展示与报告输出
    """

    VERSION = "1.0.0"
    SYSTEM_NAME = "智盾网络安全态势感知与智能防御系统"

    def __init__(self, config: Optional[SystemConfig] = None):
        self.config = config or SystemConfig()
        self._running = False
        self._start_time = 0

        # 初始化日志系统
        self.log_manager = LogManager(
            log_dir=self.config.log_dir,
            level=self.config.log_level.value,
        )

        # 初始化核心引擎
        self.traffic_engine = TrafficCaptureEngine(self.config.capture)
        self.detection_engine = ThreatDetectionEngine(self.config.detection)
        self.awareness_engine = SituationAwarenessEngine(self.config)
        self.response_engine = AutoResponseEngine(self.config.response)

        # 初始化功能模块
        self.intel_engine = ThreatIntelligenceEngine(self.config.threat_intel)
        self.auth_manager = UserAuthManager()
        self.report_generator = ReportGenerator()
        self.ml_engine = MLDetectionEngine()

        # 初始化仪表盘
        self.dashboard = DashboardAPIServer(self.config.dashboard)

        # 连接各模块
        self._setup_pipelines()
        self._register_data_providers()

        logger.info(f"{self.SYSTEM_NAME} V{self.VERSION} 初始化完成")

    def _setup_pipelines(self):
        """配置数据处理管道

        数据流: 流量采集 -> 威胁检测 -> 态势感知 -> 自动响应
        """
        # 流量引擎 -> 威胁检测引擎
        self.traffic_engine.register_callback(self._on_packet_captured)

        # 威胁检测引擎 -> 态势感知 + 自动响应
        self.detection_engine.register_alert_callback(self._on_threat_detected)

    def _register_data_providers(self):
        """注册仪表盘数据提供器"""
        self.dashboard.register_data_provider(
            "posture", lambda: self.awareness_engine.get_dashboard_data()
        )
        self.dashboard.register_data_provider(
            "traffic_stats", lambda: self.traffic_engine.get_statistics()
        )
        self.dashboard.register_data_provider(
            "heatmap", lambda: self.awareness_engine.heatmap.get_heatmap_data()
        )
        self.dashboard.register_data_provider(
            "alerts", lambda: [
                a.to_dict() for a in self.awareness_engine._alert_history
            ]
        )
        self.dashboard.register_data_provider(
            "block_list", lambda: self.response_engine.firewall.get_block_list()
        )
        self.dashboard.register_data_provider(
            "block_ip", self.response_engine.firewall.block_ip
        )
        self.dashboard.register_data_provider(
            "unblock_ip", self.response_engine.firewall.unblock_ip
        )
        self.dashboard.register_data_provider(
            "detection_stats", lambda: self.detection_engine.get_statistics()
        )
        self.dashboard.register_data_provider(
            "response_stats", lambda: self.response_engine.get_statistics()
        )
        self.dashboard.register_data_provider(
            "intel_stats", lambda: self.intel_engine.get_statistics()
        )
        self.dashboard.register_data_provider(
            "ml_stats", lambda: self.ml_engine.get_statistics()
        )

    async def _on_packet_captured(self, packet):
        """数据包捕获回调

        对每个捕获的数据包执行：
        1. 威胁检测分析
        2. 威胁情报比对
        3. ML模型预测
        """
        flow = self.traffic_engine.flow_tracker.flows.get(packet.flow_key)
        await self.detection_engine.analyze_packet(packet, flow)

        intel_result = self.intel_engine.check_ip(packet.src_ip)
        if intel_result:
            logger.warning(
                f"威胁情报匹配: {packet.src_ip} - {intel_result.description}"
            )

    async def _on_threat_detected(self, alert: ThreatAlert):
        """威胁检测回调

        对每个检测到的威胁执行：
        1. 态势感知更新
        2. 自动化响应处置
        3. 实时告警推送
        """
        await self.awareness_engine.process_alert(alert)

        response_records = await self.response_engine.handle_alert(alert)
        if response_records:
            for record in response_records:
                if record.status.value == "已完成":
                    self.awareness_engine.record_block()

        self.log_manager.log_security_event(
            event_type=alert.attack_type.value,
            message=alert.description,
            src_ip=alert.src_ip,
            dst_ip=alert.dst_ip,
            level=logging.WARNING if alert.threat_level.value >= 3 else logging.INFO,
        )

        await self.dashboard.push_alert(alert.to_dict())

    async def start(self):
        """启动系统"""
        self._running = True
        self._start_time = time.time()

        logger.info("=" * 60)
        logger.info(f"  {self.SYSTEM_NAME}")
        logger.info(f"  版本: {self.VERSION}")
        logger.info(f"  启动时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info("=" * 60)

        # 按依赖顺序启动各子系统
        await self.intel_engine.start()
        logger.info("[1/6] 威胁情报引擎已启动")

        await self.detection_engine.start()
        logger.info("[2/6] 威胁检测引擎已启动")

        await self.awareness_engine.start()
        logger.info("[3/6] 态势感知引擎已启动")

        await self.response_engine.start()
        logger.info("[4/6] 自动响应引擎已启动")

        await self.dashboard.start()
        logger.info("[5/6] 可视化仪表盘已启动")

        await self.traffic_engine.start()
        logger.info("[6/6] 流量采集引擎已启动")

        logger.info("系统所有模块启动完成，开始安全监控...")

    async def stop(self):
        """停止系统"""
        logger.info("正在停止系统...")

        await self.traffic_engine.stop()
        await self.dashboard.stop()
        await self.response_engine.stop()
        await self.awareness_engine.stop()
        await self.detection_engine.stop()
        await self.intel_engine.stop()

        self._running = False
        uptime = time.time() - self._start_time
        logger.info(f"系统已停止, 运行时长: {uptime:.0f}秒")

    def get_system_info(self) -> dict:
        """获取系统信息"""
        return {
            "name": self.SYSTEM_NAME,
            "version": self.VERSION,
            "uptime": time.time() - self._start_time if self._start_time else 0,
            "is_running": self._running,
            "detection_stats": self.detection_engine.get_statistics(),
            "traffic_stats": self.traffic_engine.get_statistics(),
            "response_stats": self.response_engine.get_statistics(),
            "intel_stats": self.intel_engine.get_statistics(),
            "ml_stats": self.ml_engine.get_statistics(),
        }


async def main():
    """程序主入口"""
    config = load_config()
    system = ZhiDunSystem(config)

    loop = asyncio.get_event_loop()

    def signal_handler():
        logger.info("收到停止信号，正在优雅退出...")
        asyncio.ensure_future(system.stop())

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, signal_handler)

    try:
        await system.start()
        while system._running:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.info("用户中断")
    finally:
        await system.stop()


if __name__ == "__main__":
    print(f"\n{'='*60}")
    print(f"  智盾网络安全态势感知与智能防御系统 V1.0")
    print(f"  ZhiDun Security Situational Awareness System")
    print(f"{'='*60}\n")
    asyncio.run(main())
