# -*- coding: utf-8 -*-
"""
智盾网络安全态势感知与智能防御系统 - 可视化仪表盘API
提供RESTful API接口，支撑前端安全态势可视化展示
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from config.settings import DashboardConfig, ThreatLevel

logger = logging.getLogger(__name__)


@dataclass
class APIResponse:
    """API响应结构"""
    code: int
    message: str
    data: Any = None
    timestamp: float = 0

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()

    def to_dict(self) -> Dict:
        return {
            "code": self.code,
            "message": self.message,
            "data": self.data,
            "timestamp": self.timestamp,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, default=str)


class WebSocketManager:
    """WebSocket连接管理器

    管理客户端WebSocket连接，实现实时数据推送
    """

    def __init__(self):
        self._connections: Dict[str, Any] = {}
        self._subscriptions: Dict[str, set] = {
            "alerts": set(),
            "posture": set(),
            "traffic": set(),
            "responses": set(),
        }

    async def register(self, client_id: str, websocket: Any):
        """注册WebSocket连接"""
        self._connections[client_id] = websocket
        logger.info(f"WebSocket客户端已连接: {client_id}")

    async def unregister(self, client_id: str):
        """注销WebSocket连接"""
        self._connections.pop(client_id, None)
        for channel in self._subscriptions.values():
            channel.discard(client_id)
        logger.info(f"WebSocket客户端已断开: {client_id}")

    async def subscribe(self, client_id: str, channel: str):
        """订阅数据频道"""
        if channel in self._subscriptions:
            self._subscriptions[channel].add(client_id)
            logger.debug(f"客户端 {client_id} 订阅频道: {channel}")

    async def broadcast(self, channel: str, data: Dict):
        """向频道广播数据"""
        subscribers = self._subscriptions.get(channel, set())
        message = json.dumps({
            "channel": channel,
            "data": data,
            "timestamp": time.time(),
        }, ensure_ascii=False, default=str)

        disconnected = []
        for client_id in subscribers:
            ws = self._connections.get(client_id)
            if ws:
                try:
                    await self._send_message(ws, message)
                except Exception:
                    disconnected.append(client_id)

        for client_id in disconnected:
            await self.unregister(client_id)

    async def _send_message(self, websocket: Any, message: str):
        """发送WebSocket消息"""
        pass  # 实际实现依赖Web框架

    def get_connection_stats(self) -> Dict:
        """获取连接统计"""
        return {
            "total_connections": len(self._connections),
            "channel_subscribers": {
                ch: len(subs) for ch, subs in self._subscriptions.items()
            },
        }


class RateLimiter:
    """API请求限流器

    基于令牌桶算法实现API请求频率限制
    """

    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._request_counts: Dict[str, List[float]] = {}

    def is_allowed(self, client_id: str) -> bool:
        """检查请求是否允许"""
        now = time.time()
        if client_id not in self._request_counts:
            self._request_counts[client_id] = []

        # 清理过期记录
        self._request_counts[client_id] = [
            ts for ts in self._request_counts[client_id]
            if now - ts < self.window_seconds
        ]

        if len(self._request_counts[client_id]) >= self.max_requests:
            return False

        self._request_counts[client_id].append(now)
        return True

    def get_remaining(self, client_id: str) -> int:
        """获取剩余请求次数"""
        now = time.time()
        current = len([
            ts for ts in self._request_counts.get(client_id, [])
            if now - ts < self.window_seconds
        ])
        return max(0, self.max_requests - current)


class DashboardAPIServer:
    """仪表盘API服务器

    核心功能：
    1. 安全态势数据实时推送
    2. 告警信息查询与管理
    3. 流量统计数据接口
    4. 防御响应操作接口
    5. 报告生成与下载
    6. 系统管理接口
    """

    def __init__(self, config: DashboardConfig):
        self.config = config
        self.ws_manager = WebSocketManager()
        self.rate_limiter = RateLimiter()
        self._data_providers: Dict[str, Callable] = {}
        self._running = False

        logger.info(f"仪表盘API服务器初始化完成, 端口: {config.port}")

    def register_data_provider(self, name: str, provider: Callable):
        """注册数据提供器"""
        self._data_providers[name] = provider
        logger.debug(f"已注册数据提供器: {name}")

    async def start(self):
        """启动API服务器"""
        self._running = True
        asyncio.create_task(self._push_realtime_data())
        logger.info(f"仪表盘API服务器已启动: https://0.0.0.0:{self.config.port}")

    async def stop(self):
        """停止API服务器"""
        self._running = False
        logger.info("仪表盘API服务器已停止")

    # === 态势感知接口 ===

    async def get_current_posture(self, client_id: str) -> APIResponse:
        """获取当前安全态势"""
        if not self.rate_limiter.is_allowed(client_id):
            return APIResponse(429, "请求过于频繁")

        provider = self._data_providers.get("posture")
        if not provider:
            return APIResponse(503, "态势数据不可用")

        data = await provider() if asyncio.iscoroutinefunction(provider) else provider()
        return APIResponse(200, "success", data)

    async def get_threat_trend(self, client_id: str, hours: int = 24) -> APIResponse:
        """获取威胁趋势"""
        if not self.rate_limiter.is_allowed(client_id):
            return APIResponse(429, "请求过于频繁")

        provider = self._data_providers.get("threat_trend")
        if not provider:
            return APIResponse(503, "趋势数据不可用")

        data = await provider(hours) if asyncio.iscoroutinefunction(provider) else provider(hours)
        return APIResponse(200, "success", data)

    async def get_heatmap_data(self, client_id: str) -> APIResponse:
        """获取威胁热力图数据"""
        if not self.rate_limiter.is_allowed(client_id):
            return APIResponse(429, "请求过于频繁")

        provider = self._data_providers.get("heatmap")
        if not provider:
            return APIResponse(503, "热力图数据不可用")

        data = await provider() if asyncio.iscoroutinefunction(provider) else provider()
        return APIResponse(200, "success", data)

    # === 告警管理接口 ===

    async def get_alerts(self, client_id: str, page: int = 1,
                         page_size: int = 20, level: Optional[str] = None) -> APIResponse:
        """获取告警列表"""
        if not self.rate_limiter.is_allowed(client_id):
            return APIResponse(429, "请求过于频繁")

        provider = self._data_providers.get("alerts")
        if not provider:
            return APIResponse(503, "告警数据不可用")

        data = provider()
        if level:
            data = [a for a in data if a.get("threat_level") == level]

        total = len(data)
        start = (page - 1) * page_size
        end = start + page_size
        paged_data = data[start:end]

        return APIResponse(200, "success", {
            "total": total,
            "page": page,
            "page_size": page_size,
            "items": paged_data,
        })

    async def acknowledge_alert(self, client_id: str, alert_id: str) -> APIResponse:
        """确认告警"""
        if not self.rate_limiter.is_allowed(client_id):
            return APIResponse(429, "请求过于频繁")

        provider = self._data_providers.get("ack_alert")
        if provider:
            success = provider(alert_id)
            if success:
                return APIResponse(200, f"告警 {alert_id} 已确认")
        return APIResponse(404, f"告警 {alert_id} 不存在")

    # === 流量统计接口 ===

    async def get_traffic_stats(self, client_id: str) -> APIResponse:
        """获取流量统计"""
        if not self.rate_limiter.is_allowed(client_id):
            return APIResponse(429, "请求过于频繁")

        provider = self._data_providers.get("traffic_stats")
        if not provider:
            return APIResponse(503, "流量数据不可用")

        data = provider()
        return APIResponse(200, "success", data)

    # === 防御响应接口 ===

    async def block_ip(self, client_id: str, ip: str,
                       duration: int, reason: str) -> APIResponse:
        """手动封禁IP"""
        if not self.rate_limiter.is_allowed(client_id):
            return APIResponse(429, "请求过于频繁")

        provider = self._data_providers.get("block_ip")
        if not provider:
            return APIResponse(503, "响应服务不可用")

        result = await provider(ip, duration, reason)
        return APIResponse(200, f"已封禁IP: {ip}", result)

    async def unblock_ip(self, client_id: str, ip: str) -> APIResponse:
        """手动解封IP"""
        if not self.rate_limiter.is_allowed(client_id):
            return APIResponse(429, "请求过于频繁")

        provider = self._data_providers.get("unblock_ip")
        if not provider:
            return APIResponse(503, "响应服务不可用")

        success = await provider(ip)
        if success:
            return APIResponse(200, f"已解封IP: {ip}")
        return APIResponse(404, f"IP {ip} 不在封禁列表中")

    async def get_block_list(self, client_id: str) -> APIResponse:
        """获取封禁列表"""
        if not self.rate_limiter.is_allowed(client_id):
            return APIResponse(429, "请求过于频繁")

        provider = self._data_providers.get("block_list")
        if not provider:
            return APIResponse(503, "数据不可用")

        data = provider()
        return APIResponse(200, "success", data)

    # === 报告接口 ===

    async def generate_report(self, client_id: str,
                              report_type: str) -> APIResponse:
        """生成安全报告"""
        if not self.rate_limiter.is_allowed(client_id):
            return APIResponse(429, "请求过于频繁")

        provider = self._data_providers.get("generate_report")
        if not provider:
            return APIResponse(503, "报告服务不可用")

        result = provider(report_type)
        return APIResponse(200, "报告已生成", result)

    # === 系统管理接口 ===

    async def get_system_status(self, client_id: str) -> APIResponse:
        """获取系统状态"""
        if not self.rate_limiter.is_allowed(client_id):
            return APIResponse(429, "请求过于频繁")

        status = {
            "system_name": "智盾网络安全态势感知与智能防御系统",
            "version": "1.0.0",
            "uptime": time.time(),
            "websocket_connections": self.ws_manager.get_connection_stats(),
        }

        for name, provider in self._data_providers.items():
            if name.endswith("_stats"):
                try:
                    status[name] = provider()
                except Exception:
                    status[name] = "unavailable"

        return APIResponse(200, "success", status)

    # === 实时数据推送 ===

    async def _push_realtime_data(self):
        """定期推送实时数据"""
        while self._running:
            try:
                # 推送态势数据
                posture_provider = self._data_providers.get("posture")
                if posture_provider:
                    data = posture_provider()
                    await self.ws_manager.broadcast("posture", data)

                # 推送流量数据
                traffic_provider = self._data_providers.get("traffic_stats")
                if traffic_provider:
                    data = traffic_provider()
                    await self.ws_manager.broadcast("traffic", data)

                await asyncio.sleep(self.config.refresh_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"实时数据推送异常: {e}")
                await asyncio.sleep(self.config.refresh_interval)

    async def push_alert(self, alert_data: Dict):
        """推送告警通知"""
        await self.ws_manager.broadcast("alerts", alert_data)
