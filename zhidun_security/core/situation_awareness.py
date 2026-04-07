# -*- coding: utf-8 -*-
"""
智盾网络安全态势感知与智能防御系统 - 态势感知引擎
实现全局安全态势评估、趋势预测和可视化数据生成
"""

import asyncio
import logging
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from config.settings import SystemConfig, ThreatLevel
from core.threat_detector import AttackType, ThreatAlert

logger = logging.getLogger(__name__)


@dataclass
class SecurityPosture:
    """安全态势评估结果"""
    timestamp: float
    overall_score: float           # 总体安全评分 0-100
    risk_level: ThreatLevel        # 风险等级
    network_health: float          # 网络健康度 0-100
    threat_intensity: float        # 威胁强度 0-100
    defense_effectiveness: float   # 防御有效性 0-100
    asset_risk_scores: Dict[str, float] = field(default_factory=dict)
    active_threats: int = 0
    blocked_attacks: int = 0
    trend: str = "stable"          # rising/falling/stable

    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "overall_score": round(self.overall_score, 1),
            "risk_level": self.risk_level.name,
            "network_health": round(self.network_health, 1),
            "threat_intensity": round(self.threat_intensity, 1),
            "defense_effectiveness": round(self.defense_effectiveness, 1),
            "active_threats": self.active_threats,
            "blocked_attacks": self.blocked_attacks,
            "trend": self.trend,
            "top_risk_assets": dict(
                sorted(self.asset_risk_scores.items(), key=lambda x: x[1], reverse=True)[:10]
            ),
        }


@dataclass
class ThreatTrend:
    """威胁趋势数据"""
    time_bucket: str              # 时间桶标识
    alert_count: int = 0
    avg_severity: float = 0
    attack_type_distribution: Dict[str, int] = field(default_factory=dict)
    top_sources: List[Tuple[str, int]] = field(default_factory=list)
    top_targets: List[Tuple[str, int]] = field(default_factory=list)


@dataclass
class AssetProfile:
    """资产安全画像"""
    ip_address: str
    hostname: str = ""
    asset_type: str = "unknown"    # server/workstation/router/firewall
    importance_level: int = 1      # 1-5, 5为最重要
    open_ports: List[int] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    last_attack_time: float = 0
    attack_count: int = 0
    services: List[str] = field(default_factory=list)


class ThreatHeatMap:
    """威胁热力图生成器"""

    def __init__(self):
        self._grid: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self._time_series: deque = deque(maxlen=86400)  # 24小时数据

    def update(self, alert: ThreatAlert):
        """更新热力图数据"""
        src_subnet = self._ip_to_subnet(alert.src_ip)
        dst_subnet = self._ip_to_subnet(alert.dst_ip)
        intensity = alert.threat_level.value / 5.0
        self._grid[src_subnet][dst_subnet] += intensity

        self._time_series.append({
            "timestamp": alert.timestamp,
            "src_subnet": src_subnet,
            "dst_subnet": dst_subnet,
            "intensity": intensity,
            "attack_type": alert.attack_type.value,
        })

    def get_heatmap_data(self) -> Dict:
        """获取热力图数据"""
        rows = []
        for src, targets in self._grid.items():
            for dst, intensity in targets.items():
                rows.append({
                    "source": src,
                    "target": dst,
                    "intensity": round(intensity, 2),
                })
        return {
            "grid_data": sorted(rows, key=lambda x: x["intensity"], reverse=True)[:100],
            "total_cells": len(rows),
        }

    @staticmethod
    def _ip_to_subnet(ip: str) -> str:
        """将IP转换为子网标识"""
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return ip


class AttackTimelineBuilder:
    """攻击时间线构建器"""

    def __init__(self, max_events: int = 10000):
        self._events: deque = deque(maxlen=max_events)
        self._attack_sessions: Dict[str, List[Dict]] = defaultdict(list)

    def add_event(self, alert: ThreatAlert):
        """添加时间线事件"""
        event = {
            "timestamp": alert.timestamp,
            "alert_id": alert.alert_id,
            "attack_type": alert.attack_type.value,
            "threat_level": alert.threat_level.name,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "description": alert.description,
            "confidence": alert.confidence,
        }
        self._events.append(event)

        session_key = f"{alert.src_ip}->{alert.dst_ip}"
        self._attack_sessions[session_key].append(event)

    def get_timeline(self, limit: int = 100) -> List[Dict]:
        """获取最近的时间线事件"""
        events = list(self._events)
        events.sort(key=lambda x: x["timestamp"], reverse=True)
        return events[:limit]

    def get_attack_sessions(self) -> List[Dict]:
        """获取攻击会话汇总"""
        sessions = []
        for key, events in self._attack_sessions.items():
            if not events:
                continue
            src_ip, dst_ip = key.split("->")
            sessions.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "event_count": len(events),
                "first_seen": events[0]["timestamp"],
                "last_seen": events[-1]["timestamp"],
                "attack_types": list(set(e["attack_type"] for e in events)),
                "max_severity": max(e["threat_level"] for e in events),
            })
        return sorted(sessions, key=lambda x: x["event_count"], reverse=True)


class ThreatPredictor:
    """威胁趋势预测器

    基于历史威胁数据的时间序列分析，预测未来威胁趋势
    """

    def __init__(self, history_window: int = 24):
        self.history_window = history_window  # 小时
        self._hourly_counts: deque = deque(maxlen=history_window * 2)
        self._hourly_severities: deque = deque(maxlen=history_window * 2)

    def update(self, alert: ThreatAlert):
        """更新预测数据"""
        pass  # 在assess中批量处理

    def predict_next_hour(self, recent_alerts: List[ThreatAlert]) -> Dict:
        """预测下一小时的威胁态势"""
        if len(recent_alerts) < 10:
            return {
                "predicted_alert_count": 0,
                "predicted_severity": "LOW",
                "confidence": 0.3,
                "trend": "stable",
            }

        now = time.time()
        hour_buckets = defaultdict(list)
        for alert in recent_alerts:
            hour_key = int((now - alert.timestamp) / 3600)
            hour_buckets[hour_key].append(alert)

        hourly_counts = []
        hourly_severities = []
        for h in sorted(hour_buckets.keys()):
            alerts = hour_buckets[h]
            hourly_counts.append(len(alerts))
            hourly_severities.append(
                sum(a.threat_level.value for a in alerts) / len(alerts)
            )

        # 简单线性回归预测
        predicted_count = self._linear_predict(hourly_counts)
        predicted_severity = self._linear_predict(hourly_severities)

        # 趋势判断
        if len(hourly_counts) >= 3:
            recent_avg = sum(hourly_counts[-3:]) / 3
            older_avg = sum(hourly_counts[:-3]) / max(len(hourly_counts) - 3, 1)
            if recent_avg > older_avg * 1.2:
                trend = "rising"
            elif recent_avg < older_avg * 0.8:
                trend = "falling"
            else:
                trend = "stable"
        else:
            trend = "stable"

        severity_map = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL", 5: "EMERGENCY"}
        pred_level = severity_map.get(
            min(5, max(1, round(predicted_severity))), "MEDIUM"
        )

        return {
            "predicted_alert_count": max(0, round(predicted_count)),
            "predicted_severity": pred_level,
            "confidence": min(0.85, 0.5 + len(hourly_counts) * 0.05),
            "trend": trend,
        }

    @staticmethod
    def _linear_predict(values: List[float]) -> float:
        """简单线性回归预测"""
        n = len(values)
        if n < 2:
            return values[-1] if values else 0

        x_mean = (n - 1) / 2
        y_mean = sum(values) / n
        numerator = sum((i - x_mean) * (y - y_mean) for i, y in enumerate(values))
        denominator = sum((i - x_mean) ** 2 for i in range(n))

        if denominator == 0:
            return y_mean

        slope = numerator / denominator
        intercept = y_mean - slope * x_mean
        return slope * n + intercept


class SituationAwarenessEngine:
    """态势感知引擎主类

    核心功能：
    1. 全局安全态势评估与评分
    2. 威胁趋势分析与预测
    3. 资产风险画像管理
    4. 威胁热力图与时间线生成
    5. 态势报告自动生成
    """

    def __init__(self, config: SystemConfig):
        self.config = config
        self.heatmap = ThreatHeatMap()
        self.timeline = AttackTimelineBuilder()
        self.predictor = ThreatPredictor()
        self._alert_history: deque = deque(maxlen=100000)
        self._posture_history: deque = deque(maxlen=1440)  # 24小时，每分钟一次
        self._asset_profiles: Dict[str, AssetProfile] = {}
        self._blocked_count = 0
        self._running = False

        logger.info("态势感知引擎初始化完成")

    def register_asset(self, profile: AssetProfile):
        """注册资产"""
        self._asset_profiles[profile.ip_address] = profile
        logger.info(f"已注册资产: {profile.ip_address} ({profile.asset_type})")

    async def start(self):
        """启动态势感知引擎"""
        self._running = True
        asyncio.create_task(self._periodic_assessment())
        logger.info("态势感知引擎已启动")

    async def stop(self):
        """停止态势感知引擎"""
        self._running = False
        logger.info("态势感知引擎已停止")

    async def process_alert(self, alert: ThreatAlert):
        """处理威胁告警"""
        self._alert_history.append(alert)
        self.heatmap.update(alert)
        self.timeline.add_event(alert)
        self.predictor.update(alert)

        # 更新资产风险
        if alert.dst_ip in self._asset_profiles:
            asset = self._asset_profiles[alert.dst_ip]
            asset.attack_count += 1
            asset.last_attack_time = alert.timestamp
            asset.risk_score = min(100, asset.risk_score + alert.threat_level.value * 5)

    def record_block(self):
        """记录一次成功防御"""
        self._blocked_count += 1

    async def assess_situation(self) -> SecurityPosture:
        """执行安全态势评估"""
        now = time.time()
        recent_alerts = [
            a for a in self._alert_history if now - a.timestamp <= 3600
        ]

        # 计算威胁强度
        threat_intensity = self._calculate_threat_intensity(recent_alerts)

        # 计算网络健康度
        network_health = self._calculate_network_health(recent_alerts)

        # 计算防御有效性
        total_threats = len(recent_alerts)
        defense_effectiveness = (
            (self._blocked_count / max(total_threats, 1)) * 100
            if total_threats > 0 else 100
        )

        # 计算资产风险评分
        asset_risk = {}
        for ip, profile in self._asset_profiles.items():
            asset_risk[ip] = round(profile.risk_score, 1)

        # 综合安全评分
        overall_score = (
            network_health * 0.3 +
            (100 - threat_intensity) * 0.4 +
            defense_effectiveness * 0.3
        )

        # 确定风险等级
        risk_level = self._score_to_risk_level(overall_score)

        # 判断趋势
        trend = self._determine_trend()

        posture = SecurityPosture(
            timestamp=now,
            overall_score=overall_score,
            risk_level=risk_level,
            network_health=network_health,
            threat_intensity=threat_intensity,
            defense_effectiveness=min(100, defense_effectiveness),
            asset_risk_scores=asset_risk,
            active_threats=len(recent_alerts),
            blocked_attacks=self._blocked_count,
            trend=trend,
        )

        self._posture_history.append(posture)
        return posture

    def _calculate_threat_intensity(self, recent_alerts: List[ThreatAlert]) -> float:
        """计算威胁强度

        基于告警数量、严重程度和多样性的加权计算
        """
        if not recent_alerts:
            return 0.0

        count_factor = min(100, len(recent_alerts) / 10 * 100)

        severity_sum = sum(a.threat_level.value for a in recent_alerts)
        max_severity = len(recent_alerts) * 5
        severity_factor = (severity_sum / max_severity) * 100

        unique_types = len(set(a.attack_type for a in recent_alerts))
        diversity_factor = min(100, unique_types / len(AttackType) * 200)

        intensity = (
            count_factor * 0.4 +
            severity_factor * 0.4 +
            diversity_factor * 0.2
        )
        return min(100, intensity)

    def _calculate_network_health(self, recent_alerts: List[ThreatAlert]) -> float:
        """计算网络健康度"""
        base_health = 100.0

        critical_count = sum(
            1 for a in recent_alerts
            if a.threat_level in (ThreatLevel.CRITICAL, ThreatLevel.EMERGENCY)
        )
        high_count = sum(
            1 for a in recent_alerts if a.threat_level == ThreatLevel.HIGH
        )
        medium_count = sum(
            1 for a in recent_alerts if a.threat_level == ThreatLevel.MEDIUM
        )

        penalty = critical_count * 10 + high_count * 5 + medium_count * 2
        return max(0, base_health - penalty)

    def _determine_trend(self) -> str:
        """判断态势趋势"""
        if len(self._posture_history) < 5:
            return "stable"

        recent = list(self._posture_history)[-5:]
        scores = [p.overall_score for p in recent]

        avg_change = sum(
            scores[i] - scores[i - 1] for i in range(1, len(scores))
        ) / (len(scores) - 1)

        if avg_change > 2:
            return "improving"
        elif avg_change < -2:
            return "deteriorating"
        return "stable"

    @staticmethod
    def _score_to_risk_level(score: float) -> ThreatLevel:
        """评分转风险等级"""
        if score >= 90:
            return ThreatLevel.LOW
        elif score >= 70:
            return ThreatLevel.MEDIUM
        elif score >= 50:
            return ThreatLevel.HIGH
        elif score >= 30:
            return ThreatLevel.CRITICAL
        return ThreatLevel.EMERGENCY

    async def _periodic_assessment(self):
        """定期态势评估"""
        while self._running:
            try:
                posture = await self.assess_situation()
                logger.info(
                    f"态势评估: 安全评分={posture.overall_score:.1f}, "
                    f"风险等级={posture.risk_level.name}, "
                    f"趋势={posture.trend}"
                )
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"态势评估异常: {e}")
                await asyncio.sleep(60)

    def get_dashboard_data(self) -> Dict:
        """获取仪表盘展示数据"""
        now = time.time()
        recent_alerts = [
            a for a in self._alert_history if now - a.timestamp <= 3600
        ]

        latest_posture = (
            self._posture_history[-1].to_dict()
            if self._posture_history
            else None
        )

        prediction = self.predictor.predict_next_hour(recent_alerts)

        attack_distribution = defaultdict(int)
        for alert in recent_alerts:
            attack_distribution[alert.attack_type.value] += 1

        return {
            "current_posture": latest_posture,
            "threat_prediction": prediction,
            "attack_distribution": dict(attack_distribution),
            "heatmap": self.heatmap.get_heatmap_data(),
            "timeline": self.timeline.get_timeline(50),
            "attack_sessions": self.timeline.get_attack_sessions()[:20],
            "asset_count": len(self._asset_profiles),
            "total_alerts_1h": len(recent_alerts),
        }

    def generate_report(self) -> Dict:
        """生成安全态势报告"""
        now = time.time()
        all_recent = [
            a for a in self._alert_history if now - a.timestamp <= 86400
        ]

        hourly_stats = defaultdict(lambda: {"count": 0, "severity_sum": 0})
        for alert in all_recent:
            hour = int((now - alert.timestamp) / 3600)
            hourly_stats[hour]["count"] += 1
            hourly_stats[hour]["severity_sum"] += alert.threat_level.value

        top_attackers = defaultdict(int)
        top_targets = defaultdict(int)
        for alert in all_recent:
            top_attackers[alert.src_ip] += 1
            top_targets[alert.dst_ip] += 1

        return {
            "report_time": now,
            "period": "24h",
            "total_alerts": len(all_recent),
            "blocked_attacks": self._blocked_count,
            "hourly_trend": dict(hourly_stats),
            "top_attackers": dict(
                sorted(top_attackers.items(), key=lambda x: x[1], reverse=True)[:10]
            ),
            "top_targets": dict(
                sorted(top_targets.items(), key=lambda x: x[1], reverse=True)[:10]
            ),
            "attack_type_summary": dict(
                defaultdict(int, {
                    a.attack_type.value: sum(
                        1 for x in all_recent if x.attack_type == a.attack_type
                    )
                    for a in all_recent
                })
            ),
        }
