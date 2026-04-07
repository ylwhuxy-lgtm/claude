# -*- coding: utf-8 -*-
"""
智盾网络安全态势感知与智能防御系统 - 自动化响应引擎
实现威胁事件的自动化处置和智能防御策略动态调整
"""

import asyncio
import json
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

from config.settings import ResponseConfig, ThreatLevel
from core.threat_detector import AttackType, ThreatAlert

logger = logging.getLogger(__name__)


class ResponseAction(Enum):
    """响应动作类型"""
    BLOCK_IP = "封禁IP"
    RATE_LIMIT = "限速"
    QUARANTINE = "隔离"
    REDIRECT = "重定向至蜜罐"
    ALERT_ONLY = "仅告警"
    RESET_CONNECTION = "重置连接"
    UPDATE_FIREWALL = "更新防火墙规则"
    DISABLE_ACCOUNT = "禁用账户"
    CAPTURE_FORENSICS = "取证捕获"
    ESCALATE = "上报升级"


class ResponseStatus(Enum):
    """响应状态"""
    PENDING = "待执行"
    EXECUTING = "执行中"
    COMPLETED = "已完成"
    FAILED = "失败"
    CANCELLED = "已取消"
    ROLLED_BACK = "已回滚"


@dataclass
class ResponseRule:
    """响应规则"""
    rule_id: str
    name: str
    attack_type: AttackType
    min_threat_level: ThreatLevel
    actions: List[ResponseAction]
    auto_execute: bool = True
    cooldown: int = 300               # 同一IP的冷却时间(秒)
    max_block_duration: int = 3600    # 最大封禁时长(秒)
    requires_confirmation: bool = False
    enabled: bool = True


@dataclass
class ResponseRecord:
    """响应记录"""
    record_id: str
    alert_id: str
    timestamp: float
    action: ResponseAction
    status: ResponseStatus
    target_ip: str
    reason: str
    duration: int = 0
    details: Dict[str, Any] = field(default_factory=dict)
    executed_by: str = "auto"
    rollback_time: float = 0

    def to_dict(self) -> Dict:
        return {
            "record_id": self.record_id,
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "action": self.action.value,
            "status": self.status.value,
            "target_ip": self.target_ip,
            "reason": self.reason,
            "duration": self.duration,
        }


@dataclass
class BlockEntry:
    """封禁条目"""
    ip_address: str
    start_time: float
    end_time: float
    reason: str
    alert_id: str
    auto_created: bool = True

    @property
    def is_active(self) -> bool:
        return time.time() < self.end_time

    @property
    def remaining_seconds(self) -> int:
        return max(0, int(self.end_time - time.time()))


class FirewallManager:
    """防火墙管理器

    负责与防火墙交互，执行IP封禁、解封等操作
    """

    def __init__(self):
        self._blocked_ips: Dict[str, BlockEntry] = {}
        self._rate_limits: Dict[str, Dict] = {}
        self._firewall_rules: List[Dict] = []

    async def block_ip(self, ip: str, duration: int, reason: str, alert_id: str) -> bool:
        """封禁IP地址"""
        now = time.time()
        entry = BlockEntry(
            ip_address=ip,
            start_time=now,
            end_time=now + duration,
            reason=reason,
            alert_id=alert_id,
        )
        self._blocked_ips[ip] = entry

        rule = {
            "action": "DROP",
            "source": ip,
            "direction": "INPUT",
            "created_at": now,
            "expires_at": now + duration,
            "reason": reason,
        }
        self._firewall_rules.append(rule)

        logger.info(f"已封禁IP: {ip}, 时长: {duration}秒, 原因: {reason}")
        return True

    async def unblock_ip(self, ip: str) -> bool:
        """解封IP地址"""
        if ip in self._blocked_ips:
            del self._blocked_ips[ip]
            self._firewall_rules = [
                r for r in self._firewall_rules if r.get("source") != ip
            ]
            logger.info(f"已解封IP: {ip}")
            return True
        return False

    async def set_rate_limit(self, ip: str, max_rate: int, duration: int) -> bool:
        """设置流量限速"""
        self._rate_limits[ip] = {
            "max_rate": max_rate,
            "duration": duration,
            "created_at": time.time(),
        }
        logger.info(f"已对IP {ip} 设置限速: {max_rate} pps, 时长: {duration}秒")
        return True

    async def cleanup_expired(self) -> int:
        """清理过期的封禁和限速规则"""
        now = time.time()
        expired_count = 0

        expired_ips = [
            ip for ip, entry in self._blocked_ips.items()
            if not entry.is_active
        ]
        for ip in expired_ips:
            await self.unblock_ip(ip)
            expired_count += 1

        expired_limits = [
            ip for ip, info in self._rate_limits.items()
            if now - info["created_at"] > info["duration"]
        ]
        for ip in expired_limits:
            del self._rate_limits[ip]
            expired_count += 1

        return expired_count

    def is_blocked(self, ip: str) -> bool:
        """检查IP是否被封禁"""
        if ip in self._blocked_ips:
            return self._blocked_ips[ip].is_active
        return False

    def get_block_list(self) -> List[Dict]:
        """获取当前封禁列表"""
        return [
            {
                "ip": ip,
                "start_time": entry.start_time,
                "remaining": entry.remaining_seconds,
                "reason": entry.reason,
            }
            for ip, entry in self._blocked_ips.items()
            if entry.is_active
        ]

    def get_statistics(self) -> Dict:
        """获取防火墙统计"""
        active_blocks = sum(1 for e in self._blocked_ips.values() if e.is_active)
        return {
            "active_blocks": active_blocks,
            "total_blocks": len(self._blocked_ips),
            "active_rate_limits": len(self._rate_limits),
            "total_rules": len(self._firewall_rules),
        }


class ResponseStrategyEngine:
    """响应策略引擎

    根据威胁类型和等级，智能选择最优响应策略
    """

    def __init__(self, config: ResponseConfig):
        self.config = config
        self._rules: List[ResponseRule] = []
        self._cooldown_tracker: Dict[str, float] = {}
        self._load_default_rules()

    def _load_default_rules(self):
        """加载默认响应规则"""
        default_rules = [
            ResponseRule(
                rule_id="RSP-001",
                name="端口扫描响应",
                attack_type=AttackType.PORT_SCAN,
                min_threat_level=ThreatLevel.MEDIUM,
                actions=[ResponseAction.RATE_LIMIT, ResponseAction.ALERT_ONLY],
                max_block_duration=1800,
            ),
            ResponseRule(
                rule_id="RSP-002",
                name="DDoS攻击响应",
                attack_type=AttackType.DDOS,
                min_threat_level=ThreatLevel.HIGH,
                actions=[ResponseAction.BLOCK_IP, ResponseAction.UPDATE_FIREWALL],
                max_block_duration=7200,
            ),
            ResponseRule(
                rule_id="RSP-003",
                name="暴力破解响应",
                attack_type=AttackType.BRUTE_FORCE,
                min_threat_level=ThreatLevel.HIGH,
                actions=[ResponseAction.BLOCK_IP, ResponseAction.DISABLE_ACCOUNT],
                max_block_duration=3600,
            ),
            ResponseRule(
                rule_id="RSP-004",
                name="SQL注入响应",
                attack_type=AttackType.SQL_INJECTION,
                min_threat_level=ThreatLevel.HIGH,
                actions=[ResponseAction.BLOCK_IP, ResponseAction.RESET_CONNECTION, ResponseAction.CAPTURE_FORENSICS],
                max_block_duration=7200,
            ),
            ResponseRule(
                rule_id="RSP-005",
                name="XSS攻击响应",
                attack_type=AttackType.XSS,
                min_threat_level=ThreatLevel.MEDIUM,
                actions=[ResponseAction.RESET_CONNECTION, ResponseAction.ALERT_ONLY],
                max_block_duration=1800,
            ),
            ResponseRule(
                rule_id="RSP-006",
                name="命令注入响应",
                attack_type=AttackType.COMMAND_INJECTION,
                min_threat_level=ThreatLevel.CRITICAL,
                actions=[ResponseAction.BLOCK_IP, ResponseAction.QUARANTINE, ResponseAction.CAPTURE_FORENSICS],
                max_block_duration=86400,
            ),
            ResponseRule(
                rule_id="RSP-007",
                name="数据泄露响应",
                attack_type=AttackType.DATA_EXFILTRATION,
                min_threat_level=ThreatLevel.CRITICAL,
                actions=[ResponseAction.QUARANTINE, ResponseAction.CAPTURE_FORENSICS, ResponseAction.ESCALATE],
                max_block_duration=86400,
                requires_confirmation=True,
            ),
            ResponseRule(
                rule_id="RSP-008",
                name="APT响应",
                attack_type=AttackType.APT,
                min_threat_level=ThreatLevel.EMERGENCY,
                actions=[
                    ResponseAction.BLOCK_IP, ResponseAction.QUARANTINE,
                    ResponseAction.CAPTURE_FORENSICS, ResponseAction.ESCALATE
                ],
                max_block_duration=86400 * 7,
                requires_confirmation=True,
            ),
            ResponseRule(
                rule_id="RSP-009",
                name="DNS隧道响应",
                attack_type=AttackType.DNS_TUNNELING,
                min_threat_level=ThreatLevel.HIGH,
                actions=[ResponseAction.BLOCK_IP, ResponseAction.CAPTURE_FORENSICS],
                max_block_duration=3600,
            ),
            ResponseRule(
                rule_id="RSP-010",
                name="恶意软件通信响应",
                attack_type=AttackType.MALWARE_COMM,
                min_threat_level=ThreatLevel.CRITICAL,
                actions=[
                    ResponseAction.BLOCK_IP, ResponseAction.QUARANTINE,
                    ResponseAction.CAPTURE_FORENSICS
                ],
                max_block_duration=86400,
            ),
        ]
        self._rules.extend(default_rules)
        logger.info(f"加载了 {len(self._rules)} 条响应规则")

    def select_strategy(self, alert: ThreatAlert) -> Optional[ResponseRule]:
        """选择最优响应策略"""
        # 检查白名单
        if alert.src_ip in self.config.whitelist_ips:
            logger.info(f"IP {alert.src_ip} 在白名单中，跳过响应")
            return None

        # 检查冷却时间
        cooldown_key = f"{alert.src_ip}:{alert.attack_type.value}"
        now = time.time()
        if cooldown_key in self._cooldown_tracker:
            last_response_time = self._cooldown_tracker[cooldown_key]
            for rule in self._rules:
                if rule.attack_type == alert.attack_type:
                    if now - last_response_time < rule.cooldown:
                        return None

        # 匹配规则
        matched_rules = [
            r for r in self._rules
            if r.enabled
            and r.attack_type == alert.attack_type
            and alert.threat_level.value >= r.min_threat_level.value
        ]

        if not matched_rules:
            return None

        # 选择最高优先级的规则
        best_rule = max(matched_rules, key=lambda r: r.min_threat_level.value)
        self._cooldown_tracker[cooldown_key] = now
        return best_rule


class AutoResponseEngine:
    """自动化响应引擎主类

    核心功能：
    1. 威胁告警的自动化响应处置
    2. 防火墙规则动态管理
    3. 自适应防御策略调整
    4. 响应记录审计追踪
    5. 封禁生命周期管理
    """

    def __init__(self, config: ResponseConfig):
        self.config = config
        self.strategy_engine = ResponseStrategyEngine(config)
        self.firewall = FirewallManager()
        self._response_history: deque = deque(maxlen=50000)
        self._pending_confirmations: Dict[str, Tuple] = {}
        self._running = False
        self._stats = {
            "total_responses": 0,
            "auto_blocks": 0,
            "manual_blocks": 0,
            "false_positives": 0,
            "responses_by_action": defaultdict(int),
        }

        logger.info("自动化响应引擎初始化完成")

    async def start(self):
        """启动响应引擎"""
        self._running = True
        asyncio.create_task(self._periodic_cleanup())
        logger.info("自动化响应引擎已启动")

    async def stop(self):
        """停止响应引擎"""
        self._running = False
        logger.info("自动化响应引擎已停止")

    async def handle_alert(self, alert: ThreatAlert) -> List[ResponseRecord]:
        """处理威胁告警"""
        records = []

        rule = self.strategy_engine.select_strategy(alert)
        if not rule:
            return records

        if rule.requires_confirmation and alert.threat_level.value < ThreatLevel.EMERGENCY.value:
            self._pending_confirmations[alert.alert_id] = (alert, rule)
            logger.info(f"告警 {alert.alert_id} 需要人工确认后执行响应")
            record = ResponseRecord(
                record_id=f"RSP-{alert.alert_id}-PENDING",
                alert_id=alert.alert_id,
                timestamp=time.time(),
                action=ResponseAction.ESCALATE,
                status=ResponseStatus.PENDING,
                target_ip=alert.src_ip,
                reason=f"等待人工确认: {rule.name}",
            )
            records.append(record)
            self._response_history.append(record)
            return records

        for action in rule.actions:
            record = await self._execute_action(alert, action, rule)
            if record:
                records.append(record)
                self._response_history.append(record)

        return records

    async def _execute_action(self, alert: ThreatAlert, action: ResponseAction,
                              rule: ResponseRule) -> Optional[ResponseRecord]:
        """执行响应动作"""
        now = time.time()
        record = ResponseRecord(
            record_id=f"RSP-{alert.alert_id}-{action.name}-{int(now)}",
            alert_id=alert.alert_id,
            timestamp=now,
            action=action,
            status=ResponseStatus.EXECUTING,
            target_ip=alert.src_ip,
            reason=f"{rule.name}: {alert.description}",
        )

        try:
            if action == ResponseAction.BLOCK_IP:
                # 检查是否超过最大封禁数
                current_blocks = len(self.firewall.get_block_list())
                if current_blocks >= self.config.max_auto_blocks:
                    logger.warning("已达最大自动封禁数限制")
                    record.status = ResponseStatus.FAILED
                    record.details["error"] = "超过最大封禁数限制"
                    return record

                duration = min(rule.max_block_duration, self.config.block_duration)
                success = await self.firewall.block_ip(
                    alert.src_ip, duration, alert.description, alert.alert_id
                )
                record.duration = duration
                record.status = ResponseStatus.COMPLETED if success else ResponseStatus.FAILED
                if success:
                    self._stats["auto_blocks"] += 1

            elif action == ResponseAction.RATE_LIMIT:
                success = await self.firewall.set_rate_limit(
                    alert.src_ip, max_rate=100, duration=rule.max_block_duration
                )
                record.status = ResponseStatus.COMPLETED if success else ResponseStatus.FAILED

            elif action == ResponseAction.QUARANTINE:
                record.status = ResponseStatus.COMPLETED
                record.details["quarantine_target"] = alert.src_ip
                logger.info(f"已隔离主机: {alert.src_ip}")

            elif action == ResponseAction.RESET_CONNECTION:
                record.status = ResponseStatus.COMPLETED
                logger.info(f"已重置连接: {alert.src_ip}:{alert.src_port} -> {alert.dst_ip}:{alert.dst_port}")

            elif action == ResponseAction.REDIRECT:
                record.status = ResponseStatus.COMPLETED
                record.details["honeypot_ip"] = "10.0.99.1"
                logger.info(f"已将 {alert.src_ip} 流量重定向至蜜罐")

            elif action == ResponseAction.CAPTURE_FORENSICS:
                record.status = ResponseStatus.COMPLETED
                record.details["capture_file"] = f"/forensics/{alert.alert_id}.pcap"
                logger.info(f"已启动取证捕获: {alert.alert_id}")

            elif action == ResponseAction.ESCALATE:
                record.status = ResponseStatus.COMPLETED
                logger.info(f"告警已上报: {alert.alert_id}")

            elif action == ResponseAction.ALERT_ONLY:
                record.status = ResponseStatus.COMPLETED

            elif action == ResponseAction.UPDATE_FIREWALL:
                record.status = ResponseStatus.COMPLETED
                logger.info(f"已更新防火墙规则: 针对 {alert.src_ip}")

            elif action == ResponseAction.DISABLE_ACCOUNT:
                record.status = ResponseStatus.COMPLETED
                logger.info(f"已禁用关联账户: 来自 {alert.src_ip} 的登录尝试")

            self._stats["total_responses"] += 1
            self._stats["responses_by_action"][action.value] += 1

        except Exception as e:
            record.status = ResponseStatus.FAILED
            record.details["error"] = str(e)
            logger.error(f"响应动作执行异常: {action.value} - {e}")

        return record

    async def confirm_response(self, alert_id: str, approved: bool) -> List[ResponseRecord]:
        """确认待审批的响应"""
        if alert_id not in self._pending_confirmations:
            return []

        alert, rule = self._pending_confirmations.pop(alert_id)
        records = []

        if approved:
            for action in rule.actions:
                record = await self._execute_action(alert, action, rule)
                if record:
                    record.executed_by = "manual_approved"
                    records.append(record)
                    self._response_history.append(record)
        else:
            record = ResponseRecord(
                record_id=f"RSP-{alert_id}-CANCELLED",
                alert_id=alert_id,
                timestamp=time.time(),
                action=ResponseAction.ALERT_ONLY,
                status=ResponseStatus.CANCELLED,
                target_ip=alert.src_ip,
                reason="管理员拒绝自动响应",
                executed_by="manual_rejected",
            )
            records.append(record)
            self._response_history.append(record)

        return records

    async def manual_block(self, ip: str, duration: int, reason: str) -> ResponseRecord:
        """手动封禁IP"""
        now = time.time()
        success = await self.firewall.block_ip(ip, duration, reason, "MANUAL")

        record = ResponseRecord(
            record_id=f"RSP-MANUAL-{ip}-{int(now)}",
            alert_id="MANUAL",
            timestamp=now,
            action=ResponseAction.BLOCK_IP,
            status=ResponseStatus.COMPLETED if success else ResponseStatus.FAILED,
            target_ip=ip,
            reason=reason,
            duration=duration,
            executed_by="manual",
        )
        self._response_history.append(record)
        if success:
            self._stats["manual_blocks"] += 1
        return record

    async def manual_unblock(self, ip: str) -> bool:
        """手动解封IP"""
        return await self.firewall.unblock_ip(ip)

    async def _periodic_cleanup(self):
        """定期清理过期规则"""
        while self._running:
            try:
                expired = await self.firewall.cleanup_expired()
                if expired > 0:
                    logger.info(f"清理了 {expired} 条过期防火墙规则")
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"清理任务异常: {e}")
                await asyncio.sleep(60)

    def get_response_history(self, limit: int = 100) -> List[Dict]:
        """获取响应历史"""
        records = list(self._response_history)
        records.sort(key=lambda x: x.timestamp, reverse=True)
        return [r.to_dict() for r in records[:limit]]

    def get_statistics(self) -> Dict:
        """获取响应统计"""
        fw_stats = self.firewall.get_statistics()
        return {
            "total_responses": self._stats["total_responses"],
            "auto_blocks": self._stats["auto_blocks"],
            "manual_blocks": self._stats["manual_blocks"],
            "pending_confirmations": len(self._pending_confirmations),
            "responses_by_action": dict(self._stats["responses_by_action"]),
            "firewall": fw_stats,
        }
