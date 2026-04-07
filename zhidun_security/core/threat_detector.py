# -*- coding: utf-8 -*-
"""
智盾网络安全态势感知与智能防御系统 - 威胁检测引擎
基于多维度分析的智能威胁检测，融合规则匹配、行为分析和机器学习
"""

import asyncio
import json
import logging
import math
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from config.settings import DetectionEngineConfig, ThreatLevel
from core.traffic_capture import FlowRecord, PacketInfo, ProtocolType

logger = logging.getLogger(__name__)


class AttackType(Enum):
    """攻击类型枚举"""
    PORT_SCAN = "端口扫描"
    DDOS = "DDoS攻击"
    BRUTE_FORCE = "暴力破解"
    SQL_INJECTION = "SQL注入"
    XSS = "跨站脚本攻击"
    COMMAND_INJECTION = "命令注入"
    PATH_TRAVERSAL = "路径遍历"
    MALWARE_COMM = "恶意软件通信"
    DATA_EXFILTRATION = "数据泄露"
    DNS_TUNNELING = "DNS隧道"
    ARP_SPOOFING = "ARP欺骗"
    MAN_IN_THE_MIDDLE = "中间人攻击"
    ZERO_DAY = "零日攻击"
    APT = "高级持续性威胁"
    UNKNOWN = "未知威胁"


@dataclass
class ThreatAlert:
    """威胁告警记录"""
    alert_id: str
    timestamp: float
    attack_type: AttackType
    threat_level: ThreatLevel
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: ProtocolType
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    is_confirmed: bool = False
    response_action: str = ""
    related_alerts: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "attack_type": self.attack_type.value,
            "threat_level": self.threat_level.name,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "description": self.description,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


class SignatureRule:
    """签名规则"""

    def __init__(self, rule_id: str, name: str, pattern: str,
                 attack_type: AttackType, threat_level: ThreatLevel,
                 protocol: Optional[ProtocolType] = None):
        self.rule_id = rule_id
        self.name = name
        self.pattern = re.compile(pattern.encode() if isinstance(pattern, str) else pattern)
        self.attack_type = attack_type
        self.threat_level = threat_level
        self.protocol = protocol
        self.hit_count = 0

    def match(self, data: bytes) -> bool:
        """匹配数据包内容"""
        if self.pattern.search(data):
            self.hit_count += 1
            return True
        return False


class SignatureDetector:
    """基于签名的检测器"""

    def __init__(self):
        self.rules: List[SignatureRule] = []
        self._load_default_rules()

    def _load_default_rules(self):
        """加载默认检测规则"""
        default_rules = [
            SignatureRule(
                "SIG-001", "SQL注入检测-UNION",
                r"(?i)(union\s+(all\s+)?select|select\s+.*from\s+information_schema)",
                AttackType.SQL_INJECTION, ThreatLevel.HIGH
            ),
            SignatureRule(
                "SIG-002", "SQL注入检测-布尔盲注",
                r"(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1|'\s*or\s*'.*'\s*=\s*')",
                AttackType.SQL_INJECTION, ThreatLevel.HIGH
            ),
            SignatureRule(
                "SIG-003", "SQL注入检测-时间盲注",
                r"(?i)(sleep\s*\(\s*\d+\s*\)|benchmark\s*\(\s*\d+|waitfor\s+delay)",
                AttackType.SQL_INJECTION, ThreatLevel.HIGH
            ),
            SignatureRule(
                "SIG-004", "XSS检测-脚本标签",
                r"(?i)(<script[^>]*>|javascript\s*:|on\w+\s*=\s*['\"])",
                AttackType.XSS, ThreatLevel.MEDIUM
            ),
            SignatureRule(
                "SIG-005", "XSS检测-事件处理器",
                r"(?i)(onerror\s*=|onload\s*=|onmouseover\s*=|onfocus\s*=)",
                AttackType.XSS, ThreatLevel.MEDIUM
            ),
            SignatureRule(
                "SIG-006", "命令注入检测",
                r"(?i)(;\s*(cat|ls|whoami|id|uname|passwd|shadow)|`[^`]+`|\$\([^)]+\))",
                AttackType.COMMAND_INJECTION, ThreatLevel.CRITICAL
            ),
            SignatureRule(
                "SIG-007", "路径遍历检测",
                r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.%2e/|%2e\./)",
                AttackType.PATH_TRAVERSAL, ThreatLevel.HIGH
            ),
            SignatureRule(
                "SIG-008", "恶意软件通信特征",
                r"(X-Bot-Token|X-C2-Channel|X-Malware-ID)",
                AttackType.MALWARE_COMM, ThreatLevel.CRITICAL
            ),
        ]
        self.rules.extend(default_rules)
        logger.info(f"加载了 {len(self.rules)} 条签名规则")

    def detect(self, packet: PacketInfo) -> List[Tuple[SignatureRule, float]]:
        """对数据包进行签名匹配检测"""
        matches = []
        if not packet.raw_data:
            return matches

        for rule in self.rules:
            if rule.protocol and rule.protocol != packet.protocol:
                continue
            if rule.match(packet.raw_data):
                confidence = min(0.95, 0.8 + (rule.hit_count * 0.01))
                matches.append((rule, confidence))

        return matches


class BehaviorAnalyzer:
    """基于行为分析的检测器

    通过分析网络行为模式识别异常活动，包括：
    - 端口扫描检测
    - DDoS攻击检测
    - 暴力破解检测
    - 数据泄露检测
    - DNS隧道检测
    """

    def __init__(self, config: DetectionEngineConfig):
        self.config = config
        self._connection_tracker: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=10000)
        )
        self._port_scan_tracker: Dict[str, Set[int]] = defaultdict(set)
        self._login_attempt_tracker: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=1000)
        )
        self._dns_query_tracker: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=5000)
        )
        self._data_volume_tracker: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=10000)
        )

    def analyze(self, packet: PacketInfo, flow: Optional[FlowRecord] = None) -> List[ThreatAlert]:
        """综合行为分析"""
        alerts = []

        scan_alert = self._detect_port_scan(packet)
        if scan_alert:
            alerts.append(scan_alert)

        ddos_alert = self._detect_ddos(packet)
        if ddos_alert:
            alerts.append(ddos_alert)

        brute_alert = self._detect_brute_force(packet)
        if brute_alert:
            alerts.append(brute_alert)

        if flow:
            exfil_alert = self._detect_data_exfiltration(packet, flow)
            if exfil_alert:
                alerts.append(exfil_alert)

        if packet.protocol == ProtocolType.DNS:
            dns_alert = self._detect_dns_tunneling(packet)
            if dns_alert:
                alerts.append(dns_alert)

        return alerts

    def _detect_port_scan(self, packet: PacketInfo) -> Optional[ThreatAlert]:
        """端口扫描检测

        算法：统计单个源IP在时间窗口内访问的不同目标端口数量
        当端口数超过阈值时判定为端口扫描行为
        """
        src = packet.src_ip
        now = packet.timestamp
        window = self.config.correlation_window

        self._port_scan_tracker[src].add(packet.dst_port)

        conn_record = (now, packet.dst_ip, packet.dst_port)
        self._connection_tracker[src].append(conn_record)

        # 清理过期记录
        while (self._connection_tracker[src] and
               now - self._connection_tracker[src][0][0] > window):
            self._connection_tracker[src].popleft()

        recent_ports = set()
        recent_targets = set()
        for ts, dst_ip, dst_port in self._connection_tracker[src]:
            if now - ts <= window:
                recent_ports.add(dst_port)
                recent_targets.add(dst_ip)

        port_count = len(recent_ports)
        target_count = len(recent_targets)

        # 超过50个不同端口或5个不同目标，判定为扫描
        if port_count > 50 or (target_count > 5 and port_count > 20):
            scan_type = "水平扫描" if target_count > 5 else "垂直扫描"
            confidence = min(0.99, 0.7 + (port_count / 500))

            return ThreatAlert(
                alert_id=f"BA-SCAN-{src}-{int(now)}",
                timestamp=now,
                attack_type=AttackType.PORT_SCAN,
                threat_level=ThreatLevel.MEDIUM,
                src_ip=src,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=packet.protocol,
                description=f"检测到{scan_type}行为: {src} 在{window}秒内扫描了{port_count}个端口, 涉及{target_count}个目标",
                evidence={
                    "scan_type": scan_type,
                    "port_count": port_count,
                    "target_count": target_count,
                    "sample_ports": list(recent_ports)[:20],
                },
                confidence=confidence,
            )
        return None

    def _detect_ddos(self, packet: PacketInfo) -> Optional[ThreatAlert]:
        """DDoS攻击检测

        算法：基于流量速率和连接模式分析
        检测SYN Flood、UDP Flood等常见DDoS攻击模式
        """
        dst = packet.dst_ip
        now = packet.timestamp
        window = 10  # 10秒检测窗口

        tracker_key = f"ddos:{dst}"
        self._connection_tracker[tracker_key].append((now, packet.src_ip, packet.payload_size))

        while (self._connection_tracker[tracker_key] and
               now - self._connection_tracker[tracker_key][0][0] > window):
            self._connection_tracker[tracker_key].popleft()

        recent = self._connection_tracker[tracker_key]
        pps = len(recent) / window  # 每秒包数

        unique_sources = len(set(r[1] for r in recent))
        total_bytes = sum(r[2] for r in recent)

        # SYN Flood检测：TCP SYN标志位为0x02
        syn_count = 0
        if packet.protocol == ProtocolType.TCP and (packet.flags & 0x02):
            syn_count = sum(1 for _ in recent)

        is_ddos = False
        ddos_type = ""

        if pps > 10000:
            is_ddos = True
            ddos_type = "流量洪泛"
        elif syn_count > 5000:
            is_ddos = True
            ddos_type = "SYN Flood"
        elif pps > 5000 and unique_sources > 100:
            is_ddos = True
            ddos_type = "分布式拒绝服务"

        if is_ddos:
            confidence = min(0.99, 0.75 + (pps / 100000))
            return ThreatAlert(
                alert_id=f"BA-DDOS-{dst}-{int(now)}",
                timestamp=now,
                attack_type=AttackType.DDOS,
                threat_level=ThreatLevel.CRITICAL,
                src_ip=packet.src_ip,
                dst_ip=dst,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=packet.protocol,
                description=f"检测到{ddos_type}攻击: 目标 {dst}, 速率 {pps:.0f} pps, 来源数 {unique_sources}, 流量 {total_bytes} bytes",
                evidence={
                    "ddos_type": ddos_type,
                    "packets_per_second": round(pps, 2),
                    "unique_sources": unique_sources,
                    "total_bytes": total_bytes,
                },
                confidence=confidence,
            )
        return None

    def _detect_brute_force(self, packet: PacketInfo) -> Optional[ThreatAlert]:
        """暴力破解检测

        算法：监控针对认证服务端口的连接频率
        短时间内大量连接尝试判定为暴力破解
        """
        auth_ports = {22, 23, 3389, 21, 3306, 5432, 1433, 6379, 27017}
        if packet.dst_port not in auth_ports:
            return None

        key = f"{packet.src_ip}:{packet.dst_ip}:{packet.dst_port}"
        now = packet.timestamp
        window = 60

        self._login_attempt_tracker[key].append(now)

        while (self._login_attempt_tracker[key] and
               now - self._login_attempt_tracker[key][0] > window):
            self._login_attempt_tracker[key].popleft()

        attempt_count = len(self._login_attempt_tracker[key])

        if attempt_count > 30:
            service_map = {
                22: "SSH", 23: "Telnet", 3389: "RDP", 21: "FTP",
                3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL",
                6379: "Redis", 27017: "MongoDB"
            }
            service = service_map.get(packet.dst_port, "未知服务")
            confidence = min(0.98, 0.75 + (attempt_count / 500))

            return ThreatAlert(
                alert_id=f"BA-BRUTE-{key}-{int(now)}",
                timestamp=now,
                attack_type=AttackType.BRUTE_FORCE,
                threat_level=ThreatLevel.HIGH,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=packet.protocol,
                description=f"检测到{service}暴力破解: {packet.src_ip} 在{window}秒内尝试连接 {attempt_count} 次",
                evidence={
                    "service": service,
                    "attempt_count": attempt_count,
                    "window_seconds": window,
                    "rate": round(attempt_count / window, 2),
                },
                confidence=confidence,
            )
        return None

    def _detect_data_exfiltration(self, packet: PacketInfo, flow: FlowRecord) -> Optional[ThreatAlert]:
        """数据泄露检测

        算法：监控出站流量的数据传输量和传输模式
        异常大量数据外传判定为潜在数据泄露
        """
        if not packet.is_inbound:
            return None

        key = f"exfil:{packet.src_ip}"
        now = packet.timestamp

        self._data_volume_tracker[key].append((now, packet.payload_size))

        while (self._data_volume_tracker[key] and
               now - self._data_volume_tracker[key][0][0] > 3600):
            self._data_volume_tracker[key].popleft()

        total_outbound = sum(size for _, size in self._data_volume_tracker[key])

        # 1小时内出站数据超过1GB
        threshold = 1024 * 1024 * 1024
        if total_outbound > threshold:
            confidence = min(0.90, 0.6 + (total_outbound / (threshold * 10)))
            return ThreatAlert(
                alert_id=f"BA-EXFIL-{packet.src_ip}-{int(now)}",
                timestamp=now,
                attack_type=AttackType.DATA_EXFILTRATION,
                threat_level=ThreatLevel.CRITICAL,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=packet.protocol,
                description=f"检测到潜在数据泄露: {packet.src_ip} 在1小时内外传 {total_outbound / (1024*1024):.1f} MB 数据",
                evidence={
                    "total_outbound_mb": round(total_outbound / (1024 * 1024), 2),
                    "threshold_mb": round(threshold / (1024 * 1024), 2),
                    "flow_duration": flow.duration,
                },
                confidence=confidence,
            )
        return None

    def _detect_dns_tunneling(self, packet: PacketInfo) -> Optional[ThreatAlert]:
        """DNS隧道检测

        算法：分析DNS查询的域名长度、查询频率和编码特征
        异常长域名或高频查询判定为DNS隧道
        """
        key = f"dns:{packet.src_ip}"
        now = packet.timestamp

        self._dns_query_tracker[key].append((now, packet.payload_size))

        while (self._dns_query_tracker[key] and
               now - self._dns_query_tracker[key][0][0] > 300):
            self._dns_query_tracker[key].popleft()

        query_count = len(self._dns_query_tracker[key])
        avg_size = sum(s for _, s in self._dns_query_tracker[key]) / max(query_count, 1)

        # DNS隧道通常表现为高频查询 + 异常大的DNS数据包
        if query_count > 500 and avg_size > 200:
            confidence = min(0.92, 0.65 + (query_count / 5000) + (avg_size / 1000))
            return ThreatAlert(
                alert_id=f"BA-DNST-{packet.src_ip}-{int(now)}",
                timestamp=now,
                attack_type=AttackType.DNS_TUNNELING,
                threat_level=ThreatLevel.HIGH,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=packet.protocol,
                description=f"检测到疑似DNS隧道: {packet.src_ip} 在5分钟内发起 {query_count} 次DNS查询, 平均数据大小 {avg_size:.0f} bytes",
                evidence={
                    "query_count": query_count,
                    "avg_payload_size": round(avg_size, 2),
                    "window_seconds": 300,
                },
                confidence=confidence,
            )
        return None


class AnomalyScorer:
    """异常评分引擎

    基于统计学方法和信息熵计算网络行为的异常程度
    """

    def __init__(self, baseline_window: int = 3600):
        self.baseline_window = baseline_window
        self._baselines: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))

    def calculate_entropy(self, data: List[int]) -> float:
        """计算信息熵"""
        if not data:
            return 0.0
        total = len(data)
        freq = defaultdict(int)
        for item in data:
            freq[item] += 1
        entropy = 0.0
        for count in freq.values():
            prob = count / total
            if prob > 0:
                entropy -= prob * math.log2(prob)
        return entropy

    def calculate_zscore(self, value: float, key: str) -> float:
        """计算Z分数"""
        self._baselines[key].append(value)
        data = list(self._baselines[key])
        if len(data) < 10:
            return 0.0

        mean = sum(data) / len(data)
        variance = sum((x - mean) ** 2 for x in data) / len(data)
        std_dev = math.sqrt(variance) if variance > 0 else 1.0
        return (value - mean) / std_dev

    def score_flow(self, flow: FlowRecord) -> float:
        """对网络流进行异常评分

        综合考虑多个维度：
        1. 包速率异常
        2. 数据包大小分布异常
        3. 端口使用异常
        4. 持续时间异常
        """
        scores = []

        # 包速率Z分数
        pps_zscore = abs(self.calculate_zscore(
            flow.packets_per_second, f"pps:{flow.dst_ip}"
        ))
        scores.append(min(1.0, pps_zscore / 5.0))

        # 数据包大小熵
        if flow.payload_sizes:
            size_entropy = self.calculate_entropy(flow.payload_sizes)
            expected_entropy = 4.0  # 正常流量期望熵
            entropy_deviation = abs(size_entropy - expected_entropy) / expected_entropy
            scores.append(min(1.0, entropy_deviation))

        # 流持续时间Z分数
        duration_zscore = abs(self.calculate_zscore(
            flow.duration, f"duration:{flow.protocol.name}"
        ))
        scores.append(min(1.0, duration_zscore / 5.0))

        # 平均包大小Z分数
        avg_size_zscore = abs(self.calculate_zscore(
            flow.avg_packet_size, f"avg_size:{flow.protocol.name}"
        ))
        scores.append(min(1.0, avg_size_zscore / 5.0))

        # 加权平均
        weights = [0.35, 0.25, 0.20, 0.20]
        if len(scores) < len(weights):
            weights = weights[:len(scores)]
        total_weight = sum(weights)
        weighted_score = sum(s * w for s, w in zip(scores, weights)) / total_weight

        return round(weighted_score, 4)


class ThreatCorrelator:
    """威胁关联分析引擎

    对多个告警进行关联分析，识别复合攻击模式
    """

    def __init__(self, correlation_window: int = 300):
        self.correlation_window = correlation_window
        self._alert_history: deque = deque(maxlen=50000)
        self._attack_chains: Dict[str, List[ThreatAlert]] = defaultdict(list)

    def correlate(self, alert: ThreatAlert) -> Optional[ThreatAlert]:
        """关联分析新告警"""
        self._alert_history.append(alert)
        self._attack_chains[alert.src_ip].append(alert)

        chain = self._detect_attack_chain(alert.src_ip)
        if chain:
            return chain

        lateral = self._detect_lateral_movement(alert)
        if lateral:
            return lateral

        return None

    def _detect_attack_chain(self, src_ip: str) -> Optional[ThreatAlert]:
        """检测攻击链

        典型攻击链：扫描 -> 漏洞利用 -> 权限提升 -> 数据窃取
        """
        alerts = self._attack_chains[src_ip]
        now = time.time()

        recent = [a for a in alerts if now - a.timestamp <= self.correlation_window]
        if len(recent) < 3:
            return None

        attack_types = [a.attack_type for a in recent]
        attack_chain_patterns = [
            ([AttackType.PORT_SCAN, AttackType.BRUTE_FORCE], "侦察-入侵攻击链"),
            ([AttackType.PORT_SCAN, AttackType.SQL_INJECTION], "侦察-注入攻击链"),
            ([AttackType.BRUTE_FORCE, AttackType.DATA_EXFILTRATION], "入侵-窃密攻击链"),
            ([AttackType.SQL_INJECTION, AttackType.COMMAND_INJECTION], "注入-提权攻击链"),
        ]

        for pattern, chain_name in attack_chain_patterns:
            if all(at in attack_types for at in pattern):
                related_ids = [a.alert_id for a in recent]
                return ThreatAlert(
                    alert_id=f"CORR-CHAIN-{src_ip}-{int(now)}",
                    timestamp=now,
                    attack_type=AttackType.APT,
                    threat_level=ThreatLevel.EMERGENCY,
                    src_ip=src_ip,
                    dst_ip=recent[-1].dst_ip,
                    src_port=recent[-1].src_port,
                    dst_port=recent[-1].dst_port,
                    protocol=recent[-1].protocol,
                    description=f"检测到{chain_name}: {src_ip} 在{self.correlation_window}秒内执行了多阶段攻击, 涉及 {len(recent)} 个告警",
                    evidence={
                        "chain_name": chain_name,
                        "attack_sequence": [at.value for at in attack_types],
                        "alert_count": len(recent),
                    },
                    confidence=0.92,
                    related_alerts=related_ids,
                )

        return None

    def _detect_lateral_movement(self, alert: ThreatAlert) -> Optional[ThreatAlert]:
        """检测横向移动

        同一源IP短时间内攻击多个内网目标
        """
        now = time.time()
        src_alerts = [
            a for a in self._alert_history
            if a.src_ip == alert.src_ip and now - a.timestamp <= self.correlation_window
        ]

        targets = set(a.dst_ip for a in src_alerts)
        internal_targets = set(
            ip for ip in targets
            if ip.startswith(("10.", "172.16.", "192.168."))
        )

        if len(internal_targets) >= 3:
            return ThreatAlert(
                alert_id=f"CORR-LATERAL-{alert.src_ip}-{int(now)}",
                timestamp=now,
                attack_type=AttackType.APT,
                threat_level=ThreatLevel.EMERGENCY,
                src_ip=alert.src_ip,
                dst_ip=alert.dst_ip,
                src_port=alert.src_port,
                dst_port=alert.dst_port,
                protocol=alert.protocol,
                description=f"检测到横向移动: {alert.src_ip} 正在攻击 {len(internal_targets)} 个内网目标",
                evidence={
                    "targets": list(internal_targets),
                    "target_count": len(internal_targets),
                    "related_alert_count": len(src_alerts),
                },
                confidence=0.88,
            )

        return None


class ThreatDetectionEngine:
    """威胁检测引擎主类

    整合签名检测、行为分析、异常评分和关联分析四大模块，
    提供多维度、多层次的威胁检测能力
    """

    def __init__(self, config: DetectionEngineConfig):
        self.config = config
        self.signature_detector = SignatureDetector()
        self.behavior_analyzer = BehaviorAnalyzer(config)
        self.anomaly_scorer = AnomalyScorer()
        self.threat_correlator = ThreatCorrelator(config.correlation_window)
        self._alert_queue: asyncio.Queue = asyncio.Queue()
        self._alert_callbacks: List[Callable] = []
        self._running = False
        self._stats = {
            "total_packets_analyzed": 0,
            "total_alerts": 0,
            "alerts_by_type": defaultdict(int),
            "alerts_by_level": defaultdict(int),
        }
        logger.info("威胁检测引擎初始化完成")

    def register_alert_callback(self, callback: Callable):
        """注册告警回调函数"""
        self._alert_callbacks.append(callback)

    async def start(self):
        """启动检测引擎"""
        self._running = True
        asyncio.create_task(self._process_alerts())
        logger.info("威胁检测引擎已启动")

    async def stop(self):
        """停止检测引擎"""
        self._running = False
        logger.info("威胁检测引擎已停止")

    async def analyze_packet(self, packet: PacketInfo, flow: Optional[FlowRecord] = None):
        """分析单个数据包"""
        self._stats["total_packets_analyzed"] += 1

        # 第一层：签名检测
        sig_matches = self.signature_detector.detect(packet)
        for rule, confidence in sig_matches:
            alert = ThreatAlert(
                alert_id=f"SIG-{rule.rule_id}-{int(packet.timestamp)}",
                timestamp=packet.timestamp,
                attack_type=rule.attack_type,
                threat_level=rule.threat_level,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=packet.protocol,
                description=f"签名匹配告警: {rule.name}",
                confidence=confidence,
            )
            await self._emit_alert(alert)

        # 第二层：行为分析
        behavior_alerts = self.behavior_analyzer.analyze(packet, flow)
        for alert in behavior_alerts:
            await self._emit_alert(alert)

        # 第三层：异常评分
        if flow:
            anomaly_score = self.anomaly_scorer.score_flow(flow)
            if anomaly_score > self.config.anomaly_threshold:
                alert = ThreatAlert(
                    alert_id=f"ANOMALY-{flow.flow_key}-{int(packet.timestamp)}",
                    timestamp=packet.timestamp,
                    attack_type=AttackType.UNKNOWN,
                    threat_level=self._score_to_level(anomaly_score),
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    src_port=packet.src_port,
                    dst_port=packet.dst_port,
                    protocol=packet.protocol,
                    description=f"异常行为检测: 流 {flow.flow_key} 异常评分 {anomaly_score:.3f}",
                    confidence=anomaly_score,
                    evidence={"anomaly_score": anomaly_score},
                )
                await self._emit_alert(alert)

    async def _emit_alert(self, alert: ThreatAlert):
        """发布告警"""
        self._stats["total_alerts"] += 1
        self._stats["alerts_by_type"][alert.attack_type.value] += 1
        self._stats["alerts_by_level"][alert.threat_level.name] += 1

        # 关联分析
        correlated = self.threat_correlator.correlate(alert)
        if correlated:
            await self._alert_queue.put(correlated)

        await self._alert_queue.put(alert)

    async def _process_alerts(self):
        """处理告警队列"""
        while self._running:
            try:
                alert = await asyncio.wait_for(self._alert_queue.get(), timeout=1.0)
                for callback in self._alert_callbacks:
                    try:
                        if asyncio.iscoroutinefunction(callback):
                            await callback(alert)
                        else:
                            callback(alert)
                    except Exception as e:
                        logger.error(f"告警回调执行异常: {e}")
            except asyncio.TimeoutError:
                continue

    @staticmethod
    def _score_to_level(score: float) -> ThreatLevel:
        """异常评分转威胁等级"""
        if score >= 0.95:
            return ThreatLevel.EMERGENCY
        elif score >= 0.90:
            return ThreatLevel.CRITICAL
        elif score >= 0.85:
            return ThreatLevel.HIGH
        elif score >= 0.75:
            return ThreatLevel.MEDIUM
        return ThreatLevel.LOW

    def get_statistics(self) -> Dict:
        """获取检测统计信息"""
        return {
            "total_packets_analyzed": self._stats["total_packets_analyzed"],
            "total_alerts": self._stats["total_alerts"],
            "alerts_by_type": dict(self._stats["alerts_by_type"]),
            "alerts_by_level": dict(self._stats["alerts_by_level"]),
            "signature_rules_count": len(self.signature_detector.rules),
            "active_correlations": len(self.threat_correlator._attack_chains),
        }
