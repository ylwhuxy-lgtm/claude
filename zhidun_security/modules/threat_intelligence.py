# -*- coding: utf-8 -*-
"""
智盾网络安全态势感知与智能防御系统 - 威胁情报模块
提供威胁情报的采集、存储、查询和关联分析功能
"""

import asyncio
import hashlib
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from config.settings import ThreatIntelConfig, ThreatLevel

logger = logging.getLogger(__name__)


class IoC_Type(Enum):
    """威胁指标类型"""
    IP_ADDRESS = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "md5"
    FILE_HASH_SHA256 = "sha256"
    EMAIL = "email"
    CVE = "cve"
    USER_AGENT = "user_agent"


class IntelSource(Enum):
    """情报来源"""
    LOCAL = "本地数据库"
    COMMUNITY = "社区情报"
    COMMERCIAL = "商业情报"
    HONEYPOT = "蜜罐捕获"
    MANUAL = "人工录入"


@dataclass
class ThreatIndicator:
    """威胁指标(IoC)"""
    indicator_id: str
    ioc_type: IoC_Type
    value: str
    threat_level: ThreatLevel
    source: IntelSource
    description: str
    tags: List[str] = field(default_factory=list)
    first_seen: float = 0
    last_seen: float = 0
    confidence: float = 0.0
    ttl: int = 86400
    related_indicators: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.first_seen:
            self.first_seen = time.time()
        if not self.last_seen:
            self.last_seen = self.first_seen
        if not self.indicator_id:
            hash_input = f"{self.ioc_type.value}:{self.value}"
            self.indicator_id = hashlib.sha256(hash_input.encode()).hexdigest()[:16]

    @property
    def is_expired(self) -> bool:
        return time.time() - self.last_seen > self.ttl

    def to_dict(self) -> Dict:
        return {
            "indicator_id": self.indicator_id,
            "type": self.ioc_type.value,
            "value": self.value,
            "threat_level": self.threat_level.name,
            "source": self.source.value,
            "description": self.description,
            "tags": self.tags,
            "confidence": self.confidence,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


class IoCDatabase:
    """威胁指标数据库

    提供高效的IoC存储、查询和管理功能
    """

    def __init__(self, max_entries: int = 1000000):
        self.max_entries = max_entries
        self._indicators: Dict[str, ThreatIndicator] = {}
        self._ip_index: Dict[str, str] = {}
        self._domain_index: Dict[str, str] = {}
        self._hash_index: Dict[str, str] = {}
        self._tag_index: Dict[str, Set[str]] = defaultdict(set)

    def add(self, indicator: ThreatIndicator) -> bool:
        """添加威胁指标"""
        if len(self._indicators) >= self.max_entries:
            self._evict_expired()
            if len(self._indicators) >= self.max_entries:
                logger.warning("IoC数据库已满，无法添加新指标")
                return False

        self._indicators[indicator.indicator_id] = indicator

        if indicator.ioc_type == IoC_Type.IP_ADDRESS:
            self._ip_index[indicator.value] = indicator.indicator_id
        elif indicator.ioc_type == IoC_Type.DOMAIN:
            self._domain_index[indicator.value] = indicator.indicator_id
        elif indicator.ioc_type in (IoC_Type.FILE_HASH_MD5, IoC_Type.FILE_HASH_SHA256):
            self._hash_index[indicator.value] = indicator.indicator_id

        for tag in indicator.tags:
            self._tag_index[tag].add(indicator.indicator_id)

        return True

    def lookup_ip(self, ip: str) -> Optional[ThreatIndicator]:
        """查询IP威胁情报"""
        ioc_id = self._ip_index.get(ip)
        if ioc_id and ioc_id in self._indicators:
            indicator = self._indicators[ioc_id]
            if not indicator.is_expired:
                indicator.last_seen = time.time()
                return indicator
        return None

    def lookup_domain(self, domain: str) -> Optional[ThreatIndicator]:
        """查询域名威胁情报"""
        ioc_id = self._domain_index.get(domain)
        if ioc_id and ioc_id in self._indicators:
            indicator = self._indicators[ioc_id]
            if not indicator.is_expired:
                indicator.last_seen = time.time()
                return indicator
        return None

    def lookup_hash(self, file_hash: str) -> Optional[ThreatIndicator]:
        """查询文件哈希威胁情报"""
        ioc_id = self._hash_index.get(file_hash.lower())
        if ioc_id and ioc_id in self._indicators:
            indicator = self._indicators[ioc_id]
            if not indicator.is_expired:
                return indicator
        return None

    def search_by_tag(self, tag: str) -> List[ThreatIndicator]:
        """按标签搜索"""
        ioc_ids = self._tag_index.get(tag, set())
        return [
            self._indicators[ioc_id]
            for ioc_id in ioc_ids
            if ioc_id in self._indicators and not self._indicators[ioc_id].is_expired
        ]

    def remove(self, indicator_id: str) -> bool:
        """删除威胁指标"""
        if indicator_id not in self._indicators:
            return False

        indicator = self._indicators.pop(indicator_id)

        if indicator.ioc_type == IoC_Type.IP_ADDRESS:
            self._ip_index.pop(indicator.value, None)
        elif indicator.ioc_type == IoC_Type.DOMAIN:
            self._domain_index.pop(indicator.value, None)
        elif indicator.ioc_type in (IoC_Type.FILE_HASH_MD5, IoC_Type.FILE_HASH_SHA256):
            self._hash_index.pop(indicator.value, None)

        for tag in indicator.tags:
            self._tag_index[tag].discard(indicator_id)

        return True

    def _evict_expired(self):
        """清除过期指标"""
        expired_ids = [
            ioc_id for ioc_id, ioc in self._indicators.items()
            if ioc.is_expired
        ]
        for ioc_id in expired_ids:
            self.remove(ioc_id)
        logger.info(f"清除了 {len(expired_ids)} 条过期威胁指标")

    def get_statistics(self) -> Dict:
        """获取数据库统计"""
        type_counts = defaultdict(int)
        level_counts = defaultdict(int)
        source_counts = defaultdict(int)

        for ioc in self._indicators.values():
            type_counts[ioc.ioc_type.value] += 1
            level_counts[ioc.threat_level.name] += 1
            source_counts[ioc.source.value] += 1

        return {
            "total_indicators": len(self._indicators),
            "ip_indicators": len(self._ip_index),
            "domain_indicators": len(self._domain_index),
            "hash_indicators": len(self._hash_index),
            "by_type": dict(type_counts),
            "by_level": dict(level_counts),
            "by_source": dict(source_counts),
            "unique_tags": len(self._tag_index),
        }


class ThreatIntelligenceEngine:
    """威胁情报引擎

    核心功能：
    1. 多源威胁情报采集与聚合
    2. IoC快速查询与匹配
    3. 情报关联分析
    4. 情报质量评估
    5. 自动化情报更新
    """

    def __init__(self, config: ThreatIntelConfig):
        self.config = config
        self.database = IoCDatabase(max_entries=config.max_ioc_entries)
        self._update_callbacks: List = []
        self._running = False
        self._match_count = 0

        self._load_builtin_indicators()
        logger.info("威胁情报引擎初始化完成")

    def _load_builtin_indicators(self):
        """加载内置威胁指标"""
        builtin_indicators = [
            ThreatIndicator(
                indicator_id="", ioc_type=IoC_Type.IP_ADDRESS,
                value="0.0.0.0", threat_level=ThreatLevel.LOW,
                source=IntelSource.LOCAL, description="保留地址",
                tags=["reserved"], confidence=1.0,
            ),
        ]
        for ioc in builtin_indicators:
            self.database.add(ioc)

    async def start(self):
        """启动情报引擎"""
        self._running = True
        if self.config.enabled:
            asyncio.create_task(self._periodic_update())
        logger.info("威胁情报引擎已启动")

    async def stop(self):
        """停止情报引擎"""
        self._running = False
        logger.info("威胁情报引擎已停止")

    def check_ip(self, ip: str) -> Optional[ThreatIndicator]:
        """检查IP是否在威胁情报中"""
        result = self.database.lookup_ip(ip)
        if result:
            self._match_count += 1
            logger.debug(f"IP匹配威胁情报: {ip} -> {result.description}")
        return result

    def check_domain(self, domain: str) -> Optional[ThreatIndicator]:
        """检查域名是否在威胁情报中"""
        result = self.database.lookup_domain(domain)
        if result:
            self._match_count += 1
        return result

    def check_file_hash(self, file_hash: str) -> Optional[ThreatIndicator]:
        """检查文件哈希是否在威胁情报中"""
        result = self.database.lookup_hash(file_hash)
        if result:
            self._match_count += 1
        return result

    def add_indicator(self, indicator: ThreatIndicator) -> bool:
        """添加威胁指标"""
        return self.database.add(indicator)

    def batch_add_indicators(self, indicators: List[ThreatIndicator]) -> int:
        """批量添加威胁指标"""
        added = 0
        for ioc in indicators:
            if self.database.add(ioc):
                added += 1
        logger.info(f"批量添加完成: {added}/{len(indicators)} 条指标")
        return added

    async def _periodic_update(self):
        """定期更新威胁情报"""
        while self._running:
            try:
                await asyncio.sleep(self.config.update_interval)
                for source_name in self.config.sources:
                    await self._fetch_from_source(source_name)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"情报更新异常: {e}")

    async def _fetch_from_source(self, source_name: str):
        """从指定来源获取情报"""
        logger.info(f"正在更新情报来源: {source_name}")
        # 实际实现会连接外部情报源API
        pass

    def get_statistics(self) -> Dict:
        """获取情报统计"""
        db_stats = self.database.get_statistics()
        db_stats["total_matches"] = self._match_count
        return db_stats
