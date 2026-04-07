# -*- coding: utf-8 -*-
"""
智盾网络安全态势感知与智能防御系统 - 网络流量采集引擎
负责实时捕获和预处理网络数据包，提取关键特征信息
"""

import asyncio
import hashlib
import logging
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    AsyncGenerator, Callable, Dict, List, Optional, Set, Tuple
)

from config.settings import NetworkCaptureConfig

logger = logging.getLogger(__name__)


class ProtocolType(Enum):
    """网络协议类型"""
    TCP = 6
    UDP = 17
    ICMP = 1
    HTTP = 80
    HTTPS = 443
    DNS = 53
    SSH = 22
    FTP = 21
    SMTP = 25
    UNKNOWN = -1


@dataclass
class PacketInfo:
    """数据包信息结构"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: ProtocolType
    payload_size: int
    flags: int = 0
    ttl: int = 64
    raw_data: bytes = b""
    packet_hash: str = ""

    def __post_init__(self):
        if not self.packet_hash:
            hash_input = f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}:{self.timestamp}"
            self.packet_hash = hashlib.md5(hash_input.encode()).hexdigest()

    @property
    def flow_key(self) -> str:
        """生成流标识键"""
        ips = sorted([self.src_ip, self.dst_ip])
        ports = sorted([self.src_port, self.dst_port])
        return f"{ips[0]}:{ports[0]}<->{ips[1]}:{ports[1]}:{self.protocol.value}"

    @property
    def is_inbound(self) -> bool:
        """判断是否为入站流量"""
        return not self.src_ip.startswith(("10.", "172.16.", "192.168."))


@dataclass
class FlowRecord:
    """网络流记录"""
    flow_key: str
    start_time: float
    end_time: float = 0
    packet_count: int = 0
    total_bytes: int = 0
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: ProtocolType = ProtocolType.UNKNOWN
    flags_seen: Set[int] = field(default_factory=set)
    payload_sizes: List[int] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time if self.end_time > 0 else 0

    @property
    def avg_packet_size(self) -> float:
        return self.total_bytes / self.packet_count if self.packet_count > 0 else 0

    @property
    def packets_per_second(self) -> float:
        dur = self.duration
        return self.packet_count / dur if dur > 0 else 0


@dataclass
class TrafficStatistics:
    """流量统计信息"""
    total_packets: int = 0
    total_bytes: int = 0
    inbound_packets: int = 0
    outbound_packets: int = 0
    protocol_distribution: Dict[str, int] = field(default_factory=dict)
    top_talkers: Dict[str, int] = field(default_factory=dict)
    active_flows: int = 0
    packets_per_second: float = 0
    bytes_per_second: float = 0
    start_time: float = 0


class PacketParser:
    """数据包深度解析器"""

    ETHERNET_HEADER_LEN = 14
    IP_HEADER_MIN_LEN = 20
    TCP_HEADER_MIN_LEN = 20
    UDP_HEADER_LEN = 8

    @staticmethod
    def parse_ethernet_header(raw_data: bytes) -> Optional[Dict]:
        """解析以太网帧头"""
        if len(raw_data) < PacketParser.ETHERNET_HEADER_LEN:
            return None
        dst_mac = raw_data[0:6]
        src_mac = raw_data[6:12]
        eth_type = struct.unpack("!H", raw_data[12:14])[0]
        return {
            "dst_mac": ":".join(f"{b:02x}" for b in dst_mac),
            "src_mac": ":".join(f"{b:02x}" for b in src_mac),
            "eth_type": eth_type,
            "payload": raw_data[PacketParser.ETHERNET_HEADER_LEN:]
        }

    @staticmethod
    def parse_ip_header(raw_data: bytes) -> Optional[Dict]:
        """解析IP头部"""
        if len(raw_data) < PacketParser.IP_HEADER_MIN_LEN:
            return None

        version_ihl = raw_data[0]
        version = (version_ihl >> 4) & 0xF
        ihl = (version_ihl & 0xF) * 4

        if version != 4 or len(raw_data) < ihl:
            return None

        total_length = struct.unpack("!H", raw_data[2:4])[0]
        ttl = raw_data[8]
        protocol = raw_data[9]
        src_ip = ".".join(str(b) for b in raw_data[12:16])
        dst_ip = ".".join(str(b) for b in raw_data[16:20])

        return {
            "version": version,
            "header_length": ihl,
            "total_length": total_length,
            "ttl": ttl,
            "protocol": protocol,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "payload": raw_data[ihl:]
        }

    @staticmethod
    def parse_tcp_header(raw_data: bytes) -> Optional[Dict]:
        """解析TCP头部"""
        if len(raw_data) < PacketParser.TCP_HEADER_MIN_LEN:
            return None

        src_port = struct.unpack("!H", raw_data[0:2])[0]
        dst_port = struct.unpack("!H", raw_data[2:4])[0]
        seq_num = struct.unpack("!I", raw_data[4:8])[0]
        ack_num = struct.unpack("!I", raw_data[8:12])[0]
        data_offset = ((raw_data[12] >> 4) & 0xF) * 4
        flags = raw_data[13]

        return {
            "src_port": src_port,
            "dst_port": dst_port,
            "seq_num": seq_num,
            "ack_num": ack_num,
            "data_offset": data_offset,
            "flags": flags,
            "payload": raw_data[data_offset:] if data_offset <= len(raw_data) else b""
        }

    @staticmethod
    def parse_udp_header(raw_data: bytes) -> Optional[Dict]:
        """解析UDP头部"""
        if len(raw_data) < PacketParser.UDP_HEADER_LEN:
            return None

        src_port = struct.unpack("!H", raw_data[0:2])[0]
        dst_port = struct.unpack("!H", raw_data[2:4])[0]
        length = struct.unpack("!H", raw_data[4:6])[0]

        return {
            "src_port": src_port,
            "dst_port": dst_port,
            "length": length,
            "payload": raw_data[PacketParser.UDP_HEADER_LEN:]
        }

    @classmethod
    def parse_packet(cls, raw_data: bytes) -> Optional[PacketInfo]:
        """完整数据包解析"""
        eth = cls.parse_ethernet_header(raw_data)
        if not eth or eth["eth_type"] != 0x0800:
            return None

        ip = cls.parse_ip_header(eth["payload"])
        if not ip:
            return None

        protocol_num = ip["protocol"]
        src_port = 0
        dst_port = 0
        flags = 0
        payload_size = 0

        if protocol_num == ProtocolType.TCP.value:
            tcp = cls.parse_tcp_header(ip["payload"])
            if tcp:
                src_port = tcp["src_port"]
                dst_port = tcp["dst_port"]
                flags = tcp["flags"]
                payload_size = len(tcp["payload"])

        elif protocol_num == ProtocolType.UDP.value:
            udp = cls.parse_udp_header(ip["payload"])
            if udp:
                src_port = udp["src_port"]
                dst_port = udp["dst_port"]
                payload_size = len(udp["payload"])

        try:
            proto = ProtocolType(protocol_num)
        except ValueError:
            proto = ProtocolType.UNKNOWN

        return PacketInfo(
            timestamp=time.time(),
            src_ip=ip["src_ip"],
            dst_ip=ip["dst_ip"],
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            payload_size=payload_size,
            flags=flags,
            ttl=ip["ttl"],
            raw_data=raw_data
        )


class FlowTracker:
    """网络流跟踪器"""

    def __init__(self, flow_timeout: int = 300):
        self.flows: Dict[str, FlowRecord] = {}
        self.flow_timeout = flow_timeout
        self._expired_flows: List[FlowRecord] = []

    def update_flow(self, packet: PacketInfo) -> FlowRecord:
        """更新网络流记录"""
        flow_key = packet.flow_key
        now = time.time()

        if flow_key not in self.flows:
            flow = FlowRecord(
                flow_key=flow_key,
                start_time=now,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=packet.protocol,
            )
            self.flows[flow_key] = flow
        else:
            flow = self.flows[flow_key]

        flow.end_time = now
        flow.packet_count += 1
        flow.total_bytes += packet.payload_size
        flow.flags_seen.add(packet.flags)
        flow.payload_sizes.append(packet.payload_size)

        return flow

    def cleanup_expired_flows(self) -> List[FlowRecord]:
        """清理过期的网络流"""
        now = time.time()
        expired = []
        active_keys = list(self.flows.keys())

        for key in active_keys:
            flow = self.flows[key]
            last_active = flow.end_time if flow.end_time > 0 else flow.start_time
            if now - last_active > self.flow_timeout:
                expired.append(flow)
                del self.flows[key]

        self._expired_flows.extend(expired)
        return expired

    @property
    def active_flow_count(self) -> int:
        return len(self.flows)

    def get_flow_summary(self) -> Dict:
        """获取流量摘要"""
        total_packets = sum(f.packet_count for f in self.flows.values())
        total_bytes = sum(f.total_bytes for f in self.flows.values())
        protocols = defaultdict(int)
        for f in self.flows.values():
            protocols[f.protocol.name] += f.packet_count

        return {
            "active_flows": self.active_flow_count,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "protocol_distribution": dict(protocols)
        }


class TrafficCaptureEngine:
    """网络流量采集引擎

    核心功能：
    1. 实时网络数据包捕获
    2. 多协议深度解析
    3. 网络流跟踪与管理
    4. 流量统计与特征提取
    """

    def __init__(self, config: NetworkCaptureConfig):
        self.config = config
        self.parser = PacketParser()
        self.flow_tracker = FlowTracker()
        self.statistics = TrafficStatistics()
        self._running = False
        self._packet_queue: asyncio.Queue = asyncio.Queue(
            maxsize=config.packet_batch_size * 10
        )
        self._callbacks: List[Callable] = []
        self._capture_tasks: List[asyncio.Task] = []

        logger.info(
            f"流量采集引擎初始化完成, 监听接口: {config.interfaces}, "
            f"混杂模式: {config.promiscuous_mode}"
        )

    def register_callback(self, callback: Callable):
        """注册数据包处理回调函数"""
        self._callbacks.append(callback)
        logger.debug(f"已注册回调函数: {callback.__name__}")

    async def start(self):
        """启动流量采集"""
        if self._running:
            logger.warning("流量采集引擎已在运行中")
            return

        self._running = True
        self.statistics.start_time = time.time()

        for interface in self.config.interfaces:
            task = asyncio.create_task(self._capture_interface(interface))
            self._capture_tasks.append(task)

        process_task = asyncio.create_task(self._process_packets())
        self._capture_tasks.append(process_task)

        cleanup_task = asyncio.create_task(self._periodic_cleanup())
        self._capture_tasks.append(cleanup_task)

        logger.info("流量采集引擎已启动")

    async def stop(self):
        """停止流量采集"""
        self._running = False
        for task in self._capture_tasks:
            task.cancel()
        await asyncio.gather(*self._capture_tasks, return_exceptions=True)
        self._capture_tasks.clear()
        logger.info("流量采集引擎已停止")

    async def _capture_interface(self, interface: str):
        """在指定接口上捕获数据包"""
        logger.info(f"开始在接口 {interface} 上捕获流量")
        try:
            while self._running:
                raw_packets = await self._read_packets_from_interface(interface)
                for raw_data in raw_packets:
                    if not self._packet_queue.full():
                        await self._packet_queue.put(raw_data)
                    else:
                        logger.warning("数据包队列已满，丢弃数据包")
        except asyncio.CancelledError:
            logger.info(f"接口 {interface} 捕获任务已取消")
        except Exception as e:
            logger.error(f"接口 {interface} 捕获异常: {e}")

    async def _read_packets_from_interface(self, interface: str) -> List[bytes]:
        """从网络接口读取原始数据包"""
        await asyncio.sleep(0.001)
        return []

    async def _process_packets(self):
        """处理捕获的数据包"""
        batch = []
        try:
            while self._running:
                try:
                    raw_data = await asyncio.wait_for(
                        self._packet_queue.get(), timeout=1.0
                    )
                    batch.append(raw_data)

                    if len(batch) >= self.config.packet_batch_size:
                        await self._process_batch(batch)
                        batch.clear()
                except asyncio.TimeoutError:
                    if batch:
                        await self._process_batch(batch)
                        batch.clear()
        except asyncio.CancelledError:
            if batch:
                await self._process_batch(batch)

    async def _process_batch(self, raw_packets: List[bytes]):
        """批量处理数据包"""
        for raw_data in raw_packets:
            packet = self.parser.parse_packet(raw_data)
            if packet is None:
                continue

            self._update_statistics(packet)
            self.flow_tracker.update_flow(packet)

            for callback in self._callbacks:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(packet)
                    else:
                        callback(packet)
                except Exception as e:
                    logger.error(f"回调函数执行异常: {e}")

    def _update_statistics(self, packet: PacketInfo):
        """更新流量统计"""
        self.statistics.total_packets += 1
        self.statistics.total_bytes += packet.payload_size

        if packet.is_inbound:
            self.statistics.inbound_packets += 1
        else:
            self.statistics.outbound_packets += 1

        proto_name = packet.protocol.name
        self.statistics.protocol_distribution[proto_name] = (
            self.statistics.protocol_distribution.get(proto_name, 0) + 1
        )

        self.statistics.top_talkers[packet.src_ip] = (
            self.statistics.top_talkers.get(packet.src_ip, 0) + 1
        )

        elapsed = time.time() - self.statistics.start_time
        if elapsed > 0:
            self.statistics.packets_per_second = self.statistics.total_packets / elapsed
            self.statistics.bytes_per_second = self.statistics.total_bytes / elapsed

        self.statistics.active_flows = self.flow_tracker.active_flow_count

    async def _periodic_cleanup(self):
        """定期清理过期流"""
        try:
            while self._running:
                await asyncio.sleep(60)
                expired = self.flow_tracker.cleanup_expired_flows()
                if expired:
                    logger.info(f"清理了 {len(expired)} 条过期流记录")
        except asyncio.CancelledError:
            pass

    def get_statistics(self) -> Dict:
        """获取当前流量统计信息"""
        return {
            "total_packets": self.statistics.total_packets,
            "total_bytes": self.statistics.total_bytes,
            "inbound_packets": self.statistics.inbound_packets,
            "outbound_packets": self.statistics.outbound_packets,
            "protocol_distribution": self.statistics.protocol_distribution,
            "active_flows": self.statistics.active_flows,
            "packets_per_second": round(self.statistics.packets_per_second, 2),
            "bytes_per_second": round(self.statistics.bytes_per_second, 2),
            "top_talkers": dict(
                sorted(
                    self.statistics.top_talkers.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:20]
            ),
        }

    async def get_packet_stream(self) -> AsyncGenerator[PacketInfo, None]:
        """获取实时数据包流"""
        while self._running:
            try:
                raw_data = await asyncio.wait_for(
                    self._packet_queue.get(), timeout=5.0
                )
                packet = self.parser.parse_packet(raw_data)
                if packet:
                    yield packet
            except asyncio.TimeoutError:
                continue
