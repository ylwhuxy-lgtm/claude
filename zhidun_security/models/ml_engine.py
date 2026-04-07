# -*- coding: utf-8 -*-
"""
智盾网络安全态势感知与智能防御系统 - 机器学习检测引擎
基于网络流量特征的智能威胁识别模型
"""

import logging
import math
import random
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class FeatureVector:
    """网络流量特征向量"""
    packet_rate: float = 0.0          # 包速率
    byte_rate: float = 0.0            # 字节速率
    avg_packet_size: float = 0.0      # 平均包大小
    packet_size_std: float = 0.0      # 包大小标准差
    flow_duration: float = 0.0        # 流持续时间
    unique_dst_ports: int = 0         # 唯一目标端口数
    unique_dst_ips: int = 0           # 唯一目标IP数
    syn_ratio: float = 0.0           # SYN标志比例
    fin_ratio: float = 0.0           # FIN标志比例
    rst_ratio: float = 0.0           # RST标志比例
    payload_entropy: float = 0.0     # 载荷熵值
    inter_arrival_mean: float = 0.0  # 到达间隔均值
    inter_arrival_std: float = 0.0   # 到达间隔标准差
    protocol_ratio_tcp: float = 0.0  # TCP协议比例
    protocol_ratio_udp: float = 0.0  # UDP协议比例
    inbound_ratio: float = 0.0       # 入站流量比例

    def to_list(self) -> List[float]:
        """转为特征列表"""
        return [
            self.packet_rate, self.byte_rate, self.avg_packet_size,
            self.packet_size_std, self.flow_duration, self.unique_dst_ports,
            self.unique_dst_ips, self.syn_ratio, self.fin_ratio,
            self.rst_ratio, self.payload_entropy, self.inter_arrival_mean,
            self.inter_arrival_std, self.protocol_ratio_tcp,
            self.protocol_ratio_udp, self.inbound_ratio,
        ]

    @property
    def dimension(self) -> int:
        return len(self.to_list())


class FeatureExtractor:
    """网络流量特征提取器

    从原始网络流数据中提取用于机器学习的特征向量
    """

    def __init__(self, window_size: int = 60):
        self.window_size = window_size
        self._packet_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=50000)
        )

    def extract_features(self, flow_key: str,
                         packets: List[Dict]) -> FeatureVector:
        """从数据包列表中提取特征向量"""
        if not packets:
            return FeatureVector()

        feature = FeatureVector()
        total_packets = len(packets)
        total_bytes = sum(p.get("size", 0) for p in packets)

        timestamps = [p.get("timestamp", 0) for p in packets]
        duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.001

        # 速率特征
        feature.packet_rate = total_packets / duration if duration > 0 else 0
        feature.byte_rate = total_bytes / duration if duration > 0 else 0
        feature.flow_duration = duration

        # 包大小特征
        sizes = [p.get("size", 0) for p in packets]
        feature.avg_packet_size = sum(sizes) / len(sizes) if sizes else 0
        if len(sizes) > 1:
            mean = feature.avg_packet_size
            variance = sum((s - mean) ** 2 for s in sizes) / len(sizes)
            feature.packet_size_std = math.sqrt(variance)

        # 端口和IP多样性
        feature.unique_dst_ports = len(set(p.get("dst_port", 0) for p in packets))
        feature.unique_dst_ips = len(set(p.get("dst_ip", "") for p in packets))

        # TCP标志特征
        tcp_packets = [p for p in packets if p.get("protocol") == "TCP"]
        if tcp_packets:
            tcp_count = len(tcp_packets)
            feature.syn_ratio = sum(
                1 for p in tcp_packets if p.get("flags", 0) & 0x02
            ) / tcp_count
            feature.fin_ratio = sum(
                1 for p in tcp_packets if p.get("flags", 0) & 0x01
            ) / tcp_count
            feature.rst_ratio = sum(
                1 for p in tcp_packets if p.get("flags", 0) & 0x04
            ) / tcp_count

        # 到达间隔特征
        if len(timestamps) > 1:
            intervals = [
                timestamps[i] - timestamps[i - 1]
                for i in range(1, len(timestamps))
            ]
            feature.inter_arrival_mean = sum(intervals) / len(intervals)
            if len(intervals) > 1:
                mean = feature.inter_arrival_mean
                variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
                feature.inter_arrival_std = math.sqrt(variance)

        # 协议比例
        feature.protocol_ratio_tcp = sum(
            1 for p in packets if p.get("protocol") == "TCP"
        ) / total_packets
        feature.protocol_ratio_udp = sum(
            1 for p in packets if p.get("protocol") == "UDP"
        ) / total_packets

        # 载荷熵
        feature.payload_entropy = self._calculate_payload_entropy(packets)

        # 入站比例
        inbound = sum(1 for p in packets if p.get("is_inbound", False))
        feature.inbound_ratio = inbound / total_packets

        return feature

    @staticmethod
    def _calculate_payload_entropy(packets: List[Dict]) -> float:
        """计算载荷字节熵"""
        byte_freq = defaultdict(int)
        total_bytes = 0

        for p in packets:
            payload = p.get("payload", b"")
            if isinstance(payload, bytes):
                for byte in payload:
                    byte_freq[byte] += 1
                    total_bytes += 1

        if total_bytes == 0:
            return 0.0

        entropy = 0.0
        for count in byte_freq.values():
            prob = count / total_bytes
            if prob > 0:
                entropy -= prob * math.log2(prob)

        return entropy


class IsolationTree:
    """孤立树

    孤立森林的基本组成单元，通过随机特征切分隔离异常点
    """

    def __init__(self, max_depth: int = 10):
        self.max_depth = max_depth
        self.root = None

    def fit(self, data: List[List[float]]):
        """构建孤立树"""
        self.root = self._build_tree(data, depth=0)

    def _build_tree(self, data: List[List[float]], depth: int) -> Dict:
        """递归构建树节点"""
        n_samples = len(data)

        if depth >= self.max_depth or n_samples <= 1:
            return {"type": "leaf", "size": n_samples}

        n_features = len(data[0]) if data else 0
        if n_features == 0:
            return {"type": "leaf", "size": n_samples}

        # 随机选择特征和切分点
        feature_idx = random.randint(0, n_features - 1)
        feature_values = [row[feature_idx] for row in data]
        min_val = min(feature_values)
        max_val = max(feature_values)

        if min_val == max_val:
            return {"type": "leaf", "size": n_samples}

        split_value = random.uniform(min_val, max_val)

        left_data = [row for row in data if row[feature_idx] < split_value]
        right_data = [row for row in data if row[feature_idx] >= split_value]

        return {
            "type": "internal",
            "feature_idx": feature_idx,
            "split_value": split_value,
            "left": self._build_tree(left_data, depth + 1),
            "right": self._build_tree(right_data, depth + 1),
        }

    def path_length(self, sample: List[float]) -> float:
        """计算样本在树中的路径长度"""
        return self._traverse(self.root, sample, depth=0)

    def _traverse(self, node: Dict, sample: List[float], depth: int) -> float:
        """遍历树计算路径长度"""
        if node["type"] == "leaf":
            size = node["size"]
            if size <= 1:
                return depth
            return depth + self._average_path_length(size)

        feature_idx = node["feature_idx"]
        split_value = node["split_value"]

        if sample[feature_idx] < split_value:
            return self._traverse(node["left"], sample, depth + 1)
        return self._traverse(node["right"], sample, depth + 1)

    @staticmethod
    def _average_path_length(n: int) -> float:
        """估算BST平均路径长度"""
        if n <= 1:
            return 0
        if n == 2:
            return 1
        return 2 * (math.log(n - 1) + 0.5772156649) - 2 * (n - 1) / n


class IsolationForest:
    """孤立森林异常检测模型

    通过构建多棵随机孤立树，利用样本被隔离的难易程度
    来判断其是否为异常。异常点因为与正常数据差异大，
    更容易被隔离（路径更短）。

    创新点：
    1. 针对网络流量特征优化的特征空间
    2. 在线增量学习支持
    3. 自适应阈值调整
    """

    def __init__(self, n_trees: int = 100, max_samples: int = 256,
                 max_depth: int = 10):
        self.n_trees = n_trees
        self.max_samples = max_samples
        self.max_depth = max_depth
        self.trees: List[IsolationTree] = []
        self._training_size = 0
        self._threshold = 0.6
        self._score_history: deque = deque(maxlen=10000)

    def fit(self, training_data: List[List[float]]):
        """训练孤立森林模型"""
        self._training_size = len(training_data)
        self.trees.clear()

        for i in range(self.n_trees):
            # 随机采样子集
            n_samples = min(self.max_samples, len(training_data))
            sample_indices = random.sample(range(len(training_data)), n_samples)
            sample_data = [training_data[idx] for idx in sample_indices]

            tree = IsolationTree(max_depth=self.max_depth)
            tree.fit(sample_data)
            self.trees.append(tree)

        logger.info(
            f"孤立森林模型训练完成: {self.n_trees}棵树, "
            f"训练样本数: {self._training_size}"
        )

    def predict_anomaly_score(self, sample: List[float]) -> float:
        """计算异常评分

        返回值范围 [0, 1]，越接近1越可能是异常
        """
        if not self.trees:
            return 0.5

        avg_path_length = sum(
            tree.path_length(sample) for tree in self.trees
        ) / len(self.trees)

        c_n = IsolationTree._average_path_length(self._training_size)
        if c_n == 0:
            return 0.5

        score = 2 ** (-avg_path_length / c_n)
        self._score_history.append(score)
        return score

    def is_anomaly(self, sample: List[float]) -> Tuple[bool, float]:
        """判断样本是否为异常"""
        score = self.predict_anomaly_score(sample)
        return (score > self._threshold, score)

    def update_threshold(self, percentile: float = 0.95):
        """自适应更新检测阈值"""
        if len(self._score_history) < 100:
            return

        scores = sorted(self._score_history)
        idx = int(len(scores) * percentile)
        new_threshold = scores[min(idx, len(scores) - 1)]

        # 平滑更新
        self._threshold = self._threshold * 0.7 + new_threshold * 0.3
        logger.info(f"异常检测阈值已更新: {self._threshold:.4f}")


class TrafficClassifier:
    """网络流量分类器

    基于K近邻(KNN)算法的流量分类模型
    将网络流量分为正常流量和多种攻击类型
    """

    LABELS = {
        0: "正常流量",
        1: "端口扫描",
        2: "DDoS攻击",
        3: "暴力破解",
        4: "Web攻击",
        5: "恶意软件",
        6: "数据泄露",
    }

    def __init__(self, k: int = 5):
        self.k = k
        self._training_data: List[Tuple[List[float], int]] = []
        self._feature_means: List[float] = []
        self._feature_stds: List[float] = []

    def fit(self, features: List[List[float]], labels: List[int]):
        """训练分类器"""
        if len(features) != len(labels):
            raise ValueError("特征和标签数量不匹配")

        # 计算归一化参数
        n_features = len(features[0]) if features else 0
        self._feature_means = [0.0] * n_features
        self._feature_stds = [1.0] * n_features

        for j in range(n_features):
            col = [features[i][j] for i in range(len(features))]
            self._feature_means[j] = sum(col) / len(col)
            variance = sum((x - self._feature_means[j]) ** 2 for x in col) / len(col)
            self._feature_stds[j] = math.sqrt(variance) if variance > 0 else 1.0

        # 存储归一化后的训练数据
        self._training_data = [
            (self._normalize(f), l) for f, l in zip(features, labels)
        ]
        logger.info(f"流量分类器训练完成: {len(features)} 样本, {n_features} 特征")

    def predict(self, feature: List[float]) -> Tuple[int, float]:
        """预测流量类型

        返回: (预测类别, 置信度)
        """
        if not self._training_data:
            return (0, 0.0)

        normalized = self._normalize(feature)

        # 计算与所有训练样本的距离
        distances = []
        for train_feature, train_label in self._training_data:
            dist = self._euclidean_distance(normalized, train_feature)
            distances.append((dist, train_label))

        distances.sort(key=lambda x: x[0])
        k_nearest = distances[:self.k]

        # 投票
        votes = defaultdict(float)
        for dist, label in k_nearest:
            weight = 1.0 / (dist + 1e-8)
            votes[label] += weight

        predicted_label = max(votes, key=votes.get)
        total_weight = sum(votes.values())
        confidence = votes[predicted_label] / total_weight if total_weight > 0 else 0

        return (predicted_label, confidence)

    def _normalize(self, feature: List[float]) -> List[float]:
        """特征归一化"""
        return [
            (f - m) / s
            for f, m, s in zip(feature, self._feature_means, self._feature_stds)
        ]

    @staticmethod
    def _euclidean_distance(a: List[float], b: List[float]) -> float:
        """计算欧氏距离"""
        return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))

    def get_label_name(self, label: int) -> str:
        """获取类别名称"""
        return self.LABELS.get(label, "未知")


class MLDetectionEngine:
    """机器学习检测引擎

    整合多个机器学习模型，提供智能化威胁检测：
    1. 孤立森林异常检测 - 发现未知威胁
    2. KNN流量分类 - 识别已知攻击类型
    3. 特征提取与在线学习
    """

    def __init__(self):
        self.feature_extractor = FeatureExtractor()
        self.anomaly_detector = IsolationForest(n_trees=100, max_samples=256)
        self.traffic_classifier = TrafficClassifier(k=5)
        self._is_trained = False
        self._prediction_count = 0
        self._anomaly_count = 0

        logger.info("机器学习检测引擎初始化完成")

    def train(self, training_data: List[Dict]):
        """训练所有模型"""
        if not training_data:
            logger.warning("训练数据为空")
            return

        features_list = []
        labels_list = []

        for item in training_data:
            packets = item.get("packets", [])
            label = item.get("label", 0)
            flow_key = item.get("flow_key", "")

            feature = self.feature_extractor.extract_features(flow_key, packets)
            features_list.append(feature.to_list())
            labels_list.append(label)

        # 训练异常检测模型（只用正常流量）
        normal_features = [
            f for f, l in zip(features_list, labels_list) if l == 0
        ]
        if normal_features:
            self.anomaly_detector.fit(normal_features)

        # 训练分类模型
        if features_list:
            self.traffic_classifier.fit(features_list, labels_list)

        self._is_trained = True
        logger.info(f"模型训练完成, 总样本: {len(training_data)}")

    def detect(self, flow_key: str, packets: List[Dict]) -> Dict:
        """综合检测"""
        feature = self.feature_extractor.extract_features(flow_key, packets)
        feature_list = feature.to_list()

        result = {
            "flow_key": flow_key,
            "timestamp": time.time(),
            "is_anomaly": False,
            "anomaly_score": 0.0,
            "predicted_class": 0,
            "predicted_label": "正常流量",
            "classification_confidence": 0.0,
        }

        if not self._is_trained:
            return result

        self._prediction_count += 1

        # 异常检测
        is_anomaly, anomaly_score = self.anomaly_detector.is_anomaly(feature_list)
        result["is_anomaly"] = is_anomaly
        result["anomaly_score"] = round(anomaly_score, 4)

        # 流量分类
        pred_class, confidence = self.traffic_classifier.predict(feature_list)
        result["predicted_class"] = pred_class
        result["predicted_label"] = self.traffic_classifier.get_label_name(pred_class)
        result["classification_confidence"] = round(confidence, 4)

        if is_anomaly:
            self._anomaly_count += 1

        return result

    def get_statistics(self) -> Dict:
        """获取引擎统计"""
        return {
            "is_trained": self._is_trained,
            "total_predictions": self._prediction_count,
            "anomaly_detections": self._anomaly_count,
            "anomaly_rate": round(
                self._anomaly_count / max(self._prediction_count, 1), 4
            ),
            "forest_trees": self.anomaly_detector.n_trees,
            "knn_training_size": len(self.traffic_classifier._training_data),
            "detection_threshold": round(self.anomaly_detector._threshold, 4),
        }
