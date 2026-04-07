# -*- coding: utf-8 -*-
"""
智盾网络安全态势感知与智能防御系统 - 安全报告生成模块
自动生成多维度、多格式的安全分析报告
"""

import json
import logging
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from config.settings import ThreatLevel

logger = logging.getLogger(__name__)


class ReportType(Enum):
    """报告类型"""
    DAILY = "日报"
    WEEKLY = "周报"
    MONTHLY = "月报"
    INCIDENT = "事件报告"
    COMPLIANCE = "合规报告"
    EXECUTIVE = "管理层摘要"
    CUSTOM = "自定义报告"


class ReportFormat(Enum):
    """报告格式"""
    HTML = "html"
    JSON = "json"
    PDF = "pdf"
    CSV = "csv"


@dataclass
class ReportSection:
    """报告章节"""
    title: str
    content: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    charts: List[Dict] = field(default_factory=list)
    tables: List[Dict] = field(default_factory=list)
    subsections: List['ReportSection'] = field(default_factory=list)


@dataclass
class SecurityReport:
    """安全报告"""
    report_id: str
    report_type: ReportType
    title: str
    generated_at: float
    period_start: float
    period_end: float
    generated_by: str
    sections: List[ReportSection] = field(default_factory=list)
    summary: str = ""
    recommendations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "report_id": self.report_id,
            "report_type": self.report_type.value,
            "title": self.title,
            "generated_at": self.generated_at,
            "period_start": self.period_start,
            "period_end": self.period_end,
            "summary": self.summary,
            "recommendations": self.recommendations,
            "section_count": len(self.sections),
        }


class ReportTemplateEngine:
    """报告模板引擎"""

    HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>
        body {{ font-family: "Microsoft YaHei", sans-serif; margin: 40px; color: #333; }}
        .header {{ background: linear-gradient(135deg, #1a237e, #0d47a1); color: white;
                   padding: 30px; border-radius: 8px; margin-bottom: 30px; }}
        .header h1 {{ margin: 0; font-size: 24px; }}
        .header .meta {{ font-size: 14px; opacity: 0.8; margin-top: 10px; }}
        .summary {{ background: #e3f2fd; padding: 20px; border-radius: 8px;
                    border-left: 4px solid #1565c0; margin-bottom: 20px; }}
        .section {{ margin-bottom: 30px; }}
        .section h2 {{ color: #1565c0; border-bottom: 2px solid #e3f2fd; padding-bottom: 8px; }}
        .section h3 {{ color: #1976d2; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th {{ background: #1565c0; color: white; padding: 10px; text-align: left; }}
        td {{ padding: 8px 10px; border-bottom: 1px solid #e0e0e0; }}
        tr:hover {{ background: #f5f5f5; }}
        .metric {{ display: inline-block; background: #f5f5f5; padding: 15px 25px;
                   border-radius: 8px; margin: 5px; text-align: center; }}
        .metric .value {{ font-size: 28px; font-weight: bold; color: #1565c0; }}
        .metric .label {{ font-size: 12px; color: #666; }}
        .recommendation {{ background: #fff3e0; padding: 15px; border-radius: 8px;
                          border-left: 4px solid #ff9800; margin: 10px 0; }}
        .critical {{ color: #d32f2f; font-weight: bold; }}
        .high {{ color: #f57c00; font-weight: bold; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #4caf50; }}
        .footer {{ text-align: center; color: #999; font-size: 12px;
                   margin-top: 40px; padding-top: 20px; border-top: 1px solid #e0e0e0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{title}</h1>
        <div class="meta">
            报告类型: {report_type} | 生成时间: {generated_time} | 报告周期: {period}
        </div>
    </div>
    <div class="summary">
        <h3>执行摘要</h3>
        <p>{summary}</p>
    </div>
    {content}
    <div class="section">
        <h2>安全建议</h2>
        {recommendations}
    </div>
    <div class="footer">
        智盾网络安全态势感知与智能防御系统 V1.0 - 自动生成报告 - {generated_time}
    </div>
</body>
</html>"""

    @classmethod
    def render_html(cls, report: SecurityReport) -> str:
        """渲染HTML报告"""
        content_html = ""
        for section in report.sections:
            content_html += cls._render_section(section)

        rec_html = ""
        for i, rec in enumerate(report.recommendations, 1):
            rec_html += f'<div class="recommendation">{i}. {rec}</div>\n'

        return cls.HTML_TEMPLATE.format(
            title=report.title,
            report_type=report.report_type.value,
            generated_time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(report.generated_at)),
            period=f"{time.strftime('%Y-%m-%d', time.localtime(report.period_start))} 至 "
                   f"{time.strftime('%Y-%m-%d', time.localtime(report.period_end))}",
            summary=report.summary,
            content=content_html,
            recommendations=rec_html,
        )

    @classmethod
    def _render_section(cls, section: ReportSection) -> str:
        """渲染章节"""
        html = f'<div class="section"><h2>{section.title}</h2>\n'

        if section.content:
            html += f"<p>{section.content}</p>\n"

        for table in section.tables:
            html += cls._render_table(table)

        for chart in section.charts:
            html += cls._render_chart_placeholder(chart)

        for subsection in section.subsections:
            html += f"<h3>{subsection.title}</h3>\n"
            if subsection.content:
                html += f"<p>{subsection.content}</p>\n"
            for table in subsection.tables:
                html += cls._render_table(table)

        html += "</div>\n"
        return html

    @staticmethod
    def _render_table(table: Dict) -> str:
        """渲染表格"""
        html = "<table>\n<thead><tr>"
        headers = table.get("headers", [])
        for h in headers:
            html += f"<th>{h}</th>"
        html += "</tr></thead>\n<tbody>\n"

        rows = table.get("rows", [])
        for row in rows:
            html += "<tr>"
            for cell in row:
                html += f"<td>{cell}</td>"
            html += "</tr>\n"

        html += "</tbody></table>\n"
        return html

    @staticmethod
    def _render_chart_placeholder(chart: Dict) -> str:
        """渲染图表占位符"""
        return f'<div class="metric"><div class="label">{chart.get("title", "")}</div></div>\n'


class ReportGenerator:
    """安全报告生成器

    核心功能：
    1. 多类型报告自动生成（日报/周报/月报/事件报告）
    2. 多格式输出支持（HTML/JSON/PDF/CSV）
    3. 智能安全建议生成
    4. 可定制报告模板
    5. 报告归档与检索
    """

    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = output_dir
        self.template_engine = ReportTemplateEngine()
        self._report_history: List[SecurityReport] = []

        logger.info("安全报告生成器初始化完成")

    def generate_daily_report(self, alert_data: List[Dict],
                              traffic_stats: Dict,
                              posture_data: Dict,
                              response_data: Dict) -> SecurityReport:
        """生成日报"""
        now = time.time()
        period_start = now - 86400

        report = SecurityReport(
            report_id=f"RPT-DAILY-{time.strftime('%Y%m%d')}",
            report_type=ReportType.DAILY,
            title=f"智盾安全态势日报 - {time.strftime('%Y年%m月%d日')}",
            generated_at=now,
            period_start=period_start,
            period_end=now,
            generated_by="system",
        )

        # 总体概述
        total_alerts = len(alert_data)
        critical_alerts = sum(1 for a in alert_data if a.get("threat_level") in ("CRITICAL", "EMERGENCY"))
        blocked_count = response_data.get("auto_blocks", 0) + response_data.get("manual_blocks", 0)

        report.summary = (
            f"过去24小时内，系统共检测到 {total_alerts} 起安全告警，"
            f"其中严重/紧急告警 {critical_alerts} 起。"
            f"自动响应引擎成功拦截 {blocked_count} 次攻击。"
            f"当前网络安全态势整体{'可控' if critical_alerts < 5 else '严峻'}。"
        )

        # 安全态势概览章节
        posture_section = ReportSection(
            title="安全态势概览",
            content=f"当前安全评分: {posture_data.get('overall_score', 'N/A')}, "
                    f"风险等级: {posture_data.get('risk_level', 'N/A')}, "
                    f"趋势: {posture_data.get('trend', 'N/A')}",
        )
        report.sections.append(posture_section)

        # 告警统计章节
        alert_section = self._build_alert_section(alert_data)
        report.sections.append(alert_section)

        # 流量分析章节
        traffic_section = self._build_traffic_section(traffic_stats)
        report.sections.append(traffic_section)

        # 响应处置章节
        response_section = self._build_response_section(response_data)
        report.sections.append(response_section)

        # 生成安全建议
        report.recommendations = self._generate_recommendations(
            alert_data, posture_data, traffic_stats
        )

        self._report_history.append(report)
        return report

    def generate_incident_report(self, incident_alerts: List[Dict],
                                 response_records: List[Dict],
                                 impact_assessment: Dict) -> SecurityReport:
        """生成安全事件报告"""
        now = time.time()

        timestamps = [a.get("timestamp", now) for a in incident_alerts]
        period_start = min(timestamps) if timestamps else now - 3600
        period_end = max(timestamps) if timestamps else now

        report = SecurityReport(
            report_id=f"RPT-INC-{int(now)}",
            report_type=ReportType.INCIDENT,
            title=f"安全事件分析报告 - {time.strftime('%Y%m%d%H%M%S')}",
            generated_at=now,
            period_start=period_start,
            period_end=period_end,
            generated_by="system",
        )

        # 事件概述
        attack_types = set(a.get("attack_type", "") for a in incident_alerts)
        report.summary = (
            f"本次安全事件涉及 {len(incident_alerts)} 条告警，"
            f"攻击类型包括: {', '.join(attack_types)}。"
        )

        # 事件时间线
        timeline_section = ReportSection(
            title="事件时间线",
            tables=[{
                "headers": ["时间", "告警ID", "攻击类型", "威胁等级", "源IP", "目标IP", "描述"],
                "rows": [
                    [
                        time.strftime("%H:%M:%S", time.localtime(a.get("timestamp", 0))),
                        a.get("alert_id", ""),
                        a.get("attack_type", ""),
                        a.get("threat_level", ""),
                        a.get("src_ip", ""),
                        a.get("dst_ip", ""),
                        a.get("description", "")[:50],
                    ]
                    for a in sorted(incident_alerts, key=lambda x: x.get("timestamp", 0))
                ]
            }]
        )
        report.sections.append(timeline_section)

        # 影响评估
        impact_section = ReportSection(
            title="影响评估",
            content=f"受影响资产: {impact_assessment.get('affected_assets', 0)} 个, "
                    f"数据泄露风险: {impact_assessment.get('data_leak_risk', '低')}, "
                    f"业务影响: {impact_assessment.get('business_impact', '低')}",
        )
        report.sections.append(impact_section)

        # 处置记录
        response_section = ReportSection(
            title="处置记录",
            tables=[{
                "headers": ["时间", "响应动作", "状态", "目标IP", "原因"],
                "rows": [
                    [
                        time.strftime("%H:%M:%S", time.localtime(r.get("timestamp", 0))),
                        r.get("action", ""),
                        r.get("status", ""),
                        r.get("target_ip", ""),
                        r.get("reason", "")[:50],
                    ]
                    for r in response_records
                ]
            }]
        )
        report.sections.append(response_section)

        report.recommendations = [
            "立即核实受影响系统的完整性",
            "检查是否存在未被发现的后门程序",
            "更新受影响系统的安全补丁",
            "加强对类似攻击向量的监控力度",
            "完善应急响应预案",
        ]

        self._report_history.append(report)
        return report

    def _build_alert_section(self, alert_data: List[Dict]) -> ReportSection:
        """构建告警统计章节"""
        type_counts = defaultdict(int)
        level_counts = defaultdict(int)
        source_counts = defaultdict(int)

        for alert in alert_data:
            type_counts[alert.get("attack_type", "未知")] += 1
            level_counts[alert.get("threat_level", "未知")] += 1
            source_counts[alert.get("src_ip", "未知")] += 1

        section = ReportSection(
            title="告警分析",
            content=f"共检测到 {len(alert_data)} 条安全告警",
        )

        # 按类型统计
        section.subsections.append(ReportSection(
            title="攻击类型分布",
            tables=[{
                "headers": ["攻击类型", "数量", "占比"],
                "rows": [
                    [atype, count, f"{count/max(len(alert_data),1)*100:.1f}%"]
                    for atype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
                ]
            }]
        ))

        # 按等级统计
        section.subsections.append(ReportSection(
            title="威胁等级分布",
            tables=[{
                "headers": ["威胁等级", "数量"],
                "rows": [
                    [level, count]
                    for level, count in sorted(level_counts.items(), key=lambda x: x[1], reverse=True)
                ]
            }]
        ))

        # Top攻击源
        top_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        section.subsections.append(ReportSection(
            title="Top 10 攻击源",
            tables=[{
                "headers": ["源IP", "告警数量"],
                "rows": [[ip, count] for ip, count in top_sources]
            }]
        ))

        return section

    def _build_traffic_section(self, traffic_stats: Dict) -> ReportSection:
        """构建流量分析章节"""
        section = ReportSection(
            title="网络流量分析",
            content=f"总流量: {traffic_stats.get('total_bytes', 0) / (1024*1024):.1f} MB, "
                    f"总数据包: {traffic_stats.get('total_packets', 0)}, "
                    f"活跃流: {traffic_stats.get('active_flows', 0)}",
        )

        proto_dist = traffic_stats.get("protocol_distribution", {})
        if proto_dist:
            section.tables.append({
                "headers": ["协议", "数据包数"],
                "rows": [
                    [proto, count]
                    for proto, count in sorted(proto_dist.items(), key=lambda x: x[1], reverse=True)
                ]
            })

        return section

    def _build_response_section(self, response_data: Dict) -> ReportSection:
        """构建响应处置章节"""
        section = ReportSection(
            title="响应处置统计",
            content=f"总响应次数: {response_data.get('total_responses', 0)}, "
                    f"自动封禁: {response_data.get('auto_blocks', 0)}, "
                    f"手动封禁: {response_data.get('manual_blocks', 0)}",
        )

        actions = response_data.get("responses_by_action", {})
        if actions:
            section.tables.append({
                "headers": ["响应动作", "执行次数"],
                "rows": [[action, count] for action, count in actions.items()]
            })

        return section

    def _generate_recommendations(self, alert_data: List[Dict],
                                   posture_data: Dict,
                                   traffic_stats: Dict) -> List[str]:
        """智能生成安全建议"""
        recommendations = []

        type_counts = defaultdict(int)
        for alert in alert_data:
            type_counts[alert.get("attack_type", "")] += 1

        if type_counts.get("SQL注入", 0) > 5:
            recommendations.append(
                "检测到频繁SQL注入攻击，建议: (1)部署WAF; (2)对所有数据库查询进行参数化; (3)限制数据库账户权限"
            )

        if type_counts.get("暴力破解", 0) > 10:
            recommendations.append(
                "检测到大量暴力破解尝试，建议: (1)启用多因素认证; (2)实施登录频率限制; (3)检查弱密码账户"
            )

        if type_counts.get("DDoS攻击", 0) > 0:
            recommendations.append(
                "检测到DDoS攻击，建议: (1)启用流量清洗服务; (2)配置CDN分散流量; (3)完善DDoS应急预案"
            )

        if type_counts.get("数据泄露", 0) > 0:
            recommendations.append(
                "检测到数据泄露风险，建议: (1)立即排查敏感数据访问; (2)加强DLP策略; (3)审计数据外传通道"
            )

        overall_score = posture_data.get("overall_score", 100)
        if overall_score < 60:
            recommendations.append(
                "当前安全评分偏低，建议: (1)全面排查安全漏洞; (2)更新安全策略; (3)加强安全培训"
            )

        if not recommendations:
            recommendations.append("当前安全态势良好，建议继续保持安全策略执行力度，定期进行安全评估")

        return recommendations

    def export_report(self, report: SecurityReport,
                      format: ReportFormat = ReportFormat.HTML) -> str:
        """导出报告"""
        if format == ReportFormat.HTML:
            content = self.template_engine.render_html(report)
            filename = f"{report.report_id}.html"
        elif format == ReportFormat.JSON:
            content = json.dumps(report.to_dict(), ensure_ascii=False, indent=2)
            filename = f"{report.report_id}.json"
        else:
            content = json.dumps(report.to_dict(), ensure_ascii=False, indent=2)
            filename = f"{report.report_id}.json"

        filepath = os.path.join(self.output_dir, filename)
        os.makedirs(self.output_dir, exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

        logger.info(f"报告已导出: {filepath}")
        return filepath

    def get_report_list(self) -> List[Dict]:
        """获取报告列表"""
        return [r.to_dict() for r in self._report_history]
