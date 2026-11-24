"""拾音工坊核心数据模型：真实日志采集与事件流处理的数据结构。"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class LogFormat(Enum):
    """日志格式枚举，对应 parser_rule 的正则表达式匹配。"""
    ACCESS = "access"
    APP = "app"
    SYS = "sys"
    CUSTOM = "custom"


class ParseResultStatus(Enum):
    """解析结果状态。"""
    OK = "ok"
    FORMAT_MISMATCH = "format_mismatch"
    FIELD_MISSING = "field_missing"
    ENCODING_ERROR = "encoding_error"
    LINE_EMPTY = "line_empty"


class MaskMethod(Enum):
    """脱敏方式枚举。"""
    PHONE = "phone"
    ID_CARD = "id_card"
    EMAIL = "email"
    IP = "ip"
    TOKEN = "token"
    CUSTOM_REGEX = "custom_regex"


class SeverityLevel(Enum):
    """事件严重级别枚举——按严重程度排序的独立评级。

    评级只作用于单条事件的独立级别判定（SeverityDecision），
    不允许回写 EventTypeDef.severity（类型模板默认值）。
    """
    TRACE = "TRACE"
    DEBUG = "DEBUG"
    LOW = "LOW"
    INFO = "INFO"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


# 严重级别排序：数值越大越严重；LOW 与模板默认 INFO 同档。
SEVERITY_RANK: dict[str, int] = {
    "TRACE": 0,
    "DEBUG": 10,
    "LOW": 20,
    "INFO": 20,
    "MEDIUM": 30,
    "HIGH": 40,
}


def severity_rank(level: str) -> int:
    """返回严重级别排序值，未知级别按最低档处理。"""
    return SEVERITY_RANK.get((level or "").upper(), 0)


@dataclass
class LogSourceConfig:
    """日志来源配置模型——对应 log_source 模块。"""
    source_id: str
    source_name: str
    app_label: str
    log_path: str
    log_format: str
    encoding: str = "utf-8"
    collect_method: str = "file_tail"
    access_state: str = "待验证"

    def match_format(self, line: str) -> bool:
        """校验一条日志行是否匹配此来源的格式。"""
        if self.log_format == "access":
            return bool(re.match(
                r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s.*?"[A-Z]+\s\S+\sHTTP',
                line.strip()))
        if self.log_format == "app":
            return bool(re.match(
                r'^\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3}\s+\[.*?\]\s+(INFO|WARN|ERROR|DEBUG)\s+',
                line.strip()))
        if self.log_format == "sys":
            return bool(re.match(
                r'^[\w-]+\s+\d+\s+\d{2}:\d{2}:\d{2}\s+[\w-]+\s+[\w-]+\[',
                line.strip()))
        return bool(line.strip() and len(line.strip()) > 10)


@dataclass
class ParseRule:
    """解析规则模型——对应 parser_rule 模块。"""
    rule_id: str
    source_id: str
    regex_pattern: str
    field_names: list[str]
    time_format: str = "%Y-%m-%d %H:%M:%S"
    multiline: bool = False
    priority: int = 0
    state: str = "草稿"
    _compiled_re: re.Pattern[str] | None = field(default=None, repr=False, compare=False)

    def compile(self) -> re.Pattern[str]:
        """编译正则表达式（惰性编译）。"""
        if self._compiled_re is None:
            self._compiled_re = re.compile(self.regex_pattern)
        return self._compiled_re

    def parse(self, line: str) -> tuple[ParseResultStatus, dict[str, str] | None]:
        """用解析规则提取一条日志行的字段。"""
        try:
            compiled = self.compile()
            m = compiled.match(line.strip())
            if m is None:
                return ParseResultStatus.FORMAT_MISMATCH, None
            fields = dict(zip(self.field_names, m.groups()))
            missing = [name for name in self.field_names if name not in fields]
            if missing:
                return ParseResultStatus.FIELD_MISSING, fields
            return ParseResultStatus.OK, fields
        except re.error:
            return ParseResultStatus.FORMAT_MISMATCH, None


@dataclass
class LogEntry:
    """单条日志条目——跨模块流转的核心数据载体。"""
    raw_line: str
    line_number: int
    source_id: str
    parsed_fields: dict[str, str] | None = None
    parse_status: ParseResultStatus = ParseResultStatus.OK
    event_time: datetime | None = None
    host: str = ""
    checksum: str = field(default="")

    def compute_checksum(self) -> str:
        """基于原始行和解析字段计算内容校验哈希。"""
        raw = (
            f"{self.source_id}|{self.line_number}|{self.raw_line[:200]}"
            f"|{sorted((self.parsed_fields or {}).items())}"
        )
        return hashlib.sha256(raw.encode()).hexdigest()

    def __post_init__(self):
        if not self.checksum:
            self.checksum = self.compute_checksum()


@dataclass
class MaskRule:
    """脱敏规则模型——对应 mask_rule 模块。"""
    rule_id: str
    target_field: str
    mask_method: MaskMethod
    mask_pattern: str
    retain_count: int = 0
    rule_state: str = "草稿"

    def apply(self, value: str) -> str:
        """对字段值执行脱敏变换。"""
        if not value:
            return value
        if self.mask_method == MaskMethod.PHONE:
            if len(value) >= 11:
                return value[:3] + "****" + value[-4:]
            return value[:1] + "****" + value[-1:] if len(value) > 2 else "****"
        if self.mask_method == MaskMethod.ID_CARD:
            if len(value) >= 18:
                return value[:6] + "********" + value[-4:]
            return value[:2] + "****" + value[-2:] if len(value) > 4 else "****"
        if self.mask_method == MaskMethod.EMAIL:
            parts = value.split("@")
            if len(parts) == 2:
                local = parts[0]
                masked_local = local[:2] + "***" + local[-1:] if len(local) > 3 else "***"
                return f"{masked_local}@{parts[1]}"
            return "***@***"
        if self.mask_method == MaskMethod.IP:
            octets = value.split(".")
            if len(octets) == 4:
                return f"{octets[0]}.{octets[1]}.*.*"
            return "***.***.***.***"
        if self.mask_method == MaskMethod.CUSTOM_REGEX:
            compiled = re.compile(self.mask_pattern)
            return compiled.sub("***", value)
        return value


@dataclass
class MaskResult:
    """脱敏变换结果——记录哪个字段被何种方式脱敏。"""
    rule_id: str
    field_name: str
    original: str
    masked: str
    method: MaskMethod
    is_masked: bool = True

    def verify(self) -> bool:
        """校验脱敏结果：敏感原值不应出现在掩码后的结果中。"""
        if not self.is_masked:
            return True
        if len(self.original) < 3:
            return self.masked != self.original
        core = self.original[3:-3] if len(self.original) > 6 else self.original
        return core not in self.masked


@dataclass
class FieldEnrichRule:
    """字段增强规则——对应 field_enrich 模块。"""
    rule_id: str
    target_field: str
    enrich_source: str
    mapping_dict: dict[str, str]
    default_value: str = "unknown"
    priority: int = 0
    # 只有已批准的级别增强规则才能进入独立级别判定；未批准的仍可写字段，不产生评级依据。
    approved: bool = True

    def enrich(self, fields: dict[str, str]) -> str:
        """根据映射字典增强目标字段。"""
        key = fields.get(self.enrich_source, "").strip()
        return self.mapping_dict.get(key, self.default_value)


@dataclass
class SeverityEvidence:
    """单条级别增强依据——一份字段证据，多规则命中时全部保留。

    保留增强前的原字段与增强后的级别、规则优先级，使争议事件可凭两份原字段追溯，
    不依赖登记顺序，也不覆盖彼此。
    """
    rule_id: str
    target_field: str
    source_field: str
    source_value: str          # 增强前的原字段值（依据）
    severity: str              # 增强映射出的级别
    priority: int
    approved: bool = True
    template_version: str = ""


@dataclass
class SeverityDecision:
    """单条事件的独立级别判定数据——与事件类型模板默认值完全隔离。

    - default_level：判定时采用的类型模板默认级别（来自某一模板版本快照）
    - effective_level：本次实际评级；有争议且未确认时回落到模板默认级别
    - confirmed：值班者是否已正式确认；确认后评级冻结，重复核验/更正不再改动
    - blocked：同优先级增强规则给出互斥级别（如 HIGH 与 TRACE），阻止进入正式高警
    """
    default_level: str = "INFO"
    effective_level: str = "INFO"
    template_version: str = ""
    evidences: list[SeverityEvidence] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    blocked: bool = False
    confirmed: bool = False
    confirmed_by: str = ""
    confirmed_level: str = ""

    def is_high(self) -> bool:
        """是否为可进入正式高警的 HIGH 评级（争议事件被阻止）。"""
        return not self.blocked and self.confirmed and self.confirmed_level == "HIGH"

    def is_medium_or_above(self) -> bool:
        """是否达到普通复查门槛 MEDIUM 及以上（争议事件被阻止）。"""
        if self.blocked:
            return False
        level = self.confirmed_level if self.confirmed else self.effective_level
        return severity_rank(level) >= severity_rank("MEDIUM")


@dataclass
class EventTypeDef:
    """事件类型定义——对应 event_type 模块。"""
    type_id: str
    type_name: str
    category_tag: str
    severity: str = "INFO"
    alert_threshold: int = 0
    sample_ratio: float = 1.0
    retain_days: int = 30
    # 模板版本标识：默认值被管理员调整时升版，独立判定只引用快照，不回写该对象。
    template_version: str = "v1"


@dataclass
class EventRecord:
    """标准化事件记录——解析、脱敏、增强后的最终产物。"""
    record_id: str
    event_type: EventTypeDef
    original_content: str
    parsed_fields: dict[str, str]
    masked_fields: dict[str, str]
    enriched_fields: dict[str, str]
    event_time: datetime
    source_host: str
    store_partition: str = ""
    index_state: str = "已写入"
    # 独立级别判定数据：单事件专属，绝不共享、绝不回写 event_type 模板。
    severity_decision: SeverityDecision | None = None
    # 复查领取状态：已领取但未正式确认期间，模板默认值变更需按版本优先级处理。
    review_claimed: bool = False
    review_claimed_by: str = ""


@dataclass
class DedupFilter:
    """去重过滤规则——对应 dedup_filter 模块。"""
    rule_id: str
    event_type_id: str
    dedup_fields: list[str]
    window_minutes: int = 60
    fingerprint_algo: str = "sha256"
    hit_count: int = 0
    ignore_count: int = 0

    def fingerprint(self, event: EventRecord) -> str:
        """基于去重字段生成事件指纹。"""
        key_parts = [event.event_type.type_id]
        for field in sorted(self.dedup_fields):
            val = event.parsed_fields.get(field) or event.masked_fields.get(field) or ""
            key_parts.append(f"{field}={val}")
        raw_key = "|".join(key_parts)
        return hashlib.sha256(raw_key.encode()).hexdigest()

    def is_duplicate(self, event: EventRecord, seen_fingerprints: set[str]) -> bool:
        """判断事件是否重复。"""
        fp = self.fingerprint(event)
        if fp in seen_fingerprints:
            self.hit_count += 1
            return True
        seen_fingerprints.add(fp)
        return False


@dataclass
class SampleConfig:
    """采样归并配置——对应 sample_job 模块。"""
    plan_id: str
    event_type_id: str
    sample_ratio: float
    merge_key: str = ""
    merge_window_minutes: int = 5
    retain_policy: str = "latest"


@dataclass
class BatchCheckpoint:
    """批次检查点——对应 batch_checkpoint 模块。"""
    checkpoint_id: str
    job_id: str
    file_path: str
    byte_offset: int
    line_count: int
    content_hash: str
    check_time: datetime = field(default_factory=datetime.now)
    state: str = "已记录"


@dataclass
class IngestJob:
    """采集作业模型——对应 ingest_job 模块。"""
    job_id: str
    source_id: str
    collect_mode: str = "incremental"
    file_cursor: int = 0
    batch_size: int = 100
    thread_count: int = 1
    processed_lines: int = 0
    skipped_lines: int = 0
    state: str = "待执行"


@dataclass
class IngestMetric:
    """采集指标——对应 ingest_metric 模块。"""
    metric_id: str
    source_id: str
    ingest_rate: float = 0.0
    process_delay_ms: float = 0.0
    error_rate: float = 0.0
    backlog_lines: int = 0
    sample_time: datetime = field(default_factory=datetime.now)


@dataclass
class QualityReport:
    """质量报告——对应 quality_report 模块。"""
    report_id: str
    source_id: str
    completeness_rate: float = 0.0
    parse_success_rate: float = 0.0
    field_coverage_rate: float = 0.0
    time_delay_seconds: float = 0.0
    eval_period: str = "daily"
    state: str = "待生成"


@dataclass
class AnomalyRule:
    """异常告警规则——对应 anomaly_rule 模块。"""
    rule_id: str
    event_type_id: str
    detect_condition: str
    alert_level: str = "WARNING"
    trigger_frequency: int = 1
    aggregate_window_minutes: int = 5
    notify_channel: str = "webhook"


@dataclass
class ForwardRule:
    """转发路由规则——对应 forward_rule 模块。"""
    rule_id: str
    event_type_id: str
    target_address: str
    forward_format: str = "json"
    batch_size: int = 100
    retry_limit: int = 3
    timeout_seconds: int = 30