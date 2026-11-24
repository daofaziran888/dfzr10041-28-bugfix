"""拾音工坊脱敏与字段增强管道：event_store→mask_rule→field_enrich→event_type。

数据流：已存储的 EventRecord → 脱敏变换 (mask_rule) → 字段增强 (field_enrich) → 更新事件分类标记
涉及模块：event_store, mask_rule, field_enrich, event_type
"""
from __future__ import annotations

from app.core.models import (
    EventRecord, FieldEnrichRule, MaskMethod, MaskResult, MaskRule,
    SeverityEvidence,
)
from app.core.severity import SeverityService

# ---------- 预置脱敏规则 ----------

PRESET_MASK_RULES: list[MaskRule] = [
    MaskRule(
        rule_id="MASK-0001",
        target_field="client_ip",
        mask_method=MaskMethod.IP,
        mask_pattern="",
        rule_state="生效中",
    ),
    MaskRule(
        rule_id="MASK-0002",
        target_field="user_agent",
        mask_method=MaskMethod.CUSTOM_REGEX,
        mask_pattern=r'[A-Za-z0-9+/]{40,}=*',
        rule_state="生效中",
    ),
    MaskRule(
        rule_id="MASK-0003",
        target_field="message",
        mask_method=MaskMethod.PHONE,
        mask_pattern="",
        rule_state="生效中",
    ),
]

# ---------- 预置字段增强规则 ----------

PRESET_ENRICH_RULES: list[FieldEnrichRule] = [
    FieldEnrichRule(
        rule_id="FIEL-0001",
        target_field="app_name",
        enrich_source="logger",
        mapping_dict={
            "com.example.IngestController": "ingest-service",
            "com.example.ParserEngine": "parser-engine",
            "com.example.CheckpointStore": "checkpoint-store",
            "com.example.MaskService": "mask-service",
        },
        default_value="unknown-service",
        priority=10,
    ),
    FieldEnrichRule(
        rule_id="FIEL-0002",
        target_field="severity_level",
        enrich_source="level",
        mapping_dict={
            "INFO": "LOW",
            "WARN": "MEDIUM",
            "ERROR": "HIGH",
            "DEBUG": "TRACE",
        },
        default_value="UNKNOWN",
        priority=10,
    ),
    FieldEnrichRule(
        rule_id="FIEL-0003",
        target_field="status_category",
        enrich_source="status",
        mapping_dict={
            "200": "SUCCESS",
            "201": "SUCCESS",
            "301": "REDIRECT",
            "302": "REDIRECT",
            "400": "CLIENT_ERROR",
            "401": "AUTH_ERROR",
            "403": "AUTH_ERROR",
            "404": "CLIENT_ERROR",
            "500": "SERVER_ERROR",
            "502": "SERVER_ERROR",
            "503": "SERVER_ERROR",
        },
        default_value="OTHER",
        priority=5,
    ),
]


class MaskEnrichPipeline:
    """脱敏与字段增强处理管道。

    接收 EventRecord 集合 → 依次应用 mask_rule → field_enrich → 更新 event_type 标记
    """

    def __init__(self, mask_rules: list[MaskRule] | None = None,
                 enrich_rules: list[FieldEnrichRule] | None = None,
                 severity_service: SeverityService | None = None):
        if mask_rules is None:
            mask_rules = PRESET_MASK_RULES
        if enrich_rules is None:
            enrich_rules = PRESET_ENRICH_RULES
        self.mask_rules = mask_rules
        self.enrich_rules = enrich_rules
        # 独立级别判定服务：负责生成单事件 SeverityDecision，模板默认值由它做版本快照。
        self.severity_service = severity_service or SeverityService()
        self._mask_results: list[MaskResult] = []

    # ---------- 数据流 3: event_store → mask_rule → field_enrich → event_type ----------

    def apply_all_masks(self, record: EventRecord) -> MaskResult:
        """对一条事件记录的所有敏感字段执行脱敏变换。

        每条脱敏规则按目标字段匹配 record.parsed_fields，
        执行对应脱敏方式（phone/id_card/email/ip/custom_regex）。
        脱敏后的值写入 record.masked_fields。
        """
        last_result: MaskResult | None = None
        for rule in self.mask_rules:
            target = rule.target_field
            value = record.parsed_fields.get(target, "")
            if not value:
                continue
            masked_value = rule.apply(value)
            record.masked_fields[target] = masked_value
            result = MaskResult(
                rule_id=rule.rule_id,
                field_name=target,
                original=value,
                masked=masked_value,
                method=rule.mask_method,
                is_masked=masked_value != value,
            )
            self._mask_results.append(result)
            last_result = result
        return last_result if last_result else MaskResult(
            rule_id="", field_name="", original="", masked="",
            method=MaskMethod.CUSTOM_REGEX, is_masked=False,
        )

    def apply_all_enrichments(self, record: EventRecord) -> dict[str, str]:
        """对一条事件记录执行所有字段增强。

        每条增强规则按 enrich_source 作为查询键查找 mapping_dict，
        将映射值写入 record.enriched_fields 的 target_field 下。
        未命中映射时使用 default_value。
        """
        enriched: dict[str, str] = {}
        for rule in sorted(self.enrich_rules, key=lambda r: r.priority):
            source_value = (
                record.parsed_fields.get(rule.enrich_source) or
                record.masked_fields.get(rule.enrich_source) or ""
            )
            mapped = rule.enrich(record.parsed_fields)
            record.enriched_fields[rule.target_field] = mapped
            enriched[rule.target_field] = mapped
        return enriched

    def process_records(self, records: list[EventRecord]) -> list[EventRecord]:
        """批量处理事件记录：依次执行脱敏、字段增强和独立级别判定。

        这是 event_store → mask_rule → field_enrich → event_type 的完整实现。
        级别增强只写入单事件的 SeverityDecision，绝不修改 event_type 模板默认值；
        已确认评级的事件重复核验时保持冻结。
        """
        for record in records:
            # 1. mask_rule: 脱敏变换
            self.apply_all_masks(record)
            # 2. field_enrich: 字段增强
            self.apply_all_enrichments(record)
            # 3. 独立级别判定：生成/重算单事件级别，模板默认值保持不变
            self._update_severity(record)
        return records

    def verify_mask_completeness(self, records: list[EventRecord]) -> dict[str, Any]:
        """验证脱敏完整性：检查是否有敏感值泄露（遗漏告警）。

        逐个检查 mask_results，确认掩码值不包含原始敏感数据核心部分。
        返回遗漏清单和覆盖率。
        """
        leaks: list[dict[str, str]] = []
        for record in records:
            for rule in self.mask_rules:
                target = rule.target_field
                original = record.parsed_fields.get(target, "")
                masked = record.masked_fields.get(target, original)
                if not original:
                    continue
                if len(original) > 3 and original[2:-2] in masked:
                    leaks.append({
                        "record_id": record.record_id,
                        "field": target,
                        "original_snippet": original[:50],
                        "masked_snippet": masked[:50],
                        "rule_id": rule.rule_id,
                    })
        total_fields = len(self.mask_rules)
        covered = total_fields - len(leaks)
        return {
            "total_rules": total_fields,
            "leaks_found": len(leaks),
            "leaks_detail": leaks,
            "coverage_rate": round(covered / total_fields, 4) if total_fields else 1.0,
        }

    def verify_enrich_mapping(self, expected_enrich_count: int) -> dict[str, Any]:
        """验证字段增强：检查是否有映射缺失。

        统计 enrichment 实际生效的规则数量和映射质量。
        """
        return {
            "expected_rules": expected_enrich_count,
            "actual_rules": len(self.enrich_rules),
            "rules_active": [r.rule_id for r in self.enrich_rules],
            "mapping_missing": any(
                r.default_value != "unknown" for r in self.enrich_rules
            ),
        }

    def get_mask_results(self) -> list[MaskResult]:
        return list(self._mask_results)

    def _collect_severity_evidence(self, record: EventRecord) -> list[SeverityEvidence]:
        """收集本事件命中的全部级别增强依据（含未批准规则），逐份保留原字段。

        同一事件命中多条级别增强规则时所有依据都留存；
        是否参与正式判定交给 SeverityService 按 approved 与优先级处理，
        同优先级互斥级别由判定层阻止，不能按登记顺序覆盖。
        """
        evidences: list[SeverityEvidence] = []
        for rule in sorted(self.enrich_rules, key=lambda r: (r.priority, r.rule_id)):
            if rule.target_field != "severity_level":
                continue
            source_value = (
                record.parsed_fields.get(rule.enrich_source)
                or record.masked_fields.get(rule.enrich_source) or ""
            )
            if not source_value:
                continue
            mapped = rule.enrich(record.parsed_fields)
            if mapped.upper() not in ("TRACE", "DEBUG", "LOW", "INFO", "MEDIUM", "HIGH"):
                continue
            evidences.append(SeverityEvidence(
                rule_id=rule.rule_id,
                target_field=rule.target_field,
                source_field=rule.enrich_source,
                source_value=source_value,
                severity=mapped.upper(),
                priority=rule.priority,
                approved=rule.approved,
                template_version=record.event_type.template_version,
            ))
        return evidences

    def _update_severity(self, record: EventRecord) -> None:
        """根据增强字段生成单事件独立级别判定（不回写事件类型模板）。

        旧实现直接改写 record.event_type.severity，导致一条事件增强为 HIGH
        会污染整个事件类型的默认严重级别、同类型其他事件候选串位。现改为：
        - 模板默认级别只作为只读快照进入 SeverityDecision；
        - 评级结果存放在 record.severity_decision，类型模板 severity 保持原值；
        - 已正式确认的评级重复核验时冻结，不被重复增强覆盖。
        """
        service = self.severity_service
        type_id = record.event_type.type_id
        if service.active_template(type_id) is None:
            service.register_template(
                type_id, record.event_type.template_version,
                record.event_type.severity,
            )
        evidences = self._collect_severity_evidence(record)
        service.compute_decision(record, evidences)


def make_mask_enrich_pipeline() -> MaskEnrichPipeline:
    """工厂函数：创建预配置的脱敏/增强管道实例。"""
    return MaskEnrichPipeline()