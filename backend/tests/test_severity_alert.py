"""测试：单事件独立级别判定与告警复查全链路。

覆盖修复点：
- 单事件级别增强只生成独立 SeverityDecision，不污染事件类型模板默认值；
- 高警 HIGH 与普通复查 MEDIUM+ 分别选真实候选并各自核对告警数量；
- process_records → check_anomaly 调用链串联；
- 同优先级 HIGH/TRACE 冲突保留两份原字段依据并阻止进入正式高警；
- 模板默认值版本冲突、领取未确认、已确认冻结、并发确认幂等；
- 中断恢复不重发、不否认旧告警，更正须关联原复查；
- 模板回写报错可复查；重复核验不改模板。
"""
from __future__ import annotations

import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.models import (
    EventRecord, EventTypeDef, FieldEnrichRule, SeverityEvidence,
)
from app.core.mask_enrich import MaskEnrichPipeline
from app.core.pipeline import IngestPipeline, make_pipeline
from app.core.severity import (
    AlertCheck, SeverityService, resolve_severity_decision,
)


# ---------- 测试夹具 ----------

def make_type(default: str = "INFO", version: str = "v1") -> EventTypeDef:
    """同类型事件共享同一个类型模板对象——用于暴露共享模板污染。"""
    return EventTypeDef(
        type_id="EVEN-T", type_name="串级测试类型",
        category_tag="cascade", severity=default, template_version=version,
    )


def make_record(record_id: str, event_type: EventTypeDef,
                level: str) -> EventRecord:
    return EventRecord(
        record_id=record_id,
        event_type=event_type,
        original_content=f"{record_id} raw {level}",
        parsed_fields={"level": level, "message": f"msg-{record_id}"},
        masked_fields={},
        enriched_fields={},
        event_time=datetime(2026, 11, 24, 10, 0, 0),
        source_host="host-1",
    )


def make_plain_record(record_id: str, event_type: EventTypeDef) -> EventRecord:
    """没有任何级别增强命中的事件（无 level 原字段），评级直接回落模板默认值。"""
    record = make_record(record_id, event_type, "")
    record.parsed_fields = {"message": f"msg-{record_id}"}
    return record


def make_severity_rules() -> list[FieldEnrichRule]:
    """标准级别增强规则：ERROR→HIGH、WARN→MEDIUM、INFO→LOW、DEBUG→TRACE。"""
    return [
        FieldEnrichRule(
            rule_id="FIEL-SEV", target_field="severity_level",
            enrich_source="level",
            mapping_dict={
                "ERROR": "HIGH", "WARN": "MEDIUM",
                "INFO": "LOW", "DEBUG": "TRACE",
            },
            default_value="UNKNOWN", priority=10, approved=True,
        ),
    ]


def make_enrich_pipeline(service: SeverityService | None = None,
                         rules: list[FieldEnrichRule] | None = None
                         ) -> MaskEnrichPipeline:
    return MaskEnrichPipeline(
        mask_rules=[],
        enrich_rules=rules or make_severity_rules(),
        severity_service=service or SeverityService(),
    )


class TestIndependentSeverityDecision:
    """单事件增强不再污染整个事件类型模板，候选与数量各自核对。"""

    def test_single_event_high_does_not_mutate_template(self):
        """同类型 A 有 HIGH 增强、B 无增强且默认 INFO：模板默认值始终保持 INFO。"""
        service = SeverityService()
        event_type = make_type("INFO")
        record_a = make_record("A", event_type, "ERROR")
        record_b = make_plain_record("B", event_type)
        pipeline = make_enrich_pipeline(service)

        pipeline.process_records([record_a, record_b])

        # 独立判定：A=HIGH，B 无增强回落模板默认 INFO
        assert record_a.severity_decision.effective_level == "HIGH"
        assert record_b.severity_decision.effective_level == "INFO"
        # 关键修复：类型模板默认值未被任何单事件回写
        assert event_type.severity == "INFO"
        assert event_type.template_version == "v1"

    def test_high_alert_only_picks_real_high_candidate(self):
        """两条规则都需候选数 > 1 才报警：高警真实候选只有 A，不应触发。"""
        service = SeverityService()
        event_type = make_type("INFO")
        records = [make_record("A", event_type, "ERROR"),
                   make_plain_record("B", event_type)]
        pipeline = make_enrich_pipeline(service)
        pipeline.process_records(records)

        high_candidates = service.eligible_candidates(records, "HIGH")
        medium_candidates = service.select_candidates(records, "MEDIUM")

        assert [r.record_id for r in high_candidates] == ["A"]
        # B 是 INFO，不允许串位成高警候选
        assert all(r.record_id != "B" for r in high_candidates)
        # B 为 INFO 不进 MEDIUM+；A 虽为 HIGH（>= MEDIUM）但未确认，普通复查不自动投递
        assert all(r.record_id != "B" for r in medium_candidates)

        high_review = service.run_review(
            records, AlertCheck("RULE-HIGH", "EVEN-T", "HIGH", threshold=1),
            "target-high",
        )
        medium_review = service.run_review(
            records, AlertCheck("RULE-MED", "EVEN-T", "MEDIUM", threshold=1),
            "target-medium",
        )
        # 候选数均不 > 1：高警只有 A 一条；普通复查仅 A（HIGH 属 MEDIUM 及以上），
        # B 为 INFO 被排除；两条规则候选数都不达标 → 都不发告警
        assert high_review.candidate_ids == ["A"]
        assert high_review.alerts == []
        assert medium_review.candidate_ids == ["A"]
        assert all(c != "B" for c in medium_review.candidate_ids)
        assert medium_review.alerts == []

    def test_repeated_verification_keeps_template_untouched(self):
        """重复核验是幂等的：评级可重算，模板默认值与版本不变。"""
        service = SeverityService()
        event_type = make_type("INFO")
        record_a = make_record("A", event_type, "ERROR")
        pipeline = make_enrich_pipeline(service)

        pipeline.process_records([record_a])
        pipeline.process_records([record_a])
        service.recompute_from_evidence(record_a)

        assert record_a.severity_decision.effective_level == "HIGH"
        assert event_type.severity == "INFO"

    def test_check_anomaly_reads_independent_decision(self):
        """check_anomaly 串联独立判定：HIGH 与 MEDIUM 档位各自筛选并核对数量。"""
        service = SeverityService()
        event_type = make_type("INFO")
        records = [make_record("A1", event_type, "ERROR"),
                   make_record("A2", event_type, "ERROR"),
                   make_record("B1", event_type, "WARN")]
        pipeline = make_enrich_pipeline(service)
        pipeline.process_records(records)
        for r in records:
            d = r.severity_decision
            if d.effective_level in ("HIGH", "MEDIUM") and not d.blocked:
                d.confirmed = True
                d.confirmed_level = d.effective_level
                d.confirmed_by = "op1"

        ingest = IngestPipeline()
        high_matched = ingest.check_anomaly(
            records, "EVEN-T", threshold=1, level="HIGH",
            severity_service=service,
        )
        medium_matched = ingest.check_anomaly(
            records, "EVEN-T", threshold=1, level="MEDIUM",
            severity_service=service,
        )

        assert sorted(r.record_id for r in high_matched) == ["A1", "A2"]
        # MEDIUM 及以上：两条确认 HIGH 的 A 与 MEDIUM 的 B 都是真实候选
        assert sorted(r.record_id for r in medium_matched) == ["A1", "A2", "B1"]
        assert all("anomaly_alert" in r.parsed_fields for r in high_matched)
        # B 不会被错标高警
        assert records[2].parsed_fields["anomaly_alert"] != "triggered:HIGH"
        assert records[2].parsed_fields["anomaly_alert"] == "triggered:MEDIUM"


class TestConflictingSeverityEnhancements:
    """同优先级增强规则给出 HIGH 与 TRACE 冲突的处理。"""

    def test_equal_priority_conflict_blocks_event_and_keeps_evidence(self):
        """冲突不由登记顺序决定：保留两份原字段依据，阻止进入正式高警。"""
        rules = [
            FieldEnrichRule(
                rule_id="FIEL-HIGH", target_field="severity_level",
                enrich_source="level",
                mapping_dict={"ERROR": "HIGH"}, default_value="UNKNOWN",
                priority=10, approved=True,
            ),
            FieldEnrichRule(
                rule_id="FIEL-TRACE", target_field="severity_level",
                enrich_source="trace_source",
                mapping_dict={"X": "TRACE"}, default_value="UNKNOWN",
                priority=10, approved=True,
            ),
        ]
        service = SeverityService()
        event_type = make_type("INFO")
        record = make_record("C", event_type, "ERROR")
        record.parsed_fields["trace_source"] = "X"
        pipeline = make_enrich_pipeline(service, rules)

        pipeline.process_records([record])
        decision = record.severity_decision

        assert decision.blocked is True
        assert decision.effective_level == "INFO"  # 回落到模板默认
        assert len(decision.evidences) == 2
        assert {e.rule_id for e in decision.evidences} == {"FIEL-HIGH", "FIEL-TRACE"}
        # 两份原字段依据都保留
        evidence_map = {e.rule_id: e for e in decision.evidences}
        assert evidence_map["FIEL-HIGH"].source_value == "ERROR"
        assert evidence_map["FIEL-TRACE"].source_value == "X"
        # 冲突说明同时引用两份互斥依据，而不是只保留先登记的一份
        joined_conflicts = "|".join(decision.conflicts)
        assert "FIEL-HIGH" in joined_conflicts and "FIEL-TRACE" in joined_conflicts
        assert "HIGH" in joined_conflicts and "TRACE" in joined_conflicts
        # 被阻止的事件不能进入高警，也不进普通复查
        assert service.select_candidates([record], "HIGH") == []
        assert service.select_candidates([record], "MEDIUM") == []
        # 模板默认值未被修改
        assert event_type.severity == "INFO"

    def test_conflict_resolution_independent_of_registration_order(self):
        """调换规则登记顺序，冲突结论一致，绝不偏向先登记的 HIGH。"""
        rules_a = [
            FieldEnrichRule("R1", "severity_level", "level",
                            {"ERROR": "HIGH"}, priority=10, approved=True),
            FieldEnrichRule("R2", "severity_level", "trace_source",
                            {"X": "TRACE"}, priority=10, approved=True),
        ]
        rules_b = list(reversed(rules_a))

        outcomes = []
        for rules in (rules_a, rules_b):
            service = SeverityService()
            event_type = make_type("INFO")
            record = make_record("C", event_type, "ERROR")
            record.parsed_fields["trace_source"] = "X"
            make_enrich_pipeline(service, rules).process_records([record])
            d = record.severity_decision
            outcomes.append((d.blocked, d.effective_level,
                             sorted(e.rule_id for e in d.evidences)))

        assert outcomes[0] == outcomes[1]
        assert outcomes[0][0] is True
        assert outcomes[0][1] == "INFO"

    def test_uncontested_events_still_computed(self):
        """存在争议事件时，其他无争议事件照常计算，不被连坐。"""
        service = SeverityService()
        event_type = make_type("INFO")
        contested = make_record("C", event_type, "ERROR")
        contested.parsed_fields["trace_source"] = "X"
        normal = make_record("A", event_type, "ERROR")
        rules = [
            FieldEnrichRule("FIEL-HIGH", "severity_level", "level",
                            {"ERROR": "HIGH"}, priority=10, approved=True),
            FieldEnrichRule("FIEL-TRACE", "severity_level", "trace_source",
                            {"X": "TRACE"}, priority=10, approved=True),
        ]
        make_enrich_pipeline(service, rules).process_records([contested, normal])

        assert contested.severity_decision.blocked is True
        assert normal.severity_decision.blocked is False
        assert normal.severity_decision.effective_level == "HIGH"
        assert event_type.severity == "INFO"

    def test_unapproved_rule_produces_evidence_but_not_rating(self):
        """未批准规则保留依据但不参与评级，不能靠登记顺序翻盘。"""
        rules = [
            FieldEnrichRule("R-OK", "severity_level", "level",
                            {"ERROR": "HIGH"}, priority=10, approved=True),
            FieldEnrichRule("R-NEW", "severity_level", "trace_source",
                            {"X": "TRACE"}, priority=10, approved=False),
        ]
        service = SeverityService()
        event_type = make_type("INFO")
        record = make_record("C", event_type, "ERROR")
        record.parsed_fields["trace_source"] = "X"
        make_enrich_pipeline(service, rules).process_records([record])
        d = record.severity_decision

        assert d.blocked is False
        assert d.effective_level == "HIGH"
        assert {e.rule_id for e in d.evidences} == {"R-OK", "R-NEW"}
        assert all(e.approved for e in d.evidences if e.rule_id == "R-OK")


class TestTemplateVersionConflict:
    """B 已领取未确认时管理员调整默认级别，两个允许模板版本冲突。"""

    def test_claimed_unconfirmed_uses_adopted_template_version(self):
        """旧版 INFO 不触发普通复查；完整新版 MEDIUM 时 A、B 两条复查都应发。"""
        service = SeverityService()
        event_type = make_type("INFO", "v1")
        service.register_template("EVEN-T", "v1", "INFO")
        record_a = make_plain_record("A", event_type)
        record_b = make_plain_record("B", event_type)
        pipeline = make_enrich_pipeline(service)
        pipeline.process_records([record_a, record_b])
        # 值班者领取分类，但还没正式确认
        service.claim_review([record_a, record_b], "duty-1")
        assert record_a.review_claimed and record_b.review_claimed

        # 管理员把默认改成 MEDIUM，产生第二个允许使用的模板版本
        service.update_template_default("EVEN-T", "MEDIUM", "v2")
        assert {tv.version for tv in service.allowed_versions("EVEN-T")} == {"v1", "v2"}

        # 采用旧版 v1（INFO）：MEDIUM 复查无候选，不触发
        old_review = service.run_review(
            [record_a, record_b],
            AlertCheck("RULE-MED", "EVEN-T", "MEDIUM", threshold=1),
            "target-old", template_version="v1",
        )
        assert old_review.candidate_ids == []
        assert old_review.alerts == []

        # 采用完整新版 v2（MEDIUM）：A、B 都达到 MEDIUM，候选数 2 > 1，发两条
        new_review = service.run_review(
            [record_a, record_b],
            AlertCheck("RULE-MED", "EVEN-T", "MEDIUM", threshold=1),
            "target-new", template_version="v2",
        )
        assert sorted(new_review.candidate_ids) == ["A", "B"]
        assert len(new_review.alerts) == 2
        assert {a.record_id for a in new_review.alerts} == {"A", "B"}
        # 模板对象本身默认值仍由调用方持有，服务只存版本快照
        assert event_type.severity == "INFO"

    def test_confirmed_rating_frozen_against_correction(self):
        """已确定的 A 评级不受模板更正影响，高警不把 B 算进去。"""
        service = SeverityService()
        event_type = make_type("INFO", "v1")
        service.register_template("EVEN-T", "v1", "INFO")
        record_a = make_record("A", event_type, "ERROR")
        record_b = make_plain_record("B", event_type)
        pipeline = make_enrich_pipeline(service)
        pipeline.process_records([record_a, record_b])

        review = service.run_review(
            [record_a, record_b],
            AlertCheck("RULE-HIGH", "EVEN-T", "HIGH", threshold=0),
            "target-high",
        )
        service.confirm_rating(review.review_id, record_a, "duty-1")
        # A 确认后再跑投递：高警只发 A
        service.run_review  # 状态已在 confirm 内 flush
        assert record_a.severity_decision.confirmed is True
        assert record_a.severity_decision.confirmed_level == "HIGH"

        # 管理员把默认级别改成 HIGH，A 已确认评级冻结；B 无 HIGH 增强且未确认，不进高警
        service.update_template_default("EVEN-T", "HIGH", "v2")
        service.compute_decision(record_b)
        assert record_b.severity_decision.confirmed is False
        assert not record_b.severity_decision.is_high()

        high_now = service.select_candidates([record_a, record_b], "HIGH")
        assert [r.record_id for r in high_now] == ["A"]
        # A 重算后仍是确认时的 HIGH，模板版本证据保留
        service.recompute_from_evidence(record_a, template_version="v2")
        assert record_a.severity_decision.confirmed_level == "HIGH"
        assert record_a.severity_decision.confirmed is True

    def test_concurrent_confirmation_sends_each_review_once(self):
        """并发确认同一实际复查只发一次告警，值班者可凭证据各自重算。"""
        service = SeverityService()
        event_type = make_type("INFO", "v1")
        service.register_template("EVEN-T", "v1", "INFO")
        records = [make_record(f"A{i}", event_type, "ERROR") for i in range(2)]
        make_enrich_pipeline(service).process_records(records)

        review = service.run_review(
            records, AlertCheck("RULE-HIGH", "EVEN-T", "HIGH", threshold=1),
            "target-high",
        )
        # 两位值班者并发确认同一批评级
        for r in records:
            service.confirm_rating(review.review_id, r, "duty-1")
            service.confirm_rating(review.review_id, r, "duty-2")

        assert review.delivered is True
        assert len(review.alerts) == 2  # 每条事件一个告警，确认动作不重复产生
        # 每人都能按真实评级证据重算，结论一致
        for r in records:
            d1 = service.recompute_from_evidence(r)
            d2 = service.recompute_from_evidence(r)
            assert d1.confirmed_level == d2.confirmed_level == "HIGH"
        # 投递去重键保证重跑不重发
        before = len(service._delivered_keys["target-high"])
        service.resume_review(review.review_id)
        assert len(service._delivered_keys["target-high"]) == before


class TestInterruptResumeAndCorrection:
    """送达确认未记下就中断、默认级别随后撤回的恢复语义。"""

    def test_resume_keeps_sent_alerts_and_evidence_after_withdraw(self):
        """恢复后不重发已发告警，也不能拿撤回后的 INFO 否认旧告警存在。"""
        service = SeverityService()
        event_type = make_type("INFO", "v1")
        service.register_template("EVEN-T", "v1", "INFO")
        records = [make_plain_record("A", event_type),
                   make_plain_record("B", event_type)]
        make_enrich_pipeline(service).process_records(records)
        service.update_template_default("EVEN-T", "MEDIUM", "v2")

        review = service.run_review(
            records, AlertCheck("RULE-MED", "EVEN-T", "MEDIUM", threshold=1),
            "target-original", template_version="v2",
        )
        assert len(review.alerts) == 2
        # 评级端还没记下送达确认就中断
        service.mark_interrupted(review.review_id)
        assert review.delivery_ack is False

        # 此时新版默认被撤回
        service.withdraw_template_version("EVEN-T", "v2")
        withdrawn = service.get_template("EVEN-T", "v2")
        assert withdrawn.withdrawn is True

        resumed = service.resume_review(review.review_id)
        # 继续的是原复查，不是新复查
        assert resumed.review_id == review.review_id
        # 已发告警不重发
        sent_keys = list(service._delivered_keys["target-original"])
        assert len(sent_keys) == 2
        service.resume_review(review.review_id)
        assert len(service._delivered_keys["target-original"]) == 2
        # 旧告警仍带 v2 的 MEDIUM 证据，撤回不能抹掉其曾经合法存在
        for alert in resumed.alerts:
            assert alert.template_version == "v2"
            assert alert.level == "MEDIUM"
            assert alert.evidence
        # 撤回后新判定回到 v1 INFO，不再产生 MEDIUM 候选
        fresh = make_plain_record("C", event_type)
        service.compute_decision(fresh)
        assert fresh.severity_decision.effective_level == "INFO"
        assert service.select_candidates([fresh], "MEDIUM") == []

    def test_correction_delivered_to_original_target_and_linked(self):
        """后续纠正须向原目标交付可关联更正，争议事件仍不得混入。"""
        service = SeverityService()
        event_type = make_type("INFO", "v1")
        service.register_template("EVEN-T", "v1", "INFO")
        normal = make_record("A", event_type, "WARN")
        contested = make_record("C", event_type, "ERROR")
        contested.parsed_fields["trace_source"] = "X"
        rules = [
            FieldEnrichRule("FIEL-HIGH", "severity_level", "level",
                            {"ERROR": "HIGH", "WARN": "MEDIUM"},
                            priority=10, approved=True),
            FieldEnrichRule("FIEL-TRACE", "severity_level", "trace_source",
                            {"X": "TRACE"}, priority=10, approved=True),
        ]
        make_enrich_pipeline(service, rules).process_records([normal, contested])
        review = service.run_review(
            [normal, contested],
            AlertCheck("RULE-MED", "EVEN-T", "MEDIUM", threshold=0),
            "target-original",
        )
        assert review.candidate_ids == ["A"]  # 争议事件 C 不在候选内

        correction = service.deliver_correction(
            review.review_id, normal, "HIGH", "复查后升级",
        )
        assert correction is not None
        # 更正关联原复查，且仍交付到原目标
        assert correction.evidence[0]["correction_of"] == review.review_id
        assert review.target == "target-original"
        assert review.status == "已更正"
        # 更正幂等：同级别重复纠正不再发
        again = service.deliver_correction(
            review.review_id, normal, "HIGH", "复查后升级",
        )
        assert again is None
        # 争议事件不允许借更正通道混入
        assert service.deliver_correction(
            review.review_id, contested, "HIGH", "试图混入",
        ) is None


class TestTemplateWritebackFailure:
    """模板被回写报错或产生额外告警都要能复查。"""

    def test_failed_writeback_recorded_and_old_template_holds(self):
        service = SeverityService()
        event_type = make_type("INFO", "v1")
        service.register_template("EVEN-T", "v1", "INFO")
        record = make_plain_record("A", event_type)
        make_enrich_pipeline(service).process_records([record])

        result = service.update_template_default(
            "EVEN-T", "MEDIUM", "v2-broken", fail=True, reason="磁盘只读",
        )
        assert result is None
        errors = service.list_write_errors()
        assert len(errors) == 1
        assert errors[0].attempted_version == "v2-broken"
        assert errors[0].reason == "磁盘只读"
        # 旧模板继续生效，事件按 INFO 判定，不产生额外 MEDIUM 告警
        service.compute_decision(record)
        assert record.severity_decision.effective_level == "INFO"
        review = service.run_review(
            [record], AlertCheck("RULE-MED", "EVEN-T", "MEDIUM", threshold=0),
            "target-x",
        )
        assert review.alerts == []


class TestEndToEndCascade:
    """复现同类事件串级：增强后执行两种筛选，交错改模板默认与确认。"""

    def test_full_cascade_a_and_b_ratings_counts_and_alerts(self):
        service = SeverityService()
        event_type = make_type("INFO", "v1")
        service.register_template("EVEN-T", "v1", "INFO")
        a_events = [make_record(f"A{i}", event_type, "ERROR") for i in range(2)]
        b_events = [make_plain_record(f"B{i}", event_type) for i in range(2)]
        all_records = a_events + b_events
        pipeline = make_enrich_pipeline(service)

        # 1) 实际增强
        pipeline.process_records(all_records)
        assert all(r.severity_decision.effective_level == "HIGH" for r in a_events)
        assert all(r.severity_decision.effective_level == "INFO" for r in b_events)
        assert event_type.severity == "INFO"

        # 2) 高警筛选：确认 A 之后只有 A 候选，数量 2 > 1 → 发两条高警
        high_review = service.run_review(
            all_records, AlertCheck("RULE-HIGH", "EVEN-T", "HIGH", threshold=1),
            "target-high",
        )
        assert sorted(high_review.candidate_ids) == ["A0", "A1"]
        for r in a_events:
            service.confirm_rating(high_review.review_id, r, "duty-1")
        assert len(high_review.alerts) == 2
        assert {a.level for a in high_review.alerts} == {"HIGH"}

        # 3) 交错：管理员把默认改成 MEDIUM（B 未确认，按新版重算）
        service.update_template_default("EVEN-T", "MEDIUM", "v2")
        medium_review = service.run_review(
            all_records, AlertCheck("RULE-MED", "EVEN-T", "MEDIUM", threshold=1),
            "target-medium", template_version="v2",
        )
        # A 已确认 HIGH（>=MEDIUM）且 B 按新版成 MEDIUM：四条候选，数量 > 1
        assert sorted(medium_review.candidate_ids) == ["A0", "A1", "B0", "B1"]
        assert len(medium_review.alerts) == 4

        # 4) A 评级不受影响，高警仍不含 B
        assert all(r.severity_decision.confirmed_level == "HIGH" for r in a_events)
        assert service.select_candidates(all_records, "HIGH") == a_events

        # 5) 撤回 v2 后 B 回落 INFO，但已发复查告警与证据仍可查
        service.withdraw_template_version("EVEN-T", "v2")
        for r in b_events:
            service.compute_decision(r)
        assert all(r.severity_decision.effective_level == "INFO" for r in b_events)
        assert len(medium_review.alerts) == 4
        assert all(a.template_version == "v2" for a in medium_review.alerts
                   if a.record_id.startswith("B"))

    def test_run_severity_review_chain_entry(self):
        """串联入口 run_severity_review：process_records 与 check_anomaly 一条链。"""
        service = SeverityService()
        event_type = make_type("INFO", "v1")
        service.register_template("EVEN-T", "v1", "INFO")
        records = [make_record(f"A{i}", event_type, "ERROR") for i in range(2)]
        pipeline = make_enrich_pipeline(service)
        ingest = IngestPipeline()

        review = ingest.run_severity_review(
            records,
            AlertCheck("RULE-HIGH", "EVEN-T", "HIGH", threshold=1),
            "target-chain",
            severity_service=service,
            mask_enrich_pipeline=pipeline,
        )
        # 先增强出 HIGH 判定，再确认，复核候选与数量口径一致
        for r in records:
            service.confirm_rating(review.review_id, r, "duty-1")
        assert review.candidate_ids == ["A0", "A1"]
        assert len(review.alerts) == 2
        assert event_type.severity == "INFO"


class TestResolvePureFunction:
    """纯判定函数的边界行为。"""

    def test_no_evidence_uses_default(self):
        d = resolve_severity_decision("INFO", "v1", [])
        assert d.effective_level == "INFO"
        assert d.blocked is False

    def test_higher_priority_wins(self):
        evidences = [
            SeverityEvidence("R-LOW", "severity_level", "level", "WARN",
                             "MEDIUM", priority=5),
            SeverityEvidence("R-HIGH", "severity_level", "level", "ERROR",
                             "HIGH", priority=10),
        ]
        d = resolve_severity_decision("INFO", "v1", evidences)
        assert d.effective_level == "HIGH"
        assert d.blocked is False

    def test_trace_vs_high_conflict(self):
        evidences = [
            SeverityEvidence("R-H", "severity_level", "level", "ERROR",
                             "HIGH", priority=10),
            SeverityEvidence("R-T", "severity_level", "trace_source", "X",
                             "TRACE", priority=10),
        ]
        d = resolve_severity_decision("MEDIUM", "v1", evidences)
        assert d.blocked is True
        assert d.effective_level == "MEDIUM"
        assert len(d.conflicts) == 2


# ---------- 运行入口（确定性测试，不依赖 pytest） ----------

if __name__ == "__main__":
    import traceback

    test_classes = [
        TestIndependentSeverityDecision,
        TestConflictingSeverityEnhancements,
        TestTemplateVersionConflict,
        TestInterruptResumeAndCorrection,
        TestTemplateWritebackFailure,
        TestEndToEndCascade,
        TestResolvePureFunction,
    ]

    passed = 0
    failed = 0
    for cls in test_classes:
        for name in sorted(dir(cls)):
            if not name.startswith("test_"):
                continue
            try:
                getattr(cls, name)(cls())
                passed += 1
                print(f"  PASS  test_severity_alert: {name}")
            except Exception:
                failed += 1
                print(f"  FAIL  test_severity_alert: {name}")
                traceback.print_exc()

    print(f"\ntest_severity_alert: {passed} passed, {failed} failed, "
          f"{passed + failed} total")
    sys.exit(1 if failed else 0)
