"""拾音工坊独立级别判定与告警复查服务。

修复要点：
- 级别增强只生成单事件的 SeverityDecision，绝不回写 EventTypeDef 模板默认值；
- 同优先级增强规则给出互斥级别时保留全部原字段依据，阻止争议事件进入正式高警；
- 告警筛选读取独立判定数据：高警只认真实 HIGH，普通复查取 MEDIUM 及以上，各自核对候选数；
- 模板默认值调整以版本快照管理，未确认评级按采用的模板版本重算，已确认评级冻结；
- 复查领取/确认/送达/更正全链路幂等，中断恢复不重发、不否认已发告警，更正须关联原复查。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.core.models import (
    EventRecord, SeverityDecision, SeverityEvidence,
)


# ---------- 纯函数：独立级别判定 ----------

def resolve_severity_decision(
    default_level: str,
    template_version: str,
    evidences: list[SeverityEvidence],
) -> SeverityDecision:
    """按已批准增强规则的优先级计算单事件级别，不触碰任何模板对象。

    规则：
    1. 只有 approved 的级别增强依据参与判定；
    2. 取最高优先级依据；同优先级一致给出同一级别时采用该级别（rule_id 仅作稳定排序）；
    3. 同优先级给出互斥级别（如 HIGH 与 TRACE）属于争议：保留全部原字段依据，
       不允许由登记顺序决定，事件回落到模板默认级别并标记 blocked，禁止进入正式高警；
    4. 没有有效增强依据时采用模板默认级别。
    """
    approved = [e for e in evidences if e.approved]
    conflicts: list[str] = []
    effective = (default_level or "INFO").upper()
    blocked = False

    if approved:
        top_priority = max(e.priority for e in approved)
        top = [e for e in approved if e.priority == top_priority]
        levels = {e.severity.upper() for e in top}
        if len(levels) > 1:
            blocked = True
            conflicts = [
                f"{e.rule_id}:{e.source_field}={e.source_value}->{e.severity.upper()}"
                for e in sorted(top, key=lambda e: e.rule_id)
            ]
        else:
            winner = sorted(top, key=lambda e: e.rule_id)[0]
            effective = winner.severity.upper()

    return SeverityDecision(
        default_level=effective if blocked else (default_level or "INFO").upper(),
        effective_level=effective,
        template_version=template_version,
        evidences=list(evidences),
        conflicts=conflicts,
        blocked=blocked,
    )

# ---------- 模板版本与复查运行时状态 ----------

@dataclass
class TemplateVersion:
    """事件类型模板的一个版本快照（默认级别随版本冻结）。"""
    type_id: str
    version: str
    default_level: str
    allowed: bool = True          # 允许使用：过渡期内新旧版本可同时允许
    withdrawn: bool = False       # 被撤回：不再用于新判定，但历史告警证据仍有效


@dataclass
class TemplateWriteError:
    """模板回写失败记录——失败本身也要能复查。"""
    type_id: str
    attempted_version: str
    attempted_level: str
    reason: str
    occurred_at: datetime = field(default_factory=datetime.now)


@dataclass
class AlertCheck:
    """一次告警筛选规则：级别档位 + 候选数阈值（候选数 > threshold 才发）。"""
    rule_id: str
    event_type_id: str
    level: str           # "HIGH"（高警）或 "MEDIUM"（普通复查）
    threshold: int = 1


@dataclass
class AlertEvent:
    """实际发出的告警事件数据——含评级证据快照，模板撤回后仍可证明其曾合法发出。"""
    record_id: str
    event_type_id: str
    rule_id: str
    level: str
    template_version: str
    evidence: list[dict[str, Any]]
    sent_at: datetime = field(default_factory=datetime.now)


@dataclass
class ReviewState:
    """一次实际复查的运行时状态（同一复查并发确认只发一次告警）。"""
    review_id: str
    target: str
    rule_id: str
    event_type_id: str
    level: str
    candidate_ids: list[str]
    alerts: list[AlertEvent] = field(default_factory=list)
    status: str = "进行中"        # 进行中/已领取/已送达/中断/已更正
    claimed_by: set[str] = field(default_factory=set)
    confirmed_by: set[str] = field(default_factory=set)
    delivered: bool = False
    delivery_ack: bool = False
    corrections: list[AlertEvent] = field(default_factory=list)
    # 候选事件引用：HIGH 告警只有在事件正式确认后才允许投递
    records: dict[str, EventRecord] = field(default_factory=dict)
    # 候选数阈值（候选数 > threshold 才报警）
    threshold: int = 1


class SeverityService:
    """独立级别判定 + 模板版本 + 告警复查的编排服务。"""

    def __init__(self) -> None:
        # type_id -> {version: TemplateVersion}
        self._templates: dict[str, dict[str, TemplateVersion]] = {}
        self._active_version: dict[str, str] = {}
        self._reviews: dict[str, ReviewState] = {}
        self._write_errors: list[TemplateWriteError] = []
        # target -> 已投递告警去重键，保证不重发
        self._delivered_keys: dict[str, set[str]] = {}
        self._review_seq = 0

    # ---------- 模板版本管理 ----------

    def register_template(self, type_id: str, version: str,
                          default_level: str, *, active: bool = True) -> TemplateVersion:
        """登记一个模板版本；默认从 EventTypeDef 快照初始化，不持有模板对象引用。"""
        tv = TemplateVersion(
            type_id=type_id, version=version,
            default_level=default_level.upper(), allowed=True,
        )
        self._templates.setdefault(type_id, {})[version] = tv
        if active or type_id not in self._active_version:
            self._active_version[type_id] = version
        return tv

    def active_template(self, type_id: str) -> TemplateVersion | None:
        version = self._active_version.get(type_id)
        if version is None:
            return None
        return self._templates.get(type_id, {}).get(version)

    def get_template(self, type_id: str, version: str) -> TemplateVersion | None:
        return self._templates.get(type_id, {}).get(version)

    def allowed_versions(self, type_id: str) -> list[TemplateVersion]:
        """两个允许使用的模板版本（如默认值调整的新旧版）可同时存在并冲突。"""
        return [
            tv for tv in self._templates.get(type_id, {}).values()
            if tv.allowed and not tv.withdrawn
        ]

    def update_template_default(self, type_id: str, new_level: str,
                                new_version: str, *, fail: bool = False,
                                reason: str = "模板回写失败") -> TemplateVersion | None:
        """管理员调整模板默认级别：升版而非改旧版；回写报错时记录并保留旧版生效。

        失败必须可复查（list_write_errors），且不会静默改动任何在途判定。
        """
        if fail:
            self._write_errors.append(TemplateWriteError(
                type_id=type_id, attempted_version=new_version,
                attempted_level=new_level.upper(), reason=reason,
            ))
            return None
        tv = self.register_template(type_id, new_version, new_level, active=True)
        # 旧版本保留为“允许使用”，形成两个可采用模板版本的冲突窗口
        return tv

    def withdraw_template_version(self, type_id: str, version: str) -> None:
        """撤回某模板版本：只影响之后的新判定，已发告警及其证据快照不受影响。"""
        tv = self.get_template(type_id, version)
        if tv is not None:
            tv.withdrawn = True
            tv.allowed = False
        if self._active_version.get(type_id) == version:
            remaining = self.allowed_versions(type_id)
            self._active_version[type_id] = remaining[0].version if remaining else version

    def list_write_errors(self) -> list[TemplateWriteError]:
        return list(self._write_errors)

    # ---------- 单事件级别计算（幂等、可重算） ----------

    def compute_decision(self, record: EventRecord,
                         evidences: list[SeverityEvidence] | None = None,
                         *, template_version: str | None = None) -> SeverityDecision:
        """为单条事件生成/重算独立级别判定。

        - 已正式确认的评级冻结，重复核验与模板更正都不改它；
        - 未确认评级按当前采用的模板版本（或指定版本）的默认级别重算；
        - 全程只读 EventTypeDef 的默认值做快照，绝不回写模板。
        """
        existing = record.severity_decision
        if existing is not None and existing.confirmed:
            return existing

        type_id = record.event_type.type_id
        tv = self._select_template(type_id, template_version)
        default_level = tv.default_level if tv else record.event_type.severity
        version = tv.version if tv else record.event_type.template_version

        if evidences is None:
            evidences = list(existing.evidences) if existing is not None else []

        decision = resolve_severity_decision(default_level, version, evidences)
        if existing is not None:
            # 保留领取/确认痕迹；未确认状态下采用新模板结果
            decision.confirmed = existing.confirmed
            decision.confirmed_by = existing.confirmed_by
            decision.confirmed_level = existing.confirmed_level
        record.severity_decision = decision
        return decision

    def recompute_from_evidence(self, record: EventRecord,
                                *, template_version: str | None = None) -> SeverityDecision:
        """值班者按真实评级证据重算（证据来自事件自身留存，不依赖登记顺序）。"""
        evidences = (
            list(record.severity_decision.evidences)
            if record.severity_decision is not None else []
        )
        return self.compute_decision(record, evidences, template_version=template_version)

    def _select_template(self, type_id: str, version: str | None) -> TemplateVersion | None:
        if version is not None:
            tv = self.get_template(type_id, version)
            if tv is not None and tv.allowed and not tv.withdrawn:
                return tv
        active = self.active_template(type_id)
        if active is not None:
            return active
        allowed = self.allowed_versions(type_id)
        return allowed[0] if allowed else None

    # ---------- 候选筛选（供 check_anomaly 串联） ----------

    @staticmethod
    def select_candidates(records: list[EventRecord], level: str) -> list[EventRecord]:
        """告警筛选只读取独立级别判定数据，按档位选真实候选。

        HIGH 档位要求事件已正式确认 HIGH（未确认评级不得进入正式高警）；
        MEDIUM 档位取当前评级 MEDIUM 及以上（含已确认/未确认的普通复查）。
        争议事件在任何档位都被排除。
        """
        level = level.upper()
        if level == "HIGH":
            return [r for r in records if r.severity_decision is not None
                    and r.severity_decision.is_high()]
        if level == "MEDIUM":
            return [r for r in records if r.severity_decision is not None
                    and r.severity_decision.is_medium_or_above()]
        raise ValueError(f"不支持的告警级别档位: {level}")

    @staticmethod
    def eligible_candidates(records: list[EventRecord], level: str) -> list[EventRecord]:
        """按证据档位选合格候选（不要求确认），用于复查领取与候选数核对。

        与 select_candidates 的区别：HIGH 合格但尚未确认的事件在此可见，
        供值班者领取确认；只有确认之后才会被 select_candidates 选为正式高警。
        """
        level = level.upper()
        if level == "HIGH":
            return [
                r for r in records
                if r.severity_decision is not None
                and not r.severity_decision.blocked
                and (r.severity_decision.confirmed_level
                     if r.severity_decision.confirmed
                     else r.severity_decision.effective_level) == "HIGH"
            ]
        if level == "MEDIUM":
            return [r for r in records if r.severity_decision is not None
                    and r.severity_decision.is_medium_or_above()]
        raise ValueError(f"不支持的告警级别档位: {level}")

    # ---------- 复查领取、确认与告警投递 ----------

    def claim_review(self, records: list[EventRecord], operator: str) -> None:
        """值班者领取分类：领取但未正式确认期间，模板默认值变更按版本优先级处理。"""
        for record in records:
            record.review_claimed = True
            record.review_claimed_by = operator

    def confirm_rating(self, review_id: str, record: EventRecord,
                       operator: str) -> ReviewState:
        """正式确认单事件评级；同一复查的并发确认幂等，告警实际只发一次。"""
        review = self._reviews[review_id]
        decision = record.severity_decision
        if decision is None:
            raise ValueError(f"事件 {record.record_id} 尚无独立级别判定，无法确认")
        if decision.blocked:
            raise ValueError(f"事件 {record.record_id} 级别依据存在争议，禁止确认进入正式告警")
        if not decision.confirmed:
            decision.confirmed = True
            decision.confirmed_by = operator
            decision.confirmed_level = decision.effective_level
        review.confirmed_by.add(operator)
        review.claimed_by.add(operator)
        # HIGH 复查：确认后该事件才成为正式高警候选；数量满足时补投递（幂等）
        if review.level == "HIGH" and record.record_id in review.candidate_ids:
            already = {a.record_id for a in review.alerts}
            if (record.record_id not in already
                    and len(review.candidate_ids) > review.threshold):
                self._enqueue_alert(review, record)
        self._flush_delivery(review)
        return review

    def run_review(
        self,
        records: list[EventRecord],
        check: AlertCheck,
        target: str,
        *,
        template_version: str | None = None,
    ) -> ReviewState:
        """执行一次告警筛选并串联复查：先按采用模板重算未确认评级，再选真实候选、核对数量。

        候选数 > check.threshold 才形成告警；同一 review_id 重复执行不重发。
        HIGH 档位的候选先按证据选出（含待确认），正式告警只投递已确认部分，
        待确认事件在 confirm_rating 后补投递；MEDIUM 档位合格即投递。
        """
        self._review_seq += 1
        review_id = f"REVI-{check.rule_id}-{self._review_seq:04d}"

        typed = [r for r in records if r.event_type.type_id == check.event_type_id]
        for record in typed:
            if record.severity_decision is None or not record.severity_decision.confirmed:
                self.compute_decision(record, template_version=template_version)

        # 候选名单按证据档位选取（HIGH 含待确认事件），数量核对以真实候选为准
        eligible = self.eligible_candidates(typed, check.level)
        review = ReviewState(
            review_id=review_id, target=target, rule_id=check.rule_id,
            event_type_id=check.event_type_id, level=check.level.upper(),
            candidate_ids=[r.record_id for r in eligible],
            records={r.record_id: r for r in eligible},
            threshold=check.threshold,
        )
        self._reviews[review_id] = review

        if len(eligible) > check.threshold:
            if check.level.upper() == "HIGH":
                # 正式高警只发已确认 HIGH；其余待值班确认后补入
                for record in self.select_candidates(eligible, "HIGH"):
                    self._enqueue_alert(review, record)
            else:
                for record in eligible:
                    self._enqueue_alert(review, record)
            self._flush_delivery(review)
        return review

    def _enqueue_alert(self, review: ReviewState, record: EventRecord) -> None:
        decision = record.severity_decision
        level = decision.confirmed_level if decision.confirmed else decision.effective_level
        evidence = [
            {
                "rule_id": e.rule_id,
                "source_field": e.source_field,
                "source_value": e.source_value,
                "severity": e.severity,
                "priority": e.priority,
                "approved": e.approved,
            }
            for e in decision.evidences if e.approved
        ]
        if not evidence:
            # 无级别增强命中时，评级来自采用模板的默认级别——仍留存可复查依据，
            # 模板撤回后该快照可证明告警当时合法发出。
            evidence = [{
                "rule_id": "TEMPLATE-DEFAULT",
                "source_field": "event_type.severity",
                "source_value": decision.default_level,
                "severity": decision.default_level,
                "priority": 0,
                "approved": True,
            }]
        review.alerts.append(AlertEvent(
            record_id=record.record_id,
            event_type_id=record.event_type.type_id,
            rule_id=review.rule_id,
            level=level,
            template_version=decision.template_version,
            evidence=evidence,
        ))

    def _flush_delivery(self, review: ReviewState) -> None:
        """幂等投递：并发确认/重复执行下，同一实际复查的告警只发一次。

        尚无任何告警入队时（如 HIGH 复查等待确认）不标记已送达，
        中断恢复后仍可继续原复查并补投递。
        """
        if review.delivered or not review.alerts:
            return
        sent = self._delivered_keys.setdefault(review.target, set())
        for alert in review.alerts:
            key = f"{review.review_id}|{alert.rule_id}|{alert.record_id}"
            if key in sent:
                continue
            sent.add(key)
        review.delivered = True
        review.status = "已送达"

    def acknowledge_delivery(self, review_id: str) -> ReviewState:
        """评级端记下送达确认；未确认前中断则靠 resume_review 续办。"""
        review = self._reviews[review_id]
        if review.delivered:
            review.delivery_ack = True
        return review

    def resume_review(self, review_id: str) -> ReviewState:
        """中断恢复：继续原复查——不重发已发告警，也不允许用撤回后的模板否认旧告警。"""
        review = self._reviews[review_id]
        if review.status == "中断":
            review.status = "已送达" if review.delivered else "进行中"
        # 仅补投递此前未发出的告警；已投递键保证不重发
        self._flush_delivery(review)
        return review

    def mark_interrupted(self, review_id: str) -> ReviewState:
        review = self._reviews[review_id]
        review.status = "中断"
        return review

    def deliver_correction(self, review_id: str, record: EventRecord,
                           new_level: str, reason: str) -> AlertEvent | None:
        """后续纠正：向原目标交付可关联原复查的更正；争议事件仍不得混入。"""
        review = self._reviews[review_id]
        decision = record.severity_decision
        if decision is not None and decision.blocked:
            return None
        correction = AlertEvent(
            record_id=record.record_id,
            event_type_id=record.event_type.type_id,
            rule_id=review.rule_id,
            level=new_level.upper(),
            template_version=decision.template_version if decision else "",
            evidence=[{
                "correction_of": review.review_id,
                "reason": reason,
                "original_level": (
                    decision.confirmed_level if decision and decision.confirmed
                    else (decision.effective_level if decision else "")
                ),
            }],
        )
        key = f"CORR|{review.review_id}|{record.record_id}|{new_level.upper()}"
        sent = self._delivered_keys.setdefault(review.target, set())
        if key in sent:
            return None
        sent.add(key)
        review.corrections.append(correction)
        review.status = "已更正"
        return correction

    def get_review(self, review_id: str) -> ReviewState | None:
        return self._reviews.get(review_id)

    def list_reviews(self) -> list[ReviewState]:
        return list(self._reviews.values())
