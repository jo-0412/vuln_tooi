# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

import io
import os

try:
    import yaml
except ImportError as exc:  # pragma: no cover
    yaml = None
    _yaml_import_error = exc
else:
    _yaml_import_error = None

from app.compat import to_text
from app.collectors.permission_scanner import PermissionScanner
from app.models.check_result import CheckResult


class U23Runner(object):
    """
    U-23 SUID, SGID, Sticky bit 설정 파일 점검 실행기
    """

    def __init__(self, check_dir=None):
        self.app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.check_dir = check_dir or os.path.join(
            self.app_dir,
            "checks",
            "u23_special_permission_files"
        )
        self.permission_scanner = PermissionScanner()

        self.metadata = {}
        self.targets = {}
        self.policy = {}
        self.messages = {}

    def run(self):
        try:
            self._load_configs()
        except Exception as exc:
            return self._build_error_result(
                "설정 파일 로딩 실패: {0}".format(to_text(exc))
            )

        raw_steps = self.messages.get("remediation", {}).get("actions", [])
        remediation_steps = self._dedupe_keep_order(raw_steps)

        result = CheckResult(
            code=self.metadata.get("code", "U-23"),
            name=self.metadata.get("name", "SUID, SGID, Sticky bit 설정 파일 점검"),
            severity=self.metadata.get("severity", "high"),
            category=self.metadata.get("category", "file_and_directory_management"),
            status="MANUAL",
            success=True,
            summary=self._get_message("manual", "summary", default="추가 검토가 필요한 특수권한 항목이 존재합니다."),
            detail=self._get_message("manual", "detail", default="특수권한이 설정된 일부 파일 또는 디렉터리에 대해 업무 필요성 및 운영 목적을 추가 확인해야 합니다."),
            requires_root=self.metadata.get("requires_root", "required"),
            remediation_summary=self.messages.get("remediation", {}).get("summary"),
            remediation_steps=remediation_steps
        )

        scan_config = self.targets.get("scan", {})
        roots = scan_config.get("roots", ["/"])
        exclude_paths = scan_config.get("exclude_paths", [])

        scan_result = self.permission_scanner.scan(
            roots=roots,
            exclude_paths=exclude_paths,
            xdev=True,
            root_owned_only=True
        )

        result.raw["scan_result"] = scan_result.to_dict()

        if scan_result.status == "error":
            result.set_status("ERROR", success=False)
            result.summary = self._get_message(
                "error", "summary",
                default="점검 실행 중 오류가 발생했습니다."
            )
            reasons = scan_result.errors or ["파일시스템 스캔을 수행하지 못했습니다."]
            result.detail = self._merge_detail(
                self._get_message(
                    "error", "detail",
                    default="전체 파일시스템 검색 또는 특수권한 항목 수집 중 오류가 발생했습니다."
                ),
                reasons
            )
            for err in scan_result.errors:
                result.add_error(err)
            return result

        allowlists = self.policy.get("rules", {}).get("special_permission_rule", {}).get("allowlists", {})

        allowed_suid = self._normalize_path_set(allowlists.get("suid_files", []))
        allowed_sgid = self._normalize_path_set(allowlists.get("sgid_files", []))
        allowed_sticky = self._normalize_path_set(allowlists.get("sticky_dirs", []))

        suid_files = scan_result.suid_files
        sgid_files = scan_result.sgid_files
        sticky_dirs = scan_result.sticky_dirs

        unexpected_suid = self._filter_unexpected(suid_files, allowed_suid)
        unexpected_sgid = self._filter_unexpected(sgid_files, allowed_sgid)
        unexpected_sticky = self._filter_unexpected(sticky_dirs, allowed_sticky)

        review_required_items = []
        review_required_items.extend(unexpected_suid)
        review_required_items.extend(unexpected_sgid)
        review_required_items.extend(unexpected_sticky)

        result.add_evidence(
            key="suid_files",
            label=self._label("suid_files"),
            source="filesystem",
            value=[item.to_dict() for item in suid_files],
            status="ok" if suid_files else "info",
            notes="count={0}".format(len(suid_files))
        )

        result.add_evidence(
            key="sgid_files",
            label=self._label("sgid_files"),
            source="filesystem",
            value=[item.to_dict() for item in sgid_files],
            status="ok" if sgid_files else "info",
            notes="count={0}".format(len(sgid_files))
        )

        result.add_evidence(
            key="sticky_dirs",
            label=self._label("sticky_dirs"),
            source="filesystem",
            value=[item.to_dict() for item in sticky_dirs],
            status="ok" if sticky_dirs else "info",
            notes="count={0}".format(len(sticky_dirs))
        )

        result.add_evidence(
            key="unexpected_suid_files",
            label=self._label("unexpected_suid_files"),
            source="filesystem",
            value=[item.to_dict() for item in unexpected_suid],
            status="fail" if unexpected_suid else "ok"
        )

        result.add_evidence(
            key="unexpected_sgid_files",
            label=self._label("unexpected_sgid_files"),
            source="filesystem",
            value=[item.to_dict() for item in unexpected_sgid],
            status="fail" if unexpected_sgid else "ok"
        )

        result.add_evidence(
            key="unexpected_sticky_dirs",
            label=self._label("unexpected_sticky_dirs"),
            source="filesystem",
            value=[item.to_dict() for item in unexpected_sticky],
            status="manual" if unexpected_sticky else "ok"
        )

        result.add_evidence(
            key="special_permission_count",
            label=self._label("special_permission_count"),
            source="filesystem",
            value={
                "suid_count": len(suid_files),
                "sgid_count": len(sgid_files),
                "sticky_dir_count": len(sticky_dirs),
                "unexpected_suid_count": len(unexpected_suid),
                "unexpected_sgid_count": len(unexpected_sgid),
                "unexpected_sticky_count": len(unexpected_sticky),
            },
            status="info"
        )

        result.add_evidence(
            key="review_required_items",
            label=self._label("review_required_items"),
            source="filesystem",
            value=[item.to_dict() for item in review_required_items],
            status="manual" if review_required_items else "ok"
        )

        reasons = []

        if unexpected_suid:
            reasons.append(
                "허용 목록 외 SUID 파일이 존재합니다: {0}".format(
                    ", ".join(self._extract_paths(unexpected_suid, limit=10))
                )
            )

        if unexpected_sgid:
            reasons.append(
                "허용 목록 외 SGID 파일이 존재합니다: {0}".format(
                    ", ".join(self._extract_paths(unexpected_sgid, limit=10))
                )
            )

        if unexpected_sticky:
            reasons.append(
                "허용 목록 외 Sticky bit 디렉터리가 존재합니다: {0}".format(
                    ", ".join(self._extract_paths(unexpected_sticky, limit=10))
                )
            )

        if scan_result.warnings:
            for warning in scan_result.warnings[:5]:
                reasons.append("스캔 경고: {0}".format(to_text(warning)))

        comparison_rules = self.policy.get("rules", {}).get("special_permission_rule", {}).get("comparison_rules", {})
        suid_fail = bool(comparison_rules.get("unexpected_suid_files_fail", True))
        sgid_fail = bool(comparison_rules.get("unexpected_sgid_files_fail", True))
        sticky_manual = bool(comparison_rules.get("unexpected_sticky_dirs_manual", True))

        fail_triggered = False
        manual_triggered = False

        if unexpected_suid and suid_fail:
            fail_triggered = True

        if unexpected_sgid and sgid_fail:
            fail_triggered = True

        if unexpected_sticky and sticky_manual:
            manual_triggered = True

        if scan_result.status == "partial":
            manual_triggered = True

        if fail_triggered:
            result.set_status("FAIL", success=False)
            result.summary = self._get_message(
                "fail", "summary",
                default="불필요한 SUID/SGID 특수권한 파일이 존재합니다."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "fail", "detail",
                    default="불필요한 SUID/SGID 파일이 존재해 일반 사용자가 해당 파일을 통해 root 권한 상승을 시도할 수 있습니다."
                ),
                reasons
            )
            return result

        if manual_triggered:
            result.set_status("MANUAL", success=True)
            result.summary = self._get_message(
                "manual", "summary",
                default="추가 검토가 필요한 특수권한 항목이 존재합니다."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "manual", "detail",
                    default="특수권한이 설정된 일부 파일 또는 디렉터리에 대해 업무 필요성 및 운영 목적을 추가 확인해야 합니다."
                ),
                reasons
            )
            return result

        result.set_status("PASS", success=True)
        result.summary = self._get_message(
            "pass", "summary",
            default="불필요한 SUID/SGID 특수권한 파일이 존재하지 않습니다."
        )
        result.detail = self._merge_detail(
            self._get_message(
                "pass", "detail",
                default="허용되지 않은 특수권한 파일이 확인되지 않아 일반 사용자에 의한 권한 상승 위험이 낮습니다."
            ),
            [
                "허용 목록 외 SUID 파일이 없습니다.",
                "허용 목록 외 SGID 파일이 없습니다.",
            ]
        )
        return result

    @staticmethod
    def _normalize_path_set(paths):
        normalized = set()
        for path in paths:
            normalized.add(os.path.abspath(to_text(path).strip()))
        return normalized

    @staticmethod
    def _filter_unexpected(items, allowed_paths):
        unexpected = []
        for item in items:
            normalized = os.path.abspath(to_text(item.path))
            if normalized not in allowed_paths:
                unexpected.append(item)
        return unexpected

    @staticmethod
    def _extract_paths(items, limit=None):
        paths = []
        count = 0
        for item in items:
            paths.append(to_text(item.path))
            count += 1
            if limit is not None and count >= limit:
                break
        return paths

    def _load_configs(self):
        if yaml is None:
            raise RuntimeError(
                "PyYAML이 필요합니다. 설치 후 다시 실행하세요. 원인: {0}".format(
                    to_text(_yaml_import_error)
                )
            )

        self.metadata = self._load_yaml(os.path.join(self.check_dir, "metadata.yaml"))
        self.targets = self._load_yaml(os.path.join(self.check_dir, "targets.yaml"))
        self.policy = self._load_yaml(os.path.join(self.check_dir, "policy.yaml"))
        self.messages = self._load_yaml(os.path.join(self.check_dir, "messages.yaml"))

    @staticmethod
    def _load_yaml(path):
        if not os.path.exists(path):
            raise IOError("설정 파일을 찾을 수 없습니다: {0}".format(path))

        with io.open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        if not isinstance(data, dict):
            raise ValueError("YAML 최상위 구조는 dict 여야 합니다: {0}".format(path))

        return data

    def _get_message(self, section, field, default=""):
        value = self.messages.get(section, {}).get(field, default)
        return to_text(value)

    def _label(self, key):
        value = self.messages.get("evidence_labels", {}).get(key, key)
        return to_text(value)

    @staticmethod
    def _dedupe_keep_order(items):
        seen = set()
        result = []

        for item in items:
            if item is None:
                continue
            normalized = to_text(item).strip()
            if not normalized:
                continue
            if normalized not in seen:
                seen.add(normalized)
                result.append(normalized)

        return result

    @staticmethod
    def _merge_detail(base_detail, reasons):
        filtered = []
        for reason in reasons:
            normalized = to_text(reason).strip()
            if normalized:
                filtered.append(normalized)

        if not filtered:
            return to_text(base_detail).strip()

        merged = [to_text(base_detail).strip(), "", "판정 근거:"]
        for reason in filtered:
            merged.append("- {0}".format(reason))
        return "\n".join(merged)

    def _build_error_result(self, message):
        result = CheckResult(
            code="U-23",
            name="SUID, SGID, Sticky bit 설정 파일 점검",
            severity="high",
            category="file_and_directory_management",
            status="ERROR",
            success=False,
            summary="점검 실행 중 오류가 발생했습니다.",
            detail=to_text(message),
            requires_root="required"
        )
        result.add_error(to_text(message))
        return result