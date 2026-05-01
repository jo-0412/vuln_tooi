# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

import io
import os

try:
    import yaml
except ImportError as exc:
    yaml = None
    _yaml_import_error = exc
else:
    _yaml_import_error = None

from app.compat import to_text
from app.collectors.world_writable_scanner import WorldWritableScanner
from app.models.check_result import CheckResult


class U25Runner(object):
    """
    U-25 world writable 파일 점검 실행기

    주석/설명: 한국어
    사용자 출력: 영어
    Python 2.7 ~ 3.x 호환

    기능:
    - targets.yaml의 scan roots/exclude_paths를 읽음
    - world_writable_scanner.py로 전체 파일시스템 검사
    - allowlist를 제외한 world writable 파일이 있으면 FAIL
    - 없으면 PASS
    - 일부 경로 접근 실패가 있으면 evidence notes에 기록
    """

    def __init__(self, check_dir=None):
        self.app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.check_dir = check_dir or os.path.join(
            self.app_dir,
            "checks",
            "u25_world_writable_files"
        )

        self.scanner = WorldWritableScanner()

        self.metadata = {}
        self.targets = {}
        self.policy = {}
        self.messages = {}

    def run(self):
        try:
            self._load_configs()
        except Exception as exc:
            return self._build_error_result(
                "Configuration loading failed: {0}".format(to_text(exc))
            )

        result = CheckResult(
            code=self.metadata.get("code", "U-25"),
            name=self.metadata.get("name", "Check World Writable Files"),
            severity=self.metadata.get("severity", "high"),
            category=self.metadata.get("category", "file_system"),
            status="MANUAL",
            success=True,
            summary=self._get_message(
                "manual",
                "summary",
                default="World writable files require manual verification."
            ),
            detail=self._get_message(
                "manual",
                "detail",
                default="Some files may be intentionally world writable, but require verification."
            ),
            requires_root=self.metadata.get("requires_root", "required"),
            remediation_summary=self._get_remediation_summary(),
            remediation_steps=self._get_remediation_steps()
        )

        scan_config = self.targets.get("scan", {})
        roots = scan_config.get("roots", ["/"])
        exclude_paths = scan_config.get("exclude_paths", [])

        policy_rule = self.policy.get("rules", {}).get("world_writable_rule", {})
        allowlist_files = self._normalize_paths(
            policy_rule.get("allowlist_files", [])
        )
        allowlist_dirs = self._normalize_paths(
            policy_rule.get("allowlist_dirs", [])
        )

        scan_result = self.scanner.scan(
            roots=roots,
            exclude_paths=exclude_paths,
            xdev=True
        )

        result.raw["scan_result"] = scan_result.to_dict()
        result.raw["allowlist_files"] = allowlist_files
        result.raw["allowlist_dirs"] = allowlist_dirs

        if scan_result.status == "error":
            result.set_status("ERROR", success=False)
            result.summary = self._get_message(
                "error",
                "summary",
                default="An error occurred during filesystem scan."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "error",
                    "detail",
                    default="The scan could not be completed successfully."
                ),
                scan_result.errors or ["Filesystem scan failed."]
            )

            for error in scan_result.errors:
                result.add_error(error)

            return result

        all_files = scan_result.world_writable_files
        unexpected_files = self._filter_unexpected(
            all_files,
            allowlist_files,
            allowlist_dirs
        )

        result.add_evidence(
            key="world_writable_files",
            label=self._label("world_writable_files", "World writable file list"),
            source="filesystem",
            value=[item.to_dict() for item in all_files],
            status="fail" if unexpected_files else "ok",
            notes="total={0}, unexpected={1}".format(
                len(all_files),
                len(unexpected_files)
            )
        )

        result.add_evidence(
            key="world_writable_count",
            label=self._label("world_writable_count", "Total world writable file count"),
            source="filesystem",
            value={
                "total": len(all_files),
                "unexpected": len(unexpected_files),
                "allowed": len(all_files) - len(unexpected_files),
            },
            status="fail" if unexpected_files else "ok"
        )

        result.add_evidence(
            key="excluded_paths",
            label=self._label("excluded_paths", "Excluded scan paths"),
            source="policy",
            value=scan_result.exclude_paths,
            status="info"
        )

        result.add_evidence(
            key="scan_warnings",
            label=self._label("scan_warnings", "Scan warnings"),
            source="filesystem",
            value=scan_result.warnings if scan_result.warnings else ["(none)"],
            status="manual" if scan_result.warnings else "ok"
        )

        result.add_evidence(
            key="review_required_items",
            label=self._label("review_required_items", "Review required items"),
            source="filesystem",
            value=[item.to_dict() for item in unexpected_files],
            status="fail" if unexpected_files else "ok"
        )

        reasons = []

        if unexpected_files:
            reasons.append(
                "World writable files were detected outside the allowlist."
            )
            reasons.append(
                "Detected unexpected world writable file count: {0}".format(
                    len(unexpected_files)
                )
            )

            preview_paths = self._extract_paths(unexpected_files, limit=10)
            if preview_paths:
                reasons.append(
                    "Examples: {0}".format(", ".join(preview_paths))
                )

            result.set_status("FAIL", success=False)
            result.summary = self._get_message(
                "fail",
                "summary",
                default="World writable files were detected."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "fail",
                    "detail",
                    default="Files with write permission for all users may allow unauthorized modification, deletion, or insertion of malicious code."
                ),
                reasons
            )
            return result

        if scan_result.status == "partial":
            reasons.append(
                "No unexpected world writable files were detected, but the scan completed with warnings."
            )

            result.set_status("MANUAL", success=True)
            result.summary = self._get_message(
                "manual",
                "summary",
                default="World writable files require manual verification."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "manual",
                    "detail",
                    default="Some scan paths could not be fully verified."
                ),
                reasons + scan_result.warnings[:5]
            )
            return result

        result.set_status("PASS", success=True)
        result.summary = self._get_message(
            "pass",
            "summary",
            default="No world writable files detected."
        )
        result.detail = self._merge_detail(
            self._get_message(
                "pass",
                "detail",
                default="No files were found with write permissions for all users."
            ),
            ["No world writable files were detected outside the allowlist."]
        )
        return result

    @staticmethod
    def _filter_unexpected(items, allowlist_files, allowlist_dirs):
        unexpected = []

        for item in items:
            path = os.path.abspath(to_text(item.path))

            if path in allowlist_files:
                continue

            if U25Runner._is_under_allowlist_dir(path, allowlist_dirs):
                continue

            unexpected.append(item)

        return unexpected

    @staticmethod
    def _is_under_allowlist_dir(path, allowlist_dirs):
        for directory in allowlist_dirs:
            if path == directory:
                return True

            if path.startswith(directory + os.sep):
                return True

        return False

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

    @staticmethod
    def _normalize_paths(paths):
        result = []
        seen = set()

        for path in paths or []:
            normalized = os.path.abspath(to_text(path).strip())

            if not normalized:
                continue

            if normalized not in seen:
                seen.add(normalized)
                result.append(normalized)

        return result

    def _load_configs(self):
        if yaml is None:
            raise RuntimeError(
                "PyYAML is required. Please install it first. Cause: {0}".format(
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
            raise IOError("Configuration file not found: {0}".format(path))

        with io.open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        if not isinstance(data, dict):
            raise ValueError("YAML root must be a dict: {0}".format(path))

        return data

    def _get_message(self, status, field, default=""):
        direct = self.messages.get(status, {})

        if isinstance(direct, dict) and field in direct:
            return to_text(direct.get(field, default))

        reverse = self.messages.get(field, {})

        if isinstance(reverse, dict) and status in reverse:
            return to_text(reverse.get(status, default))

        return to_text(default)

    def _get_remediation_summary(self):
        remediation = self.messages.get("remediation", {})

        if isinstance(remediation, dict):
            return to_text(
                remediation.get(
                    "summary",
                    "Remove unnecessary world writable permissions."
                )
            )

        return "Remove unnecessary world writable permissions."

    def _get_remediation_steps(self):
        remediation = self.messages.get("remediation", {})

        if isinstance(remediation, dict):
            steps = remediation.get("steps", remediation.get("actions", []))
            return self._dedupe_keep_order(steps)

        return []

    def _label(self, key, default):
        labels = self.messages.get("evidence_labels", {})

        if isinstance(labels, dict):
            return to_text(labels.get(key, default))

        return to_text(default)

    @staticmethod
    def _dedupe_keep_order(items):
        seen = set()
        result = []

        for item in items or []:
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

        for reason in reasons or []:
            normalized = to_text(reason).strip()

            if normalized:
                filtered.append(normalized)

        if not filtered:
            return to_text(base_detail).strip()

        merged = [to_text(base_detail).strip(), "", "Decision reasons:"]

        for reason in filtered:
            merged.append("- {0}".format(reason))

        return "\n".join(merged)

    def _build_error_result(self, message):
        result = CheckResult(
            code="U-25",
            name="Check World Writable Files",
            severity="high",
            category="file_system",
            status="ERROR",
            success=False,
            summary="An error occurred during filesystem scan.",
            detail=to_text(message),
            requires_root="required"
        )
        result.add_error(to_text(message))
        return result