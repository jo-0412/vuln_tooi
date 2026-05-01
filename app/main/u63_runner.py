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
from app.collectors.account_policy_reader import AccountPolicyReader
from app.models.check_result import CheckResult


class U63Runner(object):
    """
    U-63 sudo 명령어 접근 관리 점검 실행기

    주석/설명: 한국어
    사용자 출력: 영어
    Python 2.7 ~ 3.x 호환

    기능:
    - /etc/sudoers 존재 여부 확인
    - /etc/sudoers 소유자 root 여부 확인
    - /etc/sudoers 권한이 0640 이하인지 확인
    - sudoers include 구조 수집
    - /etc/sudoers.d 디렉터리 메타데이터 수집
    - /etc/sudoers.d 파일 목록 수집

    차별점:
    - 이번 1차 구현은 sudo 정책 내용 전체 분석보다
      KISA 기준에 가까운 sudoers 파일 소유자/권한 점검에 집중한다.
    - include 구조와 sudoers.d 파일은 자동 FAIL보다는 추가 검토용 evidence로 남긴다.
    """

    def __init__(self, check_dir=None):
        self.app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.check_dir = check_dir or os.path.join(
            self.app_dir,
            "checks",
            "u63_sudo_access_management"
        )

        self.reader = AccountPolicyReader()

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
            code=self.metadata.get("code", "U-63"),
            name=self.metadata.get("name", "Manage sudoers File Access"),
            severity=self.metadata.get("severity", "high"),
            category=self.metadata.get("category", "privilege_management"),
            status="MANUAL",
            success=True,
            summary=self._get_message(
                "manual",
                "summary",
                default="sudoers access control requires manual verification."
            ),
            detail=self._get_message(
                "manual",
                "detail",
                default="The main sudoers file or include structure requires additional review."
            ),
            requires_root=self.metadata.get("requires_root", "partial"),
            remediation_summary=self._get_remediation_summary(),
            remediation_steps=self._get_remediation_steps()
        )

        sudoers_rule = self.policy.get("rules", {}).get(
            "sudoers_file_permission_rule",
            {}
        )
        sudoers_d_rule = self.policy.get("rules", {}).get(
            "sudoers_d_directory_rule",
            {}
        )

        sudoers_path = to_text(
            sudoers_rule.get("target_file", "/etc/sudoers")
        ).strip() or "/etc/sudoers"

        sudoers_d_path = to_text(
            sudoers_d_rule.get("target_directory", "/etc/sudoers.d")
        ).strip() or "/etc/sudoers.d"

        max_mode = to_text(
            sudoers_rule.get(
                "max_mode_octal",
                self.policy.get("thresholds", {}).get("sudoers_max_mode", "0640")
            )
        ).strip() or "0640"

        required_owners = self._normalize_text_list(
            sudoers_rule.get("required_owner_names", ["root"])
        )

        allowed_groups = self._normalize_text_list(
            sudoers_rule.get("allowed_group_names", ["root"])
        )

        sudoers_metadata = self.reader.inspect_file(sudoers_path)
        sudoers_file = self.reader.read_file(sudoers_path)

        sudoers_d_metadata = self.reader.inspect_file(sudoers_d_path)
        sudoers_d_files = self.reader.list_sudoers_d_files(sudoers_d_path)

        include_info = {
            "include_lines": [],
            "include_dirs": [],
            "include_files": [],
        }

        if self.reader.file_exists(sudoers_file) and sudoers_file.success and sudoers_file.content:
            include_info = self.reader.parse_sudoers_include_lines(
                sudoers_file.content
            )

        result.raw["sudoers_metadata"] = sudoers_metadata
        result.raw["sudoers_file"] = sudoers_file.to_dict() if sudoers_file else None
        result.raw["sudoers_include_info"] = include_info
        result.raw["sudoers_d_metadata"] = sudoers_d_metadata
        result.raw["sudoers_d_files"] = sudoers_d_files

        sudoers_exists = bool(sudoers_metadata.get("exists"))
        owner_name = to_text(sudoers_metadata.get("owner_name", ""))
        group_name = to_text(sudoers_metadata.get("group_name", ""))
        mode_octal = to_text(sudoers_metadata.get("mode_octal", ""))

        owner_ok = sudoers_exists and owner_name in required_owners
        group_ok = sudoers_exists and (
            not allowed_groups or group_name in allowed_groups
        )
        mode_ok = sudoers_exists and self.reader.is_mode_at_most(
            mode_octal,
            max_mode
        )

        permission_ok = sudoers_exists and owner_ok and mode_ok

        violations = []

        if not sudoers_exists:
            violations.append({
                "path": sudoers_path,
                "reason": "file_missing",
            })
        else:
            if not owner_ok:
                violations.append({
                    "path": sudoers_path,
                    "reason": "owner_not_allowed",
                    "current_owner": owner_name,
                    "required_owners": required_owners,
                })

            if not mode_ok:
                violations.append({
                    "path": sudoers_path,
                    "reason": "mode_too_permissive",
                    "mode_octal": mode_octal,
                    "max_mode_octal": max_mode,
                })

        sudoers_d_review_items = self._evaluate_sudoers_d_files(
            sudoers_d_files,
            max_mode=max_mode
        )

        result.add_evidence(
            key="sudoers_file_exists",
            label=self._label("sudoers_file_exists", "/etc/sudoers exists"),
            source=sudoers_path,
            value=sudoers_exists,
            status="ok" if sudoers_exists else "fail"
        )

        result.add_evidence(
            key="sudoers_owner",
            label=self._label("sudoers_owner", "/etc/sudoers owner"),
            source=sudoers_path,
            value=owner_name if owner_name else "(unknown)",
            status="ok" if owner_ok else "fail"
        )

        result.add_evidence(
            key="sudoers_group",
            label=self._label("sudoers_group", "/etc/sudoers group"),
            source=sudoers_path,
            value=group_name if group_name else "(unknown)",
            status="ok" if group_ok else "manual"
        )

        result.add_evidence(
            key="sudoers_mode",
            label=self._label("sudoers_mode", "/etc/sudoers permission mode"),
            source=sudoers_path,
            value=mode_octal if mode_octal else "(unknown)",
            status="ok" if mode_ok else "fail"
        )

        result.add_evidence(
            key="sudoers_permission_status",
            label=self._label("sudoers_permission_status", "/etc/sudoers permission status"),
            source=sudoers_path,
            value={
                "owner_ok": owner_ok,
                "group_ok": group_ok,
                "mode_ok": mode_ok,
                "permission_ok": permission_ok,
                "violations": violations,
            },
            status="ok" if permission_ok else "fail"
        )

        result.add_evidence(
            key="sudoers_include_structure",
            label=self._label("sudoers_include_structure", "sudoers include structure"),
            source=sudoers_path,
            value=include_info,
            status="manual" if include_info.get("include_lines") else "ok",
            notes="Include directives are not automatically vulnerable, but included files should be reviewed."
        )

        result.add_evidence(
            key="sudoers_d_directory",
            label=self._label("sudoers_d_directory", "/etc/sudoers.d directory metadata"),
            source=sudoers_d_path,
            value={
                "directory_metadata": self._compact_metadata(sudoers_d_metadata),
                "files": sudoers_d_files.get("files", []),
                "errors": sudoers_d_files.get("errors", []),
                "review_items": sudoers_d_review_items,
            },
            status="manual" if sudoers_d_files.get("exists") else "ok",
            notes="sudoers.d is optional. If it is used, included files should also be reviewed."
        )

        reasons = []

        if violations:
            reasons.append(
                "/etc/sudoers ownership or permission does not meet the policy."
            )

        if include_info.get("include_lines"):
            reasons.append(
                "sudoers include directives were detected and included files may require additional review."
            )

        if sudoers_d_review_items:
            reasons.append(
                "sudoers.d files exist and require review."
            )

        if violations:
            result.set_status("FAIL", success=False)
            result.summary = self._get_message(
                "fail",
                "summary",
                default="/etc/sudoers has unsafe ownership or permissions."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "fail",
                    "detail",
                    default="If /etc/sudoers is writable or modifiable by unauthorized users, attackers may change sudo policy and obtain root privileges."
                ),
                reasons
            )
            return result

        if include_info.get("include_lines") or sudoers_d_review_items:
            result.set_status("MANUAL", success=True)
            result.summary = self._get_message(
                "manual",
                "summary",
                default="sudoers access control requires manual verification."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "manual",
                    "detail",
                    default="The main sudoers file is protected, but include structures or sudoers.d configurations may require additional review."
                ),
                reasons
            )
            return result

        result.set_status("PASS", success=True)
        result.summary = self._get_message(
            "pass",
            "summary",
            default="/etc/sudoers is properly protected."
        )
        result.detail = self._merge_detail(
            self._get_message(
                "pass",
                "detail",
                default="The sudoers policy file is owned by root and has restrictive permissions."
            ),
            [
                "/etc/sudoers is owned by root and has permissions of {0} or more restrictive.".format(
                    max_mode
                )
            ]
        )
        return result

    def _evaluate_sudoers_d_files(self, sudoers_d_files, max_mode):
        """
        /etc/sudoers.d 파일들을 검토 대상으로 정리한다.

        1차 구현에서는 자동 FAIL로 보지 않고 manual review item으로만 남긴다.
        """
        review_items = []

        for item in sudoers_d_files.get("files", []):
            path = to_text(item.get("path", ""))
            name = to_text(item.get("name", ""))

            if not path:
                continue

            if name.startswith("."):
                continue

            mode = to_text(item.get("mode_octal", ""))
            owner = to_text(item.get("owner_name", ""))

            mode_ok = self.reader.is_mode_at_most(mode, max_mode)
            owner_ok = owner == "root"

            review_items.append({
                "path": path,
                "owner_name": owner,
                "mode_octal": mode,
                "owner_ok": owner_ok,
                "mode_ok": mode_ok,
                "requires_review": True,
            })

        return review_items

    @staticmethod
    def _compact_metadata(metadata):
        return {
            "path": metadata.get("path"),
            "exists": metadata.get("exists"),
            "owner_name": metadata.get("owner_name"),
            "group_name": metadata.get("group_name"),
            "mode_octal": metadata.get("mode_octal"),
            "is_regular_file": metadata.get("is_regular_file"),
            "is_directory": metadata.get("is_directory"),
        }

    @staticmethod
    def _normalize_text_list(values):
        result = []

        for item in values or []:
            text = to_text(item).strip()
            if text:
                result.append(text)

        return result

    def _load_configs(self):
        if yaml is None:
            raise RuntimeError(
                "PyYAML is required. Please install it first. Cause: {0}".format(
                    to_text(_yaml_import_error)
                )
            )

        self.metadata = self._load_yaml(
            os.path.join(self.check_dir, "metadata.yaml")
        )
        self.targets = self._load_yaml(
            os.path.join(self.check_dir, "targets.yaml")
        )
        self.policy = self._load_yaml(
            os.path.join(self.check_dir, "policy.yaml")
        )
        self.messages = self._load_yaml(
            os.path.join(self.check_dir, "messages.yaml")
        )

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
                    "Restrict /etc/sudoers ownership and permissions."
                )
            )

        return "Restrict /etc/sudoers ownership and permissions."

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
            code="U-63",
            name="Manage sudoers File Access",
            severity="high",
            category="privilege_management",
            status="ERROR",
            success=False,
            summary="An error occurred while running the check.",
            detail=to_text(message),
            requires_root="partial"
        )
        result.add_error(to_text(message))
        return result