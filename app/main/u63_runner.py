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

    개선된 기능:
    - /etc/sudoers 소유자/권한 확인
    - /etc/sudoers include 구조 확인
    - /etc/sudoers.d 파일 권한 확인
    - /etc/sudoers.d 파일 내용 분석
    - 위험 sudo 규칙 탐지
    - 위험 규칙이 없으면 include 구조가 있어도 PASS 가능
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
        sudoers_d_policy_analysis = self.reader.analyze_sudoers_d_policy_files(
            sudoers_d_path
        )

        include_info = {
            "include_lines": [],
            "include_dirs": [],
            "include_files": [],
        }

        main_sudoers_analysis = {
            "source": sudoers_path,
            "policy_lines": {
                "active_lines": [],
                "include_lines": [],
                "defaults_lines": [],
                "alias_lines": [],
                "rule_lines": [],
            },
            "risky_rules": [],
            "manual_rules": [],
        }

        if self.reader.file_exists(sudoers_file) and sudoers_file.success and sudoers_file.content:
            include_info = self.reader.parse_sudoers_include_lines(
                sudoers_file.content
            )
            main_sudoers_analysis = self.reader.analyze_sudoers_risky_rules(
                sudoers_file.content,
                source=sudoers_path
            )

        result.raw["sudoers_metadata"] = sudoers_metadata
        result.raw["sudoers_file"] = sudoers_file.to_dict() if sudoers_file else None
        result.raw["sudoers_include_info"] = include_info
        result.raw["main_sudoers_policy_analysis"] = main_sudoers_analysis
        result.raw["sudoers_d_metadata"] = sudoers_d_metadata
        result.raw["sudoers_d_files"] = sudoers_d_files
        result.raw["sudoers_d_policy_analysis"] = sudoers_d_policy_analysis

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

        sudoers_violations = []

        if not sudoers_exists:
            sudoers_violations.append({
                "path": sudoers_path,
                "reason": "file_missing",
            })
        else:
            if not owner_ok:
                sudoers_violations.append({
                    "path": sudoers_path,
                    "reason": "owner_not_allowed",
                    "current_owner": owner_name,
                    "required_owners": required_owners,
                })

            if not mode_ok:
                sudoers_violations.append({
                    "path": sudoers_path,
                    "reason": "mode_too_permissive",
                    "mode_octal": mode_octal,
                    "max_mode_octal": max_mode,
                })

        sudoers_d_permission_violations = self._evaluate_sudoers_d_file_permissions(
            sudoers_d_files,
            max_mode=max_mode
        )

        risky_rules = []
        manual_rules = []

        risky_rules.extend(main_sudoers_analysis.get("risky_rules", []))
        risky_rules.extend(sudoers_d_policy_analysis.get("risky_rules", []))

        manual_rules.extend(main_sudoers_analysis.get("manual_rules", []))
        manual_rules.extend(sudoers_d_policy_analysis.get("manual_rules", []))

        analysis_errors = []
        analysis_errors.extend(sudoers_d_policy_analysis.get("errors", []))

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
                "violations": sudoers_violations,
            },
            status="ok" if permission_ok else "fail"
        )

        result.add_evidence(
            key="sudoers_include_structure",
            label=self._label("sudoers_include_structure", "sudoers include structure"),
            source=sudoers_path,
            value=include_info,
            status="ok",
            notes="Include directives were parsed and included sudoers.d files were analyzed."
        )

        result.add_evidence(
            key="sudoers_d_directory",
            label=self._label("sudoers_d_directory", "/etc/sudoers.d directory metadata"),
            source=sudoers_d_path,
            value={
                "directory_metadata": self._compact_metadata(sudoers_d_metadata),
                "files": sudoers_d_files.get("files", []),
                "permission_violations": sudoers_d_permission_violations,
                "analysis_errors": analysis_errors,
            },
            status="fail" if sudoers_d_permission_violations else (
                "manual" if analysis_errors else "ok"
            ),
            notes="sudoers.d files are analyzed for ownership, permissions, and risky sudo rules."
        )

        result.add_evidence(
            key="sudoers_policy_rules",
            label="sudoers policy rule analysis",
            source="/etc/sudoers, /etc/sudoers.d",
            value={
                "main_sudoers_rule_count": len(
                    main_sudoers_analysis.get("policy_lines", {}).get("rule_lines", [])
                ),
                "sudoers_d_items": self._compact_sudoers_d_analysis(
                    sudoers_d_policy_analysis
                ),
                "risky_rules": risky_rules,
                "manual_rules": manual_rules,
            },
            status="fail" if risky_rules else (
                "manual" if manual_rules else "ok"
            ),
            notes="Risky rules such as NOPASSWD: ALL or ALL ALL=(ALL) ALL are detected automatically."
        )

        reasons = []

        if sudoers_violations:
            reasons.append(
                "/etc/sudoers ownership or permission does not meet the policy."
            )

        if sudoers_d_permission_violations:
            reasons.append(
                "Some sudoers.d files have unsafe ownership or permissions."
            )

        if risky_rules:
            reasons.append(
                "Risky sudo policy rules were detected."
            )

        if manual_rules:
            reasons.append(
                "Some sudo policy rules require manual review."
            )

        if analysis_errors:
            reasons.append(
                "Some sudoers.d files could not be analyzed."
            )

        if include_info.get("include_lines") and not risky_rules and not manual_rules and not analysis_errors:
            reasons.append(
                "sudoers include directives were detected, but included files did not contain risky rules."
            )

        # 1. /etc/sudoers 자체 권한 문제 또는 sudoers.d 권한 문제는 FAIL
        if sudoers_violations or sudoers_d_permission_violations:
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

        # 2. 위험 sudo 규칙도 FAIL
        if risky_rules:
            result.set_status("FAIL", success=False)
            result.summary = "Risky sudo policy rules were detected."
            result.detail = self._merge_detail(
                "Risky sudo rules may allow unauthorized or passwordless privilege escalation.",
                reasons
            )
            return result

        # 3. 제한적 NOPASSWD, 읽기 실패 등은 MANUAL
        if manual_rules or analysis_errors:
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
                    default="Some sudo policy rules or included files require manual review."
                ),
                reasons
            )
            return result

        # 4. include 구조가 있어도 분석 결과 문제가 없으면 PASS
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
            reasons if reasons else [
                "/etc/sudoers and included sudoers.d files are protected and no risky sudo rules were detected."
            ]
        )
        return result

    def _evaluate_sudoers_d_file_permissions(self, sudoers_d_files, max_mode):
        """
        /etc/sudoers.d 파일 권한을 평가한다.

        README는 설명 파일이므로 자동 취약 판단에서 제외한다.
        """
        violations = []

        for item in sudoers_d_files.get("files", []):
            path = to_text(item.get("path", ""))
            name = to_text(item.get("name", ""))

            if not path:
                continue

            if name.upper() == "README":
                continue

            if name.startswith("."):
                continue

            owner = to_text(item.get("owner_name", ""))
            mode = to_text(item.get("mode_octal", ""))

            if owner != "root":
                violations.append({
                    "path": path,
                    "reason": "owner_not_root",
                    "owner_name": owner,
                })

            if not self.reader.is_mode_at_most(mode, max_mode):
                violations.append({
                    "path": path,
                    "reason": "mode_too_permissive",
                    "mode_octal": mode,
                    "max_mode_octal": max_mode,
                })

        return violations

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
    def _compact_sudoers_d_analysis(analysis):
        items = []

        for item in analysis.get("items", []):
            items.append({
                "path": item.get("path"),
                "name": item.get("name"),
                "skipped": item.get("skipped"),
                "skip_reason": item.get("skip_reason", ""),
                "readable": item.get("readable", False),
                "active_policy_line_count": item.get("active_policy_line_count", 0),
                "risky_rule_count": len(item.get("risky_rules", [])),
                "manual_rule_count": len(item.get("manual_rules", [])),
            })

        return items

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