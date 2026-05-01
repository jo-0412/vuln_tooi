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


class U37Runner(object):
    """
    U-37 crontab 설정파일 권한 설정 미흡 점검 실행기

    주석/설명: 한국어
    사용자 출력: 영어
    Python 2.7 ~ 3.x 호환

    기능:
    - crontab, at 실행 파일 권한 확인
    - cron/at spool 디렉터리 권한 확인
    - cron.allow, cron.deny, at.allow, at.deny 권한 확인
    - world writable 여부 확인
    - SUID/SGID 여부 확인
    - 권한 위반 항목을 evidence로 출력

    차별점:
    - 전체 파일시스템을 스캔하지 않는다.
    - cron/at 관련 고정 경로만 metadata 기반으로 점검한다.
    - 배포판별로 없을 수 있는 경로는 missing optional로 따로 수집한다.
    """

    def __init__(self, check_dir=None):
        self.app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.check_dir = check_dir or os.path.join(
            self.app_dir,
            "checks",
            "u37_crontab_file_permissions"
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
            code=self.metadata.get("code", "U-37"),
            name=self.metadata.get("name", "Check crontab and at File Permissions"),
            severity=self.metadata.get("severity", "high"),
            category=self.metadata.get("category", "file_and_directory_management"),
            status="MANUAL",
            success=True,
            summary=self._get_message(
                "manual",
                "summary",
                default="cron and at file permissions require manual verification."
            ),
            detail=self._get_message(
                "manual",
                "detail",
                default="Some cron or at related paths require manual review."
            ),
            requires_root=self.metadata.get("requires_root", "partial"),
            remediation_summary=self._get_remediation_summary(),
            remediation_steps=self._get_remediation_steps()
        )

        executable_targets = self._get_target_paths("executables")
        spool_dir_targets = self._get_target_paths("spool_dirs")
        control_file_targets = self._get_target_paths("control_files")

        executable_rule = self._get_rule("executable_permission_rule")
        spool_rule = self._get_rule("spool_directory_permission_rule")
        control_rule = self._get_rule("control_file_permission_rule")

        executable_items = self._inspect_paths(executable_targets, "executable")
        spool_dir_items = self._inspect_paths(spool_dir_targets, "spool_dir")
        control_file_items = self._inspect_paths(control_file_targets, "control_file")

        result.raw["executables"] = executable_items
        result.raw["spool_dirs"] = spool_dir_items
        result.raw["control_files"] = control_file_items

        executable_violations = self._evaluate_executables(
            executable_items,
            executable_rule
        )
        spool_violations = self._evaluate_spool_dirs(
            spool_dir_items,
            spool_rule
        )
        control_violations = self._evaluate_control_files(
            control_file_items,
            control_rule
        )

        permission_violations = []
        permission_violations.extend(executable_violations)
        permission_violations.extend(spool_violations)
        permission_violations.extend(control_violations)

        suid_sgid_items = self._collect_suid_sgid_items(executable_items)

        missing_optional_paths = self._collect_missing_paths(
            executable_items + spool_dir_items + control_file_items
        )

        result.raw["permission_violations"] = permission_violations
        result.raw["suid_sgid_items"] = suid_sgid_items
        result.raw["missing_optional_paths"] = missing_optional_paths

        result.add_evidence(
            key="cron_at_executables",
            label=self._label(
                "cron_at_executables",
                "crontab and at executable permissions"
            ),
            source="/usr/bin/crontab, /usr/bin/at",
            value=[self._compact_item(item) for item in executable_items],
            status="fail" if executable_violations else "ok",
            notes="checked={0}, violations={1}".format(
                len(executable_items),
                len(executable_violations)
            )
        )

        result.add_evidence(
            key="cron_at_spool_directories",
            label=self._label(
                "cron_at_spool_directories",
                "cron and at spool directory permissions"
            ),
            source="/var/spool/cron, /var/spool/at",
            value=[self._compact_item(item) for item in spool_dir_items],
            status="fail" if spool_violations else (
                "manual" if self._all_missing(spool_dir_items) else "ok"
            ),
            notes="checked={0}, violations={1}".format(
                len(spool_dir_items),
                len(spool_violations)
            )
        )

        result.add_evidence(
            key="cron_at_control_files",
            label=self._label(
                "cron_at_control_files",
                "cron and at control file permissions"
            ),
            source="/etc/cron.allow, /etc/cron.deny, /etc/at.allow, /etc/at.deny",
            value=[self._compact_item(item) for item in control_file_items],
            status="fail" if control_violations else (
                "manual" if self._all_missing(control_file_items) else "ok"
            ),
            notes="checked={0}, violations={1}".format(
                len(control_file_items),
                len(control_violations)
            )
        )

        result.add_evidence(
            key="suid_sgid_status",
            label=self._label("suid_sgid_status", "SUID/SGID status"),
            source="/usr/bin/crontab, /usr/bin/at",
            value=suid_sgid_items if suid_sgid_items else ["(none detected)"],
            status="manual" if suid_sgid_items else "ok",
            notes="SUID or SGID may be distribution-specific and requires review."
        )

        result.add_evidence(
            key="permission_violations",
            label=self._label("permission_violations", "Permission violations"),
            source="cron/at related paths",
            value=permission_violations if permission_violations else [],
            status="fail" if permission_violations else "ok",
            notes="count={0}".format(len(permission_violations))
        )

        result.add_evidence(
            key="missing_optional_paths",
            label=self._label("missing_optional_paths", "Missing optional paths"),
            source="cron/at related paths",
            value=missing_optional_paths if missing_optional_paths else ["(none)"],
            status="manual" if missing_optional_paths else "ok",
            notes="Missing paths may be normal depending on distribution or installed packages."
        )

        reasons = []

        if permission_violations:
            reasons.append(
                "cron or at related files have permission violations."
            )
            reasons.append(
                "Detected permission violation count: {0}".format(
                    len(permission_violations)
                )
            )

        if suid_sgid_items:
            reasons.append(
                "SUID or SGID bit was detected and requires manual review."
            )

        if missing_optional_paths:
            reasons.append(
                "Some cron or at related optional paths are missing."
            )

        if permission_violations:
            result.set_status("FAIL", success=False)
            result.summary = self._get_message(
                "fail",
                "summary",
                default="cron or at related files have excessive permissions."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "fail",
                    "detail",
                    default="If ordinary users can freely create or modify scheduled jobs, they may execute malicious commands or damage the system."
                ),
                reasons
            )
            return result

        if suid_sgid_items or missing_optional_paths:
            result.set_status("MANUAL", success=True)
            result.summary = self._get_message(
                "manual",
                "summary",
                default="cron and at file permissions require manual verification."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "manual",
                    "detail",
                    default="Some cron or at related paths are missing, distribution-specific, or contain SUID/SGID permissions that require manual review."
                ),
                reasons
            )
            return result

        result.set_status("PASS", success=True)
        result.summary = self._get_message(
            "pass",
            "summary",
            default="cron and at related files are properly protected."
        )
        result.detail = self._merge_detail(
            self._get_message(
                "pass",
                "detail",
                default="crontab and at executables, spool directories, and control files are protected with appropriate ownership and permissions."
            ),
            ["No unsafe cron or at related permission was detected."]
        )
        return result

    def _inspect_paths(self, targets, target_type):
        """
        targets.yaml에 정의된 경로의 메타데이터를 수집한다.
        """
        items = []

        for target in targets:
            path = to_text(target.get("path", "")).strip()

            if not path:
                continue

            metadata = self.reader.inspect_file(path)

            item = {
                "path": path,
                "target_type": target_type,
                "description": to_text(target.get("description", "")),
                "exists": bool(metadata.get("exists")),
                "owner_name": to_text(metadata.get("owner_name", "")),
                "group_name": to_text(metadata.get("group_name", "")),
                "uid": metadata.get("uid"),
                "gid": metadata.get("gid"),
                "mode_octal": to_text(metadata.get("mode_octal", "")),
                "mode_int": metadata.get("mode_int"),
                "is_regular_file": bool(metadata.get("is_regular_file")),
                "metadata": metadata,
            }

            item["world_writable"] = self._is_world_writable(
                item.get("mode_octal")
            )
            item["suid"] = self._has_suid(item.get("mode_octal"))
            item["sgid"] = self._has_sgid(item.get("mode_octal"))

            items.append(item)

        return items

    def _evaluate_executables(self, items, rule):
        """
        crontab/at 실행 파일 권한을 평가한다.
        """
        violations = []

        allowed_owners = self._normalize_text_list(
            rule.get("allowed_owner_names", ["root"])
        )
        deny_world_writable = bool(rule.get("deny_world_writable", True))

        for item in items:
            if not item.get("exists"):
                continue

            path = item.get("path")
            owner = item.get("owner_name")

            if allowed_owners and owner not in allowed_owners:
                violations.append({
                    "path": path,
                    "reason": "owner_not_allowed",
                    "current_owner": owner,
                    "allowed_owners": allowed_owners,
                })

            if deny_world_writable and item.get("world_writable"):
                violations.append({
                    "path": path,
                    "reason": "world_writable",
                    "mode_octal": item.get("mode_octal"),
                })

        return violations

    def _evaluate_spool_dirs(self, items, rule):
        """
        cron/at spool 디렉터리 권한을 평가한다.
        """
        violations = []

        allowed_owners = self._normalize_text_list(
            rule.get("allowed_owner_names", ["root", "daemon"])
        )
        deny_world_writable = bool(rule.get("deny_world_writable", True))
        max_mode = to_text(rule.get("max_mode_octal", "0750")).strip()

        for item in items:
            if not item.get("exists"):
                continue

            path = item.get("path")
            owner = item.get("owner_name")
            mode = item.get("mode_octal")

            if allowed_owners and owner not in allowed_owners:
                violations.append({
                    "path": path,
                    "reason": "owner_not_allowed",
                    "current_owner": owner,
                    "allowed_owners": allowed_owners,
                })

            if deny_world_writable and item.get("world_writable"):
                violations.append({
                    "path": path,
                    "reason": "world_writable",
                    "mode_octal": mode,
                })

            if max_mode and not self._is_mode_at_most(mode, max_mode):
                violations.append({
                    "path": path,
                    "reason": "mode_too_permissive",
                    "mode_octal": mode,
                    "max_mode_octal": max_mode,
                })

        return violations

    def _evaluate_control_files(self, items, rule):
        """
        cron.allow, cron.deny, at.allow, at.deny 파일 권한을 평가한다.
        """
        violations = []

        allowed_owners = self._normalize_text_list(
            rule.get("allowed_owner_names", ["root"])
        )
        deny_world_writable = bool(rule.get("deny_world_writable", True))
        max_mode = to_text(rule.get("max_mode_octal", "0640")).strip()

        for item in items:
            if not item.get("exists"):
                continue

            path = item.get("path")
            owner = item.get("owner_name")
            mode = item.get("mode_octal")

            if allowed_owners and owner not in allowed_owners:
                violations.append({
                    "path": path,
                    "reason": "owner_not_allowed",
                    "current_owner": owner,
                    "allowed_owners": allowed_owners,
                })

            if deny_world_writable and item.get("world_writable"):
                violations.append({
                    "path": path,
                    "reason": "world_writable",
                    "mode_octal": mode,
                })

            if max_mode and not self._is_mode_at_most(mode, max_mode):
                violations.append({
                    "path": path,
                    "reason": "mode_too_permissive",
                    "mode_octal": mode,
                    "max_mode_octal": max_mode,
                })

        return violations

    @staticmethod
    def _collect_suid_sgid_items(items):
        """
        SUID/SGID 비트가 있는 실행 파일을 수집한다.
        """
        result = []

        for item in items:
            if not item.get("exists"):
                continue

            if item.get("suid") or item.get("sgid"):
                result.append({
                    "path": item.get("path"),
                    "mode_octal": item.get("mode_octal"),
                    "suid": bool(item.get("suid")),
                    "sgid": bool(item.get("sgid")),
                })

        return result

    @staticmethod
    def _collect_missing_paths(items):
        """
        존재하지 않는 경로를 수집한다.
        """
        result = []

        for item in items:
            if not item.get("exists"):
                result.append({
                    "path": item.get("path"),
                    "target_type": item.get("target_type"),
                    "description": item.get("description"),
                })

        return result

    @staticmethod
    def _compact_item(item):
        """
        evidence 출력이 너무 장황하지 않도록 핵심 정보만 정리한다.
        """
        return {
            "path": item.get("path"),
            "exists": item.get("exists"),
            "owner_name": item.get("owner_name"),
            "group_name": item.get("group_name"),
            "mode_octal": item.get("mode_octal"),
            "world_writable": item.get("world_writable"),
            "suid": item.get("suid"),
            "sgid": item.get("sgid"),
        }

    @staticmethod
    def _is_world_writable(mode_octal):
        """
        others write 권한이 있는지 확인한다.
        """
        try:
            mode_value = int(to_text(mode_octal).strip(), 8)
        except Exception:
            return False

        return bool(mode_value & 0o002)

    @staticmethod
    def _has_suid(mode_octal):
        """
        SUID 비트가 있는지 확인한다.
        """
        try:
            mode_value = int(to_text(mode_octal).strip(), 8)
        except Exception:
            return False

        return bool(mode_value & 0o4000)

    @staticmethod
    def _has_sgid(mode_octal):
        """
        SGID 비트가 있는지 확인한다.
        """
        try:
            mode_value = int(to_text(mode_octal).strip(), 8)
        except Exception:
            return False

        return bool(mode_value & 0o2000)

    @staticmethod
    def _is_mode_at_most(current_mode_octal, max_mode_octal):
        """
        현재 권한이 기준 권한 이하인지 확인한다.

        주의:
        - 단순 숫자 비교 방식이다.
        - control file의 0640 이하 판정처럼 명확한 기준에 사용한다.
        """
        try:
            current_value = int(to_text(current_mode_octal).strip(), 8)
            max_value = int(to_text(max_mode_octal).strip(), 8)
        except Exception:
            return False

        return current_value <= max_value

    def _get_target_paths(self, group_name):
        """
        targets.yaml의 files 섹션에서 그룹별 대상 목록을 읽는다.
        """
        files = self.targets.get("files", {})
        values = files.get(group_name, [])

        if isinstance(values, list):
            return values

        return []

    def _get_rule(self, rule_name):
        return self.policy.get("rules", {}).get(rule_name, {})

    @staticmethod
    def _all_missing(items):
        if not items:
            return True

        for item in items:
            if item.get("exists"):
                return False

        return True

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
                    "Restrict cron and at related files and directories to privileged users."
                )
            )

        return "Restrict cron and at related files and directories to privileged users."

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
            code="U-37",
            name="Check crontab and at File Permissions",
            severity="high",
            category="file_and_directory_management",
            status="ERROR",
            success=False,
            summary="An error occurred while running the check.",
            detail=to_text(message),
            requires_root="partial"
        )
        result.add_error(to_text(message))
        return result