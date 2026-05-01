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


class U30Runner(object):
    """
    U-30 UMASK 설정 관리 점검 실행기

    주석/설명: 한국어
    사용자 출력: 영어
    Python 2.7 ~ 3.x 호환

    기능:
    - /etc/profile의 umask 라인 확인
    - /etc/login.defs의 UMASK 값 확인
    - 현재 세션 umask 수집
    - 기준값 022 이상인지 권한 마스크 관점에서 판정
    """

    def __init__(self, check_dir=None):
        self.app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.check_dir = check_dir or os.path.join(
            self.app_dir,
            "checks",
            "u30_umask_management"
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

        required_umask = self._get_required_umask()

        result = CheckResult(
            code=self.metadata.get("code", "U-30"),
            name=self.metadata.get("name", "Manage UMASK Setting"),
            severity=self.metadata.get("severity", "medium"),
            category=self.metadata.get("category", "file_and_directory_management"),
            status="MANUAL",
            success=True,
            summary=self._get_message(
                "manual",
                "summary",
                default="UMASK configuration requires manual verification."
            ),
            detail=self._get_message(
                "manual",
                "detail",
                default="UMASK settings are missing, duplicated, or conflicting."
            ),
            requires_root=self.metadata.get("requires_root", "partial"),
            remediation_summary=self._get_remediation_summary(),
            remediation_steps=self._get_remediation_steps()
        )

        profile_file = self.reader.read_file("/etc/profile")
        login_defs_file = self.reader.read_file("/etc/login.defs")
        current_umask_info = self.reader.run_current_umask()

        result.raw["files"] = {
            "/etc/profile": profile_file.to_dict() if profile_file else None,
            "/etc/login.defs": login_defs_file.to_dict() if login_defs_file else None,
        }
        result.raw["current_umask"] = current_umask_info

        profile_exists = self.reader.file_exists(profile_file)
        login_defs_exists = self.reader.file_exists(login_defs_file)

        profile_info = {
            "items": [],
            "lines": [],
            "values": [],
        }

        login_defs_info = {
            "items": [],
            "lines": [],
            "values": [],
        }

        if profile_exists and profile_file and profile_file.success and profile_file.content:
            profile_info = self.reader.parse_profile_umask_lines(profile_file.content)

        if login_defs_exists and login_defs_file and login_defs_file.success and login_defs_file.content:
            login_defs_info = self.reader.parse_login_defs_umask(login_defs_file.content)

        profile_values = profile_info.get("values", [])
        login_defs_values = login_defs_info.get("values", [])
        current_umask_value = to_text(current_umask_info.get("value", "")).strip()

        detected_values = []
        for value in profile_values:
            detected_values.append({
                "source": "/etc/profile",
                "value": value,
                "secure": self.reader.is_umask_secure(value, required_umask),
            })

        for value in login_defs_values:
            detected_values.append({
                "source": "/etc/login.defs",
                "value": value,
                "secure": self.reader.is_umask_secure(value, required_umask),
            })

        if current_umask_value:
            detected_values.append({
                "source": "current session",
                "value": current_umask_value,
                "secure": self.reader.is_umask_secure(current_umask_value, required_umask),
            })

        global_values = []
        for value in profile_values:
            global_values.append(value)
        for value in login_defs_values:
            global_values.append(value)

        normalized_global_values = self._dedupe_keep_order([
            self.reader.normalize_umask_value(value)
            for value in global_values
            if value
        ])

        duplicate_umask_settings = len(normalized_global_values) > 1

        weak_global_values = []
        secure_global_values = []

        for value in global_values:
            normalized = self.reader.normalize_umask_value(value)
            if self.reader.is_umask_secure(normalized, required_umask):
                secure_global_values.append(normalized)
            else:
                weak_global_values.append(normalized)

        secure_global_values = self._dedupe_keep_order(secure_global_values)
        weak_global_values = self._dedupe_keep_order(weak_global_values)

        current_umask_secure = self.reader.is_umask_secure(current_umask_value, required_umask)

        result.raw["parsed"] = {
            "required_umask": required_umask,
            "profile_info": profile_info,
            "login_defs_info": login_defs_info,
            "current_umask": current_umask_info,
            "detected_values": detected_values,
            "secure_global_values": secure_global_values,
            "weak_global_values": weak_global_values,
            "duplicate_umask_settings": duplicate_umask_settings,
        }

        result.add_evidence(
            key="profile_file_exists",
            label=self._label("profile_file_exists", "/etc/profile exists"),
            source="/etc/profile",
            value=profile_exists,
            status="ok" if profile_exists else "manual"
        )

        result.add_evidence(
            key="login_defs_file_exists",
            label=self._label("login_defs_file_exists", "/etc/login.defs exists"),
            source="/etc/login.defs",
            value=login_defs_exists,
            status="ok" if login_defs_exists else "manual"
        )

        result.add_evidence(
            key="profile_umask_lines",
            label=self._label("profile_umask_lines", "UMASK lines in /etc/profile"),
            source="/etc/profile",
            value=profile_info.get("lines", []) if profile_info.get("lines", []) else ["(not configured)"],
            status="ok" if profile_values else "manual"
        )

        result.add_evidence(
            key="login_defs_umask_value",
            label=self._label("login_defs_umask_value", "UMASK value in /etc/login.defs"),
            source="/etc/login.defs",
            value=login_defs_values if login_defs_values else ["(not configured)"],
            status="ok" if login_defs_values else "manual"
        )

        result.add_evidence(
            key="detected_umask_values",
            label=self._label("detected_umask_values", "Detected UMASK values"),
            source="/etc/profile, /etc/login.defs",
            value=detected_values if detected_values else [],
            status="fail" if weak_global_values else ("ok" if secure_global_values else "manual")
        )

        result.add_evidence(
            key="duplicate_umask_settings",
            label=self._label("duplicate_umask_settings", "Duplicate UMASK settings"),
            source="/etc/profile, /etc/login.defs",
            value={
                "duplicate": duplicate_umask_settings,
                "values": normalized_global_values,
            },
            status="manual" if duplicate_umask_settings else "ok"
        )

        result.add_evidence(
            key="current_session_umask",
            label=self._label("current_session_umask", "Current session UMASK"),
            source="umask",
            value=current_umask_value if current_umask_value else "(not detected)",
            status="ok" if current_umask_secure else ("fail" if current_umask_value else "manual"),
            notes="command={0}, status={1}, rc={2}".format(
                to_text(current_umask_info.get("command", "")),
                to_text(current_umask_info.get("status", "")),
                to_text(current_umask_info.get("returncode", ""))
            )
        )

        effective_policy = {
            "required_umask": required_umask,
            "secure_global_values": secure_global_values,
            "weak_global_values": weak_global_values,
            "current_session_umask": current_umask_value if current_umask_value else "(not detected)",
            "current_session_secure": current_umask_secure,
            "duplicate_umask_settings": duplicate_umask_settings,
        }

        result.add_evidence(
            key="effective_umask_policy",
            label=self._label("effective_umask_policy", "Effective UMASK policy"),
            source="/etc/profile, /etc/login.defs, current session",
            value=effective_policy,
            status="fail" if weak_global_values else ("ok" if secure_global_values else "manual")
        )

        reasons = []

        if secure_global_values:
            reasons.append(
                "Secure global UMASK value was detected: {0}".format(
                    ", ".join(secure_global_values)
                )
            )

        if weak_global_values:
            reasons.append(
                "Weak global UMASK value was detected: {0}".format(
                    ", ".join(weak_global_values)
                )
            )

        if duplicate_umask_settings:
            reasons.append(
                "Multiple UMASK values were detected and may require final effective value review."
            )

        if current_umask_value:
            reasons.append(
                "Current session UMASK is {0}.".format(current_umask_value)
            )
        else:
            reasons.append(
                "Current session UMASK could not be collected."
            )

        if weak_global_values:
            result.set_status("FAIL", success=False)
            result.summary = self._get_message(
                "fail",
                "summary",
                default="A weak UMASK value was detected."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "fail",
                    "detail",
                    default="If UMASK is too weak, newly created files and directories may be assigned excessive permissions."
                ),
                reasons
            )
            return result

        if secure_global_values and not duplicate_umask_settings:
            result.set_status("PASS", success=True)
            result.summary = self._get_message(
                "pass",
                "summary",
                default="A secure UMASK value is configured."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "pass",
                    "detail",
                    default="The system-wide UMASK setting is configured to 022 or more restrictive."
                ),
                reasons
            )
            return result

        if secure_global_values and duplicate_umask_settings:
            result.set_status("MANUAL", success=True)
            result.summary = self._get_message(
                "manual",
                "summary",
                default="UMASK configuration requires manual verification."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "manual",
                    "detail",
                    default="Multiple UMASK settings were detected and require final effective value review."
                ),
                reasons
            )
            return result

        if current_umask_value and current_umask_secure:
            result.set_status("MANUAL", success=True)
            result.summary = self._get_message(
                "manual",
                "summary",
                default="UMASK configuration requires manual verification."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "manual",
                    "detail",
                    default="The current session UMASK appears secure, but system-wide configuration was not clearly confirmed."
                ),
                reasons
            )
            return result

        result.set_status("MANUAL", success=True)
        result.summary = self._get_message(
            "manual",
            "summary",
            default="UMASK configuration requires manual verification."
        )
        result.detail = self._merge_detail(
            self._get_message(
                "manual",
                "detail",
                default="UMASK settings are missing, duplicated, or conflicting."
            ),
            reasons
        )
        return result

    def _get_required_umask(self):
        thresholds = self.policy.get("thresholds", {})
        value = thresholds.get("required_umask", "022")
        return to_text(value).strip() or "022"

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
                    "Configure UMASK to 022 or more restrictive."
                )
            )

        return "Configure UMASK to 022 or more restrictive."

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
            code="U-30",
            name="Manage UMASK Setting",
            severity="medium",
            category="file_and_directory_management",
            status="ERROR",
            success=False,
            summary="An error occurred while running the check.",
            detail=to_text(message),
            requires_root="partial"
        )
        result.add_error(to_text(message))
        return result