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
from app.collectors.file_reader import FileReader
from app.models.check_result import CheckResult


class U05Runner(object):
    """
    U-05 Prohibit UID 0 Accounts Other Than root 점검 실행기
    """

    def __init__(self, check_dir=None):
        self.app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.check_dir = check_dir or os.path.join(
            self.app_dir,
            "checks",
            "u05_uid_zero_restriction"
        )
        self.file_reader = FileReader()

        self.metadata = {}
        self.targets = {}
        self.policy = {}
        self.messages = {}

    def run(self):
        try:
            self._load_configs()
        except Exception as exc:
            return self._build_error_result(
                "Failed to load configuration file: {0}".format(to_text(exc))
            )

        raw_steps = self.messages.get("remediation", {}).get("actions", [])
        remediation_steps = self._dedupe_keep_order(raw_steps)

        result = CheckResult(
            code=self.metadata.get("code", "U-05"),
            name=self.metadata.get("name", "Prohibit UID 0 Accounts Other Than root"),
            severity=self.metadata.get("severity", "high"),
            category=self.metadata.get("category", "account_management"),
            status="MANUAL",
            success=True,
            summary=self._get_message("manual", "summary", default="Automatic determination is difficult."),
            detail=self._get_message("manual", "detail", default="additional verification is required."),
            requires_root=self.metadata.get("requires_root", "partial"),
            remediation_summary=self.messages.get("remediation", {}).get("summary"),
            remediation_steps=remediation_steps
        )

        passwd_file = self._read_path("/etc/passwd")

        result.raw["files"] = {
            "passwd": passwd_file.to_dict() if passwd_file else None,
        }

        passwd_exists = bool(passwd_file and passwd_file.metadata.exists)
        self._add_bool_evidence(
            result,
            key="passwd_exists",
            source="/etc/passwd",
            value=passwd_exists,
            status="ok" if passwd_exists else "fail"
        )

        if passwd_file is None or (not passwd_file.success) or (not passwd_file.content):
            result.add_error("/etc/passwd file could not be read.")
            result.set_status("ERROR", success=False)
            result.summary = self._get_message(
                "error", "summary",
                default="An error occurred while running the check."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "error", "detail",
                    default="A required file could not be read, or an error occurred while collecting information needed for the check."
                ),
                ["/etc/passwd could not be read, so UID 0 accounts cannot be evaluated."]
            )
            return result

        analysis = self._analyze_passwd(passwd_file.content)
        result.raw["passwd_analysis"] = analysis

        root_found = analysis.get("root_found", False)
        root_line = analysis.get("root_line")
        uid_zero_accounts = analysis.get("uid_zero_accounts", [])
        uid_zero_non_root_accounts = analysis.get("uid_zero_non_root_accounts", [])
        malformed_lines = analysis.get("malformed_lines", [])
        uid_zero_count = len(uid_zero_accounts)

        result.add_evidence(
            key="root_passwd_line",
            label=self._label("root_passwd_line"),
            source="/etc/passwd",
            value=root_line if root_line is not None else "(root account missing)",
            status="ok" if root_found else "manual",
            excerpt=root_line
        )

        result.add_evidence(
            key="uid_zero_accounts",
            label=self._label("uid_zero_accounts"),
            source="/etc/passwd",
            value=uid_zero_accounts if uid_zero_accounts else [],
            status="ok" if uid_zero_accounts else "manual",
            notes="uid_zero_count={0}".format(uid_zero_count)
        )

        result.add_evidence(
            key="uid_zero_non_root_accounts",
            label=self._label("uid_zero_non_root_accounts"),
            source="/etc/passwd",
            value=uid_zero_non_root_accounts if uid_zero_non_root_accounts else [],
            status="fail" if uid_zero_non_root_accounts else "ok"
        )

        result.add_evidence(
            key="uid_zero_count",
            label=self._label("uid_zero_count"),
            source="/etc/passwd",
            value=uid_zero_count,
            status="ok" if uid_zero_count >= 1 else "manual"
        )

        reasons = []

        if malformed_lines:
            reasons.append(
                "Malformed lines exist in /etc/passwd. (count: {0})".format(
                    len(malformed_lines)
                )
            )

        if not root_found:
            result.set_status("MANUAL", success=True)
            result.summary = self._get_message(
                "manual", "summary",
                default="Automatic determination is difficult."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "manual", "detail",
                    default="The passwd structure is abnormal or the root account is difficult to identify, additional verification is required."
                ),
                reasons + ["The root account was not found in /etc/passwd."]
            )
            return result

        if uid_zero_non_root_accounts:
            reasons.append(
                "UID 0 accounts other than root exist: {0}".format(
                    ", ".join(uid_zero_non_root_accounts)
                )
            )
            result.set_status("FAIL", success=False)
            result.summary = self._get_message(
                "fail", "summary",
                default="A UID 0 account exists other than root."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "fail", "detail",
                    default="A UID 0 account exists other than root and can be abused as a hidden administrator account, making audit tracking difficult."
                ),
                reasons
            )
            return result

        if uid_zero_accounts == ["root"]:
            result.set_status("PASS", success=True)
            result.summary = self._get_message(
                "pass", "summary",
                default="No UID 0 account exists other than root."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "pass", "detail",
                    default="Only root has UID 0, so the possibility of privilege impersonation through hidden administrator accounts is low."
                ),
                ["Only root has UID 0."]
            )
            return result

        if uid_zero_count == 0:
            result.set_status("MANUAL", success=True)
            result.summary = self._get_message(
                "manual", "summary",
                default="Automatic determination is difficult."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "manual", "detail",
                    default="The passwd structure is abnormal or the root account is difficult to identify, additional verification is required."
                ),
                ["No account with UID 0 was found. The passwd structure must be checked."]
            )
            return result

        result.set_status("MANUAL", success=True)
        result.summary = self._get_message(
            "manual", "summary",
            default="Automatic determination is difficult."
        )
        result.detail = self._merge_detail(
            self._get_message(
                "manual", "detail",
                default="additional verification is required."
            ),
            reasons if reasons else ["UID 0 account structure requires additional verification."]
        )
        return result

    def _analyze_passwd(self, content):
        lines = content.splitlines()

        root_found = False
        root_line = None
        uid_zero_accounts = []
        uid_zero_non_root_accounts = []
        malformed_lines = []

        for raw_line in lines:
            stripped = raw_line.strip()

            if (not stripped) or stripped.startswith("#"):
                continue

            parts = raw_line.split(":")
            if len(parts) < 7:
                malformed_lines.append(raw_line.strip())
                continue

            username = to_text(parts[0]).strip()
            uid_field = to_text(parts[2]).strip()

            if username == "root":
                root_found = True
                root_line = raw_line.strip()

            if uid_field == "0":
                uid_zero_accounts.append(username)
                if username != "root":
                    uid_zero_non_root_accounts.append(username)

        return {
            "root_found": root_found,
            "root_line": root_line,
            "uid_zero_accounts": uid_zero_accounts,
            "uid_zero_non_root_accounts": uid_zero_non_root_accounts,
            "uid_zero_count": len(uid_zero_accounts),
            "malformed_lines": malformed_lines,
        }

    def _read_path(self, path):
        result = self.file_reader.read(path)
        return result if result else None

    def _add_bool_evidence(self, result, key, source, value, status):
        result.add_evidence(
            key=key,
            label=self._label(key),
            source=source,
            value=bool(value),
            status=status
        )

    def _load_configs(self):
        if yaml is None:
            raise RuntimeError(
                "PyYAML is required. Install it and run again. Cause: {0}".format(
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
            raise ValueError("The top-level YAML structure must be a dict: {0}".format(path))

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

        merged = [to_text(base_detail).strip(), "", "Decision reasons:"]
        for reason in filtered:
            merged.append("- {0}".format(reason))
        return "\n".join(merged)

    def _build_error_result(self, message):
        result = CheckResult(
            code="U-05",
            name="Prohibit UID 0 Accounts Other Than root",
            severity="high",
            category="account_management",
            status="ERROR",
            success=False,
            summary="An error occurred while running the check.",
            detail=to_text(message),
            requires_root="partial"
        )
        result.add_error(to_text(message))
        return result