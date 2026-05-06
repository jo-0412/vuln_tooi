# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

import io
import os

try:
    import shutil
except Exception:
    shutil = None

try:
    from distutils.spawn import find_executable
except Exception:  # pragma: no cover
    find_executable = None

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


class U04Runner(object):
    """
    U-04 Protect Password Files 점검 실행기
    """

    def __init__(self, check_dir=None):
        self.app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.check_dir = check_dir or os.path.join(
            self.app_dir,
            "checks",
            "u04_password_file_protection"
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
            error_message = to_text(exc)
            return self._build_error_result(
                "Failed to load configuration file: {0}".format(error_message)
            )

        raw_steps = self.messages.get("remediation", {}).get("actions", [])
        remediation_steps = self._dedupe_keep_order(raw_steps)

        result = CheckResult(
            code=self.metadata.get("code", "U-04"),
            name=self.metadata.get("name", "Protect Password Files"),
            severity=self.metadata.get("severity", "high"),
            category=self.metadata.get("category", "account_management"),
            status="MANUAL",
            success=True,
            summary=self._get_message("manual", "summary", default="Automatic determination is difficult."),
            detail=self._get_message("manual", "detail", default="additional verification is required."),
            requires_root=self.metadata.get("requires_root", "required"),
            remediation_summary=self.messages.get("remediation", {}).get("summary"),
            remediation_steps=remediation_steps
        )

        passwd_file = self._read_path("/etc/passwd")
        shadow_file = self._read_path("/etc/shadow")

        aix_path = "/etc/security/passwd"
        trusted_mode_path = "/tcb/files/auth"

        aix_exists = os.path.exists(aix_path)
        trusted_mode_exists = os.path.exists(trusted_mode_path)

        pwconv_path = self._which("pwconv")
        pwconv_available = bool(pwconv_path)

        result.raw["files"] = {
            "passwd": passwd_file.to_dict() if passwd_file else None,
            "shadow": shadow_file.to_dict() if shadow_file else None,
            "aix_passwd_exists": aix_exists,
            "trusted_mode_path_exists": trusted_mode_exists,
        }
        result.raw["commands"] = {
            "pwconv_available": pwconv_available,
            "pwconv_path": pwconv_path,
        }

        passwd_exists = bool(passwd_file and passwd_file.metadata.exists)
        shadow_exists = bool(shadow_file and shadow_file.metadata.exists)
        shadow_readable = bool(shadow_file and shadow_file.success)

        self._add_bool_evidence(
            result,
            key="passwd_exists",
            source="/etc/passwd",
            value=passwd_exists,
            status="ok" if passwd_exists else "fail"
        )

        self._add_bool_evidence(
            result,
            key="shadow_exists",
            source="/etc/shadow",
            value=shadow_exists,
            status="ok" if shadow_exists else "fail"
        )

        if shadow_exists:
            self._add_bool_evidence(
                result,
                key="shadow_readable",
                source="/etc/shadow",
                value=shadow_readable,
                status="ok" if shadow_readable else "manual"
            )
        else:
            self._add_bool_evidence(
                result,
                key="shadow_readable",
                source="/etc/shadow",
                value=False,
                status="info"
            )

        self._add_bool_evidence(
            result,
            key="aix_passwd_exists",
            source=aix_path,
            value=aix_exists,
            status="ok" if aix_exists else "info"
        )

        self._add_bool_evidence(
            result,
            key="trusted_mode_path_exists",
            source=trusted_mode_path,
            value=trusted_mode_exists,
            status="ok" if trusted_mode_exists else "info"
        )

        result.add_evidence(
            key="pwconv_available",
            label=self._label("pwconv_available"),
            source="pwconv",
            value=pwconv_path if pwconv_available else "(command unavailable)",
            status="ok" if pwconv_available else "manual"
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
                ["/etc/passwd file could not be read, so the check cannot determine the result."]
            )
            return result

        passwd_analysis = self._analyze_passwd(passwd_file.content)

        result.raw["passwd_analysis"] = passwd_analysis

        root_second_field = passwd_analysis.get("root_second_field")
        has_x_usage = bool(passwd_analysis.get("x_count", 0) > 0)
        plain_password_detected = passwd_analysis.get("plain_password_detected", False)
        plain_password_accounts = passwd_analysis.get("plain_password_accounts", [])
        root_found = passwd_analysis.get("root_found", False)

        root_field_status = self._status_for_root_field(
            root_second_field,
            aix_exists,
            trusted_mode_exists
        )

        result.add_evidence(
            key="passwd_root_second_field",
            label=self._label("passwd_root_second_field"),
            source="/etc/passwd",
            value=root_second_field if root_second_field is not None else "(root account missing)",
            status=root_field_status,
            excerpt=passwd_analysis.get("root_line")
        )

        result.add_evidence(
            key="passwd_accounts_using_x",
            label=self._label("passwd_accounts_using_x"),
            source="/etc/passwd",
            value=has_x_usage,
            status="ok" if has_x_usage else "info",
            notes="x_count={0}, total_accounts={1}".format(
                passwd_analysis.get("x_count", 0),
                passwd_analysis.get("total_accounts", 0)
            )
        )

        result.add_evidence(
            key="passwd_plain_password_detected",
            label=self._label("passwd_plain_password_detected"),
            source="/etc/passwd",
            value=plain_password_detected,
            status="fail" if plain_password_detected else "ok",
            notes=", ".join(plain_password_accounts) if plain_password_accounts else None
        )

        reasons = []

        if not root_found:
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
                ["Root account information was not found in /etc/passwd."]
            )
            return result

        if plain_password_detected:
            reasons.append("Accounts with direct password values or unsafe values in /etc/passwd exist.")

        standard_shadow_ok = False
        if root_second_field == "x" and shadow_exists:
            standard_shadow_ok = True

        alt_store_ok = bool(aix_exists or trusted_mode_exists)

        if standard_shadow_ok and not plain_password_detected:
            result.set_status("PASS", success=True)
            result.summary = self._get_message(
                "pass", "summary",
                default="Password files are properly protected."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "pass", "detail",
                    default="Passwords are protected through shadow separation or a secure storage method."
                ),
                [
                    "The second field for root in /etc/passwd is x.",
                    "/etc/shadow exists."
                ]
            )
            return result

        if alt_store_ok and (not plain_password_detected):
            result.set_status("PASS", success=True)
            result.summary = self._get_message(
                "pass", "summary",
                default="Password files are properly protected."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "pass", "detail",
                    default="Passwords are protected through shadow separation or a secure storage method."
                ),
                ["Platform-specific protected storage (/etc/security/passwd or /tcb/files/auth) exists."]
            )
            return result

        if root_second_field == "x" and (not shadow_exists):
            reasons.append("The second field for root in /etc/passwd is x, but /etc/shadow does not exist.")

        if (root_second_field != "x") and (not alt_store_ok):
            reasons.append("Shadow passwords are not used and no platform-specific protected storage was found.")

        if not reasons:
            reasons.append("Protect Password Files status does not meet the criterion.")

        result.set_status("FAIL", success=False)
        result.summary = self._get_message(
            "fail", "summary",
            default="Password file protection is insufficient."
        )
        result.detail = self._merge_detail(
            self._get_message(
                "fail", "detail",
                default="Account passwords are not protected by shadow separation or secure encryption, so password exposure risk is high if files are leaked."
            ),
            reasons
        )
        return result

    def _analyze_passwd(self, content):
        policy_root = self.policy.get("rules", {}).get("shadow_rule", {})
        passwd_requirements = policy_root.get("passwd_requirements", {})
        allowed_special_tokens = passwd_requirements.get(
            "allow_special_tokens",
            ["x", "*", "!", "!!", "NP", "LK"]
        )

        allowed_tokens = set()
        for token in allowed_special_tokens:
            allowed_tokens.add(to_text(token))

        lines = content.splitlines()
        total_accounts = 0
        x_count = 0
        root_found = False
        root_second_field = None
        root_line = None
        plain_password_detected = False
        plain_password_accounts = []

        for raw_line in lines:
            stripped = raw_line.strip()
            if (not stripped) or stripped.startswith("#"):
                continue

            parts = raw_line.split(":")
            if len(parts) < 2:
                continue

            username = to_text(parts[0]).strip()
            second_field = to_text(parts[1]).strip()

            total_accounts += 1

            if second_field == "x":
                x_count += 1

            if username == "root":
                root_found = True
                root_second_field = second_field
                root_line = raw_line.strip()

            if second_field not in allowed_tokens:
                plain_password_detected = True
                plain_password_accounts.append(username)

        return {
            "root_found": root_found,
            "root_second_field": root_second_field,
            "root_line": root_line,
            "total_accounts": total_accounts,
            "x_count": x_count,
            "plain_password_detected": plain_password_detected,
            "plain_password_accounts": plain_password_accounts,
        }

    @staticmethod
    def _status_for_root_field(root_second_field, aix_exists, trusted_mode_exists):
        if root_second_field is None:
            return "manual"

        if root_second_field == "x":
            return "ok"

        if aix_exists or trusted_mode_exists:
            if root_second_field in ("*", "!", "!!", "NP", "LK"):
                return "info"

        if root_second_field in ("*", "!", "!!", "NP", "LK"):
            return "manual"

        return "fail"

    def _read_path(self, path):
        result = self.file_reader.read(path)
        return result if result else None

    def _which(self, command_name):
        if shutil is not None and hasattr(shutil, "which"):
            try:
                return shutil.which(command_name)
            except Exception:
                pass

        if find_executable is not None:
            try:
                return find_executable(command_name)
            except Exception:
                pass

        return None

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
                    _yaml_import_error
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
            code="U-04",
            name="Protect Password Files",
            severity="high",
            category="account_management",
            status="ERROR",
            success=False,
            summary="An error occurred while running the check.",
            detail=to_text(message),
            requires_root="required"
        )
        result.add_error(to_text(message))
        return result