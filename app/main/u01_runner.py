# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

import io
import os
import re

try:
    import yaml
except ImportError as exc:  # pragma: no cover
    yaml = None
    _yaml_import_error = exc
else:
    _yaml_import_error = None

from app.collectors.file_reader import FileReader
from app.collectors.service_reader import ServiceReader
from app.models.check_result import CheckResult
from app.compat import to_text

class U01Runner(object):
    """
    U-01 Restrict Remote root Login 점검 실행기
    """

    def __init__(self, check_dir=None):
        self.app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.check_dir = check_dir or os.path.join(
            self.app_dir,
            "checks",
            "u01_root_remote_login"
        )
        self.file_reader = FileReader()
        self.service_reader = ServiceReader(timeout=5)

        self.metadata = {}
        self.targets = {}
        self.policy = {}
        self.messages = {}

    def run(self):
        try:
            self._load_configs()
        except Exception as exc:
            return self._build_error_result(
                "Failed to load configuration file: {0}".format(exc)
            )

        result = CheckResult(
            code=self.metadata.get("code", "U-01"),
            name=self.metadata.get("name", "Restrict Remote root Login"),
            severity=self.metadata.get("severity", "high"),
            category=self.metadata.get("category", "account_management"),
            status="MANUAL",
            success=True,
            summary=self._get_message("manual", "summary", default="Automatic determination is difficult."),
            detail=self._get_message("manual", "detail", default="additional verification is required."),
            requires_root=self.metadata.get("requires_root", "partial"),
            remediation_summary=self.messages.get("remediation", {}).get("summary"),
            remediation_steps=self.messages.get("remediation", {}).get("actions", []),
        )

        ssh_service = self._inspect_named_service("ssh")
        telnet_service = self._inspect_named_service("telnet")

        result.raw["service_statuses"] = {
            "ssh": ssh_service.to_dict(),
            "telnet": telnet_service.to_dict(),
        }

        self._add_service_evidence(result, "ssh_service", "SSH service status", ssh_service)
        self._add_service_evidence(result, "telnet_service", "Telnet-family service status", telnet_service)

        ssh_in_use = bool(ssh_service.active)
        telnet_in_use = bool(telnet_service.active)

        component_states = []
        detail_reasons = []

        ssh_state, ssh_reason = self._evaluate_ssh(result, ssh_in_use)
        if ssh_state:
            component_states.append(ssh_state)
        if ssh_reason:
            detail_reasons.append(ssh_reason)

        telnet_state, telnet_reason = self._evaluate_telnet(result, telnet_in_use)
        if telnet_state:
            component_states.append(telnet_state)
        if telnet_reason:
            detail_reasons.append(telnet_reason)

        if not ssh_in_use and not telnet_in_use:
            result.set_status("PASS", success=True)
            result.summary = self._get_message(
                "pass", "summary",
                default="Direct remote login for the root account is blocked."
            )
            base_detail = self._get_message(
                "pass",
                "detail",
                default="Remote terminal services are not used or direct root login is blocked."
            )
            result.detail = self._merge_detail(
                base_detail,
                ["SSH/Telnet remote terminal services are not active."]
            )
            result.raw["component_states"] = component_states
            return result

        if "fail" in component_states:
            result.set_status("FAIL", success=False)
            result.summary = self._get_message(
                "fail", "summary",
                default="Direct remote login for the root account is allowed."
            )
            base_detail = self._get_message(
                "fail",
                "detail",
                default="The current server allows direct remote login for the root account."
            )
            result.detail = self._merge_detail(base_detail, detail_reasons)
        elif "manual" in component_states or "error" in component_states:
            result.set_status("MANUAL", success=True)
            result.summary = self._get_message(
                "manual", "summary",
                default="Automatic determination is difficult."
            )
            base_detail = self._get_message(
                "manual",
                "detail",
                default="additional verification is required."
            )
            result.detail = self._merge_detail(base_detail, detail_reasons)
        else:
            result.set_status("PASS", success=True)
            result.summary = self._get_message(
                "pass", "summary",
                default="Direct remote login for the root account is blocked."
            )
            base_detail = self._get_message(
                "pass",
                "detail",
                default="Remote terminal services are not used, or direct root login is restricted in the services in use."
            )
            result.detail = self._merge_detail(base_detail, detail_reasons)

        result.raw["component_states"] = component_states
        return result

    def _evaluate_ssh(self, result, ssh_in_use):
        if not ssh_in_use:
            return "not_used", "The SSH service is not active, so remote root access is not exposed by the SSH criterion."

        ssh_paths = self._get_paths_by_parser("sshd_config")
        ssh_file = self._read_first_readable(ssh_paths)

        if ssh_file is None:
            result.add_error("SSH configuration file was not found.")
            return "manual", "The SSH service is active, but sshd_config was not found, so manual verification is required."

        self._add_file_evidence(
            result,
            key="sshd_config_path",
            label="Actual SSH configuration file used",
            source=ssh_file.path,
            value=ssh_file.path,
            status="ok" if ssh_file.success else ssh_file.status
        )

        if (not ssh_file.success) or (not ssh_file.content):
            result.add_error("Failed to read SSH configuration file: {0}".format(ssh_file.path))
            return "manual", "SSH configuration file could not be read, so the PermitRootLogin value cannot be determined automatically."

        permit_value, permit_line = self._parse_sshd_key(
            ssh_file.content,
            "PermitRootLogin"
        )
        label = self.messages.get("evidence_labels", {}).get(
            "permit_root_login",
            "PermitRootLogin value in sshd_config"
        )

        result.add_evidence(
            key="permit_root_login",
            label=label,
            source=ssh_file.path,
            value=permit_value if permit_value is not None else "(not configured)",
            status="ok" if permit_value is not None else "manual",
            excerpt=permit_line
        )

        ssh_rule = self.policy.get("rules", {}).get("ssh_rule", {})
        acceptable_values = self._normalize_value_list(
            ssh_rule.get("acceptable_values", ["no"])
        )
        vulnerable_values = self._normalize_value_list(
            ssh_rule.get("vulnerable_values", ["yes"])
        )

        if permit_value is None:
            return "manual", "The SSH service is active, but PermitRootLogin is not configured, so the default value requires interpretation."

        normalized = permit_value.strip().lower()

        if normalized in acceptable_values:
            return "pass", (
                "SSH is active and PermitRootLogin={0}, so direct root login is blocked."
                .format(permit_value)
            )

        if normalized in vulnerable_values:
            return "fail", (
                "SSH is active and PermitRootLogin={0}, so direct root login is allowed."
                .format(permit_value)
            )

        return "manual", (
            "SSH is active and PermitRootLogin={0}, and the policy decision is unclear."
            .format(permit_value)
        )

    def _evaluate_telnet(self, result, telnet_in_use):
        if not telnet_in_use:
            return "not_used", "Telnet-family services are not active."

        login_file = self.file_reader.read("/etc/pam.d/login")
        securetty_file = self.file_reader.read("/etc/securetty")

        pam_label = self.messages.get("evidence_labels", {}).get(
            "pam_securetty",
            "Whether pam_securetty is applied in /etc/pam.d/login"
        )
        securetty_label = self.messages.get("evidence_labels", {}).get(
            "securetty_pts_entries",
            "Whether pts is allowed in /etc/securetty"
        )

        if login_file.success and login_file.content:
            pam_present, pam_line = self._contains_token_line(
                login_file.content,
                "pam_securetty"
            )
            result.add_evidence(
                key="pam_securetty",
                label=pam_label,
                source=login_file.path,
                value=pam_present,
                status="ok" if pam_present else "fail",
                excerpt=pam_line
            )
        else:
            result.add_evidence(
                key="pam_securetty",
                label=pam_label,
                source="/etc/pam.d/login",
                value="읽기 실패 또는 파일 없음",
                status="manual"
            )

        if securetty_file.success and securetty_file.content is not None:
            pts_entries = self._extract_pts_entries(securetty_file.content)
            result.add_evidence(
                key="securetty_pts_entries",
                label=securetty_label,
                source=securetty_file.path,
                value=pts_entries,
                status="fail" if pts_entries else "ok"
            )
        else:
            result.add_evidence(
                key="securetty_pts_entries",
                label=securetty_label,
                source="/etc/securetty",
                value="읽기 실패 또는 파일 없음",
                status="manual"
            )

        if (not login_file.success) or (not securetty_file.success):
            return "manual", "Telnet 계열 서비스는 활성 상태지만 /etc/pam.d/login 또는 /etc/securetty 확인이 필요합니다."

        pam_present, _unused = self._contains_token_line(
            login_file.content or "",
            "pam_securetty"
        )
        pts_entries = self._extract_pts_entries(securetty_file.content or "")

        if pam_present and not pts_entries:
            return "pass", "Telnet 계열 서비스 사용 시 pam_securetty 가 적용되어 있고 /etc/securetty 에 pts/* 허용 항목이 없습니다."

        return "fail", "Telnet 계열 서비스 사용 시 pam_securetty 미적용 또는 /etc/securetty 의 pts/* 허용 항목이 존재합니다."

    def _inspect_named_service(self, logical_name):
        service_target = self._find_service_target(logical_name)
        if service_target is None:
            return self.service_reader.inspect(logical_name)

        return self.service_reader.inspect(
            service_target.get("name", logical_name),
            aliases=service_target.get("aliases", [])
        )

    def _find_service_target(self, logical_name):
        for service in self.targets.get("services", []):
            if service.get("name") == logical_name:
                return service
        return None

    def _get_paths_by_parser(self, parser_name):
        paths = []
        files = self.targets.get("files", {})
        for section in ("required", "optional"):
            for item in files.get(section, []):
                if item.get("parser") == parser_name and item.get("path"):
                    paths.append(to_text(item["path"]))
        return paths

    def _read_first_readable(self, paths):
        for path in paths:
            result = self.file_reader.read(path)
            if result.success:
                return result

        for path in paths:
            inspected = self.file_reader.inspect(path)
            if inspected.metadata.exists:
                return self.file_reader.read(path)

        return None

    def _add_service_evidence(self, result, key, label, service_result):
        result.add_evidence(
            key=key,
            label=label,
            source=service_result.matched_name or service_result.query_name,
            value={
                "installed": service_result.installed,
                "enabled": service_result.enabled,
                "active": service_result.active,
                "load_state": service_result.load_state,
                "unit_file_state": service_result.unit_file_state,
                "active_state": service_result.active_state,
            },
            status="ok" if service_result.success else service_result.status,
            notes=service_result.message
        )

    def _add_file_evidence(self, result, key, label, source, value,
                           status="info", excerpt=None, notes=None):
        result.add_evidence(
            key=key,
            label=label,
            source=source,
            value=value,
            status=status,
            excerpt=excerpt,
            notes=notes
        )

    @staticmethod
    def _parse_sshd_key(content, key):
        key_lower = key.lower()
        found_value = None
        found_line = None

        for raw_line in content.splitlines():
            stripped = raw_line.strip()
            if (not stripped) or stripped.startswith("#"):
                continue

            no_inline_comment = re.sub(r"\s+#.*$", "", stripped).strip()
            parts = re.split(r"\s+", no_inline_comment, 1)
            if len(parts) < 2:
                continue

            current_key = parts[0].strip().lower()
            current_value = parts[1].strip()

            if current_key == key_lower:
                found_value = current_value
                found_line = raw_line.strip()

        return found_value, found_line

    @staticmethod
    def _contains_token_line(content, token):
        for raw_line in content.splitlines():
            stripped = raw_line.strip()
            if (not stripped) or stripped.startswith("#"):
                continue
            if token in stripped:
                return True, raw_line.strip()
        return False, None

    @staticmethod
    def _extract_pts_entries(content):
        entries = []
        for raw_line in content.splitlines():
            stripped = raw_line.strip()
            if (not stripped) or stripped.startswith("#"):
                continue
            if re.match(r"^pts(?:/|\d)", stripped):
                entries.append(stripped)
        return entries

    @staticmethod
    def _normalize_value_list(values):
        normalized = set()
        for value in values:
            normalized.add(to_text(value).strip().lower())
        return normalized

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
        return to_text(self.messages.get(section, {}).get(field, default))

    @staticmethod
    def _merge_detail(base_detail, reasons):
        filtered = []
        for reason in reasons:
            if reason and reason.strip():
                filtered.append(reason.strip())

        if not filtered:
            return base_detail.strip()

        merged = [base_detail.strip(), "", "Decision reasons:"]
        for reason in filtered:
            merged.append("- {0}".format(reason))
        return "\n".join(merged)

    def _build_error_result(self, message):
        result = CheckResult(
            code="U-01",
            name="Restrict Remote root Login",
            severity="high",
            category="account_management",
            status="ERROR",
            success=False,
            summary="An error occurred while running the check.",
            detail=message,
            requires_root="partial"
        )
        result.add_error(message)
        return result