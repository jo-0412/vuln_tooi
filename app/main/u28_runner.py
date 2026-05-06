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
from app.collectors.network_policy_reader import NetworkPolicyReader
from app.models.check_result import CheckResult


class U28Runner(object):
    """
    U-28 Restrict Access by IP and Port 점검 실행기
    1차 구현:
    - hosts.allow / hosts.deny 규칙 흔적
    - iptables / firewalld / ufw 정책 흔적
    - sshd_config 의 Port / ListenAddress 제한 흔적
    - ss -lntup 결과 수집
    """

    def __init__(self, check_dir=None):
        self.app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.check_dir = check_dir or os.path.join(
            self.app_dir,
            "checks",
            "u28_ip_port_restriction"
        )
        self.reader = NetworkPolicyReader()

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
            code=self.metadata.get("code", "U-28"),
            name=self.metadata.get("name", "Restrict Access by IP and Port"),
            severity=self.metadata.get("severity", "high"),
            category=self.metadata.get("category", "network_security"),
            status="MANUAL",
            success=True,
            summary=self._get_message("manual", "summary", default="The access restriction policy requires additional verification."),
            detail=self._get_message("manual", "detail", default="Related settings or firewall traces exist, but additional review is required to verify whether allowed IP and port restrictions are sufficient."),
            requires_root=self.metadata.get("requires_root", "required"),
            remediation_summary=self.messages.get("remediation", {}).get("summary"),
            remediation_steps=remediation_steps
        )

        file_map = self._collect_files()
        command_map = self._collect_commands()

        result.raw["files"] = file_map
        result.raw["commands"] = command_map

        hosts_allow = file_map.get("/etc/hosts.allow")
        hosts_deny = file_map.get("/etc/hosts.deny")
        sshd_config = file_map.get("/etc/ssh/sshd_config")

        hosts_allow_exists = self._file_exists(hosts_allow)
        hosts_deny_exists = self._file_exists(hosts_deny)

        hosts_allow_rules = self._extract_rules_from_file(hosts_allow)
        hosts_deny_rules = self._extract_rules_from_file(hosts_deny)

        ssh_ports = []
        ssh_listen_addresses = []
        ssh_control_present = False

        if sshd_config and sshd_config.success and sshd_config.content:
            ssh_info = self.reader.parse_sshd_config(sshd_config.content)
            ssh_ports = ssh_info.get("ports", [])
            ssh_listen_addresses = ssh_info.get("listen_addresses", [])
            ssh_control_present = bool(ssh_listen_addresses) or self._has_non_default_ssh_port(ssh_ports)

        iptables_result = command_map.get("iptables_list")
        firewalld_result = command_map.get("firewalld_list")
        ufw_result = command_map.get("ufw_status")
        listening_result = command_map.get("listening_ports")

        iptables_policy_present = self._detect_iptables_policy(iptables_result)
        firewalld_policy_present = self._detect_firewalld_policy(firewalld_result)
        ufw_policy_present = self._detect_ufw_policy(ufw_result)

        firewall_policy_present = (
            iptables_policy_present or
            firewalld_policy_present or
            ufw_policy_present
        )

        listening_ports = []
        if listening_result and listening_result.get("status") == "ok":
            listening_ports = self.reader.parse_listening_ports(
                listening_result.get("stdout", "")
            )

        tcp_wrapper_control_present = self._detect_tcp_wrapper_control(
            hosts_allow_rules,
            hosts_deny_rules
        )

        result.add_evidence(
            key="hosts_allow_exists",
            label=self._label("hosts_allow_exists"),
            source="/etc/hosts.allow",
            value=hosts_allow_exists,
            status="ok" if hosts_allow_exists else "info"
        )

        result.add_evidence(
            key="hosts_deny_exists",
            label=self._label("hosts_deny_exists"),
            source="/etc/hosts.deny",
            value=hosts_deny_exists,
            status="ok" if hosts_deny_exists else "info"
        )

        result.add_evidence(
            key="hosts_allow_rules",
            label=self._label("hosts_allow_rules"),
            source="/etc/hosts.allow",
            value=hosts_allow_rules,
            status="ok" if hosts_allow_rules else "info"
        )

        result.add_evidence(
            key="hosts_deny_rules",
            label=self._label("hosts_deny_rules"),
            source="/etc/hosts.deny",
            value=hosts_deny_rules,
            status="ok" if hosts_deny_rules else "info"
        )

        result.add_evidence(
            key="iptables_policy_present",
            label=self._label("iptables_policy_present"),
            source="iptables -L",
            value=iptables_policy_present,
            status="ok" if iptables_policy_present else "info",
            notes=self._command_note(iptables_result)
        )

        result.add_evidence(
            key="firewalld_policy_present",
            label=self._label("firewalld_policy_present"),
            source="firewall-cmd --list-all",
            value=firewalld_policy_present,
            status="ok" if firewalld_policy_present else "info",
            notes=self._command_note(firewalld_result)
        )

        result.add_evidence(
            key="ufw_policy_present",
            label=self._label("ufw_policy_present"),
            source="ufw status numbered",
            value=ufw_policy_present,
            status="ok" if ufw_policy_present else "info",
            notes=self._command_note(ufw_result)
        )

        result.add_evidence(
            key="ssh_port",
            label=self._label("ssh_port"),
            source="/etc/ssh/sshd_config",
            value=ssh_ports if ssh_ports else ["(not configured)"],
            status="ok" if ssh_ports else "info"
        )

        result.add_evidence(
            key="ssh_listen_address",
            label=self._label("ssh_listen_address"),
            source="/etc/ssh/sshd_config",
            value=ssh_listen_addresses if ssh_listen_addresses else ["(not configured)"],
            status="ok" if ssh_listen_addresses else "info"
        )

        result.add_evidence(
            key="listening_ports",
            label=self._label("listening_ports"),
            source="ss -lntup",
            value=listening_ports,
            status="ok" if listening_ports else "info",
            notes=self._command_note(listening_result)
        )

        reasons = []

        if tcp_wrapper_control_present:
            reasons.append("Service access restriction rules exist in hosts.allow or hosts.deny.")

        if iptables_policy_present:
            reasons.append("iptables policy traces were found.")

        if firewalld_policy_present:
            reasons.append("firewalld policy traces were found.")

        if ufw_policy_present:
            reasons.append("UFW policy traces were found.")

        if ssh_control_present:
            if ssh_listen_addresses:
                reasons.append("ListenAddress restriction is configured in sshd_config.")
            elif ssh_ports:
                reasons.append("A non-default SSH port setting exists in sshd_config.")

        alt_platform_present = self._has_alt_platform_files(file_map)
        if alt_platform_present and not (tcp_wrapper_control_present or firewall_policy_present or ssh_control_present):
            result.set_status("MANUAL", success=True)
            result.summary = self._get_message(
                "manual", "summary",
                default="The access restriction policy requires additional verification."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "manual", "detail",
                    default="Related settings or firewall traces exist, but additional review is required to verify whether allowed IP and port restrictions are sufficient."
                ),
                ["Alternative access control files outside standard Linux files exist, so manual verification is required."]
            )
            return result

        collectable = self._has_any_collectable_evidence(file_map, command_map)
        control_found = tcp_wrapper_control_present or firewall_policy_present or ssh_control_present

        if control_found:
            result.set_status("PASS", success=True)
            result.summary = self._get_message(
                "pass", "summary",
                default="An access IP or port restriction policy was found."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "pass",
                    "detail",
                    default="Policy traces restricting access to allowed hosts or ports were found, so external service exposure is controlled."
                ),
                reasons
            )
            return result

        if collectable:
            fail_reasons = [
                "Allowed IP or allowed port restriction policy traces were not found."
            ]

            if not hosts_allow_rules and not hosts_deny_rules:
                fail_reasons.append("No valid rules exist in hosts.allow / hosts.deny.")

            if not firewall_policy_present:
                fail_reasons.append("iptables, firewalld, or UFW policy traces were not found.")

            if not ssh_control_present:
                fail_reasons.append("No ListenAddress or non-default port restriction traces exist in sshd_config.")

            result.set_status("FAIL", success=False)
            result.summary = self._get_message(
                "fail", "summary",
                default="No access IP or port restriction policy was found."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "fail",
                    "detail",
                    default="Services are exposed without allowed IP restrictions, so unauthorized access may occur through vulnerable services such as SSH, FTP, or Telnet."
                ),
                fail_reasons
            )
            return result

        result.set_status("ERROR", success=False)
        result.summary = self._get_message(
            "error", "summary",
            default="An error occurred while running the check."
        )
        result.detail = self._merge_detail(
            self._get_message(
                "error", "detail",
                default="An error occurred while collecting access control files or firewall policies."
            ),
            ["Access-control-related files and command results could not be collected sufficiently."]
        )
        return result

    def _collect_files(self):
        collected = {}
        for item in self.targets.get("files", {}).get("optional", []):
            path = to_text(item.get("path", "")).strip()
            if not path:
                continue
            collected[path] = self.reader.read_file(path)
        return collected

    def _collect_commands(self):
        collected = {}
        for item in self.targets.get("commands", []):
            name = to_text(item.get("name", "")).strip()
            command = to_text(item.get("command", "")).strip()
            if not name or not command:
                continue
            collected[name] = self.reader.run_command(command)
        return collected

    @staticmethod
    def _file_exists(file_result):
        if file_result is None:
            return False
        return bool(file_result.metadata.exists)

    def _extract_rules_from_file(self, file_result):
        if file_result is None or (not file_result.success) or (not file_result.content):
            return []
        return self.reader.extract_active_lines(file_result.content)

    @staticmethod
    def _has_non_default_ssh_port(ports):
        for port in ports:
            if to_text(port).strip() and to_text(port).strip() != "22":
                return True
        return False

    def _detect_tcp_wrapper_control(self, allow_rules, deny_rules):
        if allow_rules:
            for line in allow_rules:
                if ":" in to_text(line):
                    return True

        if deny_rules:
            for line in deny_rules:
                if ":" in to_text(line):
                    return True

        return False

    def _detect_iptables_policy(self, command_result):
        if not command_result or command_result.get("status") != "ok":
            return False

        stdout = to_text(command_result.get("stdout", ""))
        patterns = self.policy.get("rules", {}).get("firewall_rule", {}).get(
            "policy_presence_patterns", {}
        ).get("iptables", [])

        if self.reader.has_any_pattern(stdout, patterns):
            return True

        return False

    def _detect_firewalld_policy(self, command_result):
        if not command_result or command_result.get("status") != "ok":
            return False

        stdout = to_text(command_result.get("stdout", ""))
        lowered = stdout.lower()

        if "not running" in lowered:
            return False

        patterns = self.policy.get("rules", {}).get("firewall_rule", {}).get(
            "policy_presence_patterns", {}
        ).get("firewalld", [])

        if self.reader.has_any_pattern(stdout, patterns):
            return True

        return False

    def _detect_ufw_policy(self, command_result):
        if not command_result or command_result.get("status") != "ok":
            return False

        stdout = to_text(command_result.get("stdout", ""))
        patterns = self.policy.get("rules", {}).get("firewall_rule", {}).get(
            "policy_presence_patterns", {}
        ).get("ufw", [])

        if self.reader.has_any_pattern(stdout, patterns):
            return True

        return False

    @staticmethod
    def _command_note(command_result):
        if not command_result:
            return ""
        status = to_text(command_result.get("status", ""))
        return "{0} (rc={1})".format(
            status,
            command_result.get("returncode")
        )

    @staticmethod
    def _has_alt_platform_files(file_map):
        alt_paths = [
            "/etc/firewall/pf.conf",
            "/etc/ipf/ipf.conf",
            "/var/adm/inetd.sec",
        ]
        for path in alt_paths:
            file_result = file_map.get(path)
            if file_result and file_result.metadata.exists:
                return True
        return False

    @staticmethod
    def _has_any_collectable_evidence(file_map, command_map):
        for file_result in file_map.values():
            if file_result and file_result.metadata.exists:
                return True

        for cmd_result in command_map.values():
            if not cmd_result:
                continue
            if cmd_result.get("status") in ("ok", "error"):
                return True
            if cmd_result.get("available"):
                return True

        return False

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
            code="U-28",
            name="Restrict Access by IP and Port",
            severity="high",
            category="network_security",
            status="ERROR",
            success=False,
            summary="An error occurred while running the check.",
            detail=to_text(message),
            requires_root="required"
        )
        result.add_error(to_text(message))
        return result