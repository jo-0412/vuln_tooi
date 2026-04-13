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
    U-28 접속 IP 및 포트 제한 점검 실행기
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
                "설정 파일 로딩 실패: {0}".format(to_text(exc))
            )

        raw_steps = self.messages.get("remediation", {}).get("actions", [])
        remediation_steps = self._dedupe_keep_order(raw_steps)

        result = CheckResult(
            code=self.metadata.get("code", "U-28"),
            name=self.metadata.get("name", "접속 IP 및 포트 제한"),
            severity=self.metadata.get("severity", "high"),
            category=self.metadata.get("category", "network_security"),
            status="MANUAL",
            success=True,
            summary=self._get_message("manual", "summary", default="접속 제한 정책을 추가 확인해야 합니다."),
            detail=self._get_message("manual", "detail", default="관련 설정 또는 방화벽 흔적은 존재하지만 실제 허용 IP 및 포트 제한이 충분한지 추가 검토가 필요합니다."),
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
            value=ssh_ports if ssh_ports else ["(설정 없음)"],
            status="ok" if ssh_ports else "info"
        )

        result.add_evidence(
            key="ssh_listen_address",
            label=self._label("ssh_listen_address"),
            source="/etc/ssh/sshd_config",
            value=ssh_listen_addresses if ssh_listen_addresses else ["(설정 없음)"],
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
            reasons.append("hosts.allow 또는 hosts.deny 에 서비스 접근 제한 규칙이 존재합니다.")

        if iptables_policy_present:
            reasons.append("iptables 정책 흔적이 확인됩니다.")

        if firewalld_policy_present:
            reasons.append("firewalld 정책 흔적이 확인됩니다.")

        if ufw_policy_present:
            reasons.append("UFW 정책 흔적이 확인됩니다.")

        if ssh_control_present:
            if ssh_listen_addresses:
                reasons.append("sshd_config 에 ListenAddress 제한이 설정되어 있습니다.")
            elif ssh_ports:
                reasons.append("sshd_config 에 비기본 SSH 포트 설정이 존재합니다.")

        alt_platform_present = self._has_alt_platform_files(file_map)
        if alt_platform_present and not (tcp_wrapper_control_present or firewall_policy_present or ssh_control_present):
            result.set_status("MANUAL", success=True)
            result.summary = self._get_message(
                "manual", "summary",
                default="접속 제한 정책을 추가 확인해야 합니다."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "manual", "detail",
                    default="관련 설정 또는 방화벽 흔적은 존재하지만 실제 허용 IP 및 포트 제한이 충분한지 추가 검토가 필요합니다."
                ),
                ["Linux 표준 파일 외 대체 접근통제 파일이 존재하여 수동 확인이 필요합니다."]
            )
            return result

        collectable = self._has_any_collectable_evidence(file_map, command_map)
        control_found = tcp_wrapper_control_present or firewall_policy_present or ssh_control_present

        if control_found:
            result.set_status("PASS", success=True)
            result.summary = self._get_message(
                "pass", "summary",
                default="접속 IP 또는 포트 제한 정책이 확인됩니다."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "pass",
                    "detail",
                    default="허용된 호스트 또는 포트만 접근하도록 제한하는 정책 흔적이 확인되어 서비스 외부 노출 범위가 통제되고 있습니다."
                ),
                reasons
            )
            return result

        if collectable:
            fail_reasons = [
                "허용 IP 또는 허용 포트 제한 정책 흔적을 확인하지 못했습니다."
            ]

            if not hosts_allow_rules and not hosts_deny_rules:
                fail_reasons.append("hosts.allow / hosts.deny 에 유효 규칙이 없습니다.")

            if not firewall_policy_present:
                fail_reasons.append("iptables, firewalld, UFW 정책 흔적을 확인하지 못했습니다.")

            if not ssh_control_present:
                fail_reasons.append("sshd_config 에 ListenAddress 또는 비기본 포트 제한 흔적이 없습니다.")

            result.set_status("FAIL", success=False)
            result.summary = self._get_message(
                "fail", "summary",
                default="접속 IP 및 포트 제한 정책이 확인되지 않습니다."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "fail",
                    "detail",
                    default="서비스가 허용 IP 없이 전체에 노출되어 있어, SSH·FTP·Telnet 등 취약 서비스로 비인가 접근이 발생할 수 있습니다."
                ),
                fail_reasons
            )
            return result

        result.set_status("ERROR", success=False)
        result.summary = self._get_message(
            "error", "summary",
            default="점검 실행 중 오류가 발생했습니다."
        )
        result.detail = self._merge_detail(
            self._get_message(
                "error", "detail",
                default="접근 통제 파일 또는 방화벽 정책 수집 중 오류가 발생했습니다."
            ),
            ["접근 통제 관련 파일과 명령 결과를 충분히 수집하지 못했습니다."]
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
            code="U-28",
            name="접속 IP 및 포트 제한",
            severity="high",
            category="network_security",
            status="ERROR",
            success=False,
            summary="점검 실행 중 오류가 발생했습니다.",
            detail=to_text(message),
            requires_root="required"
        )
        result.add_error(to_text(message))
        return result