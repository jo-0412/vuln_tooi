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
from app.collectors.package_update_reader import PackageUpdateReader
from app.models.check_result import CheckResult


class U64Runner(object):
    """
    U-64 Apply Periodic Security Patches and Vendor Advisories 점검 실행기
    1차 구현:
    - 자동 업데이트 설정 흔적
    - 최근 패치 이력/로그 흔적
    - 패치 상태 확인 가능 여부
    """

    def __init__(self, check_dir=None):
        self.app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.check_dir = check_dir or os.path.join(
            self.app_dir,
            "checks",
            "u64_security_patch_management"
        )
        self.reader = PackageUpdateReader()

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
            code=self.metadata.get("code", "U-64"),
            name=self.metadata.get("name", "Apply Periodic Security Patches and Vendor Advisories"),
            severity=self.metadata.get("severity", "high"),
            category=self.metadata.get("category", "patch_management"),
            status="MANUAL",
            success=True,
            summary=self._get_message("manual", "summary", default="Patch management status requires additional verification."),
            detail=self._get_message("manual", "detail", default="Some settings or logs exist, but additional review is required to verify whether they are actually managed according to a periodic security patch policy."),
            requires_root=self.metadata.get("requires_root", "required"),
            remediation_summary=self.messages.get("remediation", {}).get("summary"),
            remediation_steps=remediation_steps
        )

        file_map = self._collect_files()
        command_map = self._collect_commands()

        result.raw["files"] = self._serialize_file_map(file_map)
        result.raw["commands"] = command_map

        auto_file = file_map.get("/etc/apt/apt.conf.d/20auto-upgrades")
        unattended_file = file_map.get("/etc/apt/apt.conf.d/50unattended-upgrades")
        history_file = file_map.get("/var/log/apt/history.log")
        unattended_log_file = file_map.get("/var/log/unattended-upgrades/unattended-upgrades.log")

        auto_exists = self._file_exists(auto_file)
        unattended_exists = self._file_exists(unattended_file)
        unattended_log_exists = self._file_exists(unattended_log_file)

        auto_info = {
            "active_lines": [],
            "update_package_lists_enabled": False,
            "unattended_upgrade_enabled": False,
        }
        if auto_file and auto_file.success and auto_file.content:
            auto_info = self.reader.parse_auto_upgrade_config(auto_file.content)

        unattended_info = {
            "active_lines": [],
            "policy_lines": [],
            "policy_present": False,
        }
        if unattended_file and unattended_file.success and unattended_file.content:
            unattended_info = self.reader.parse_unattended_upgrade_config(unattended_file.content)

        grep_auto_result = command_map.get("grep_auto_upgrade")
        grep_auto_present = False
        if grep_auto_result and grep_auto_result.get("status") == "ok":
            grep_auto_present = bool(to_text(grep_auto_result.get("stdout", "")).strip())

        auto_upgrade_enabled = (
            auto_info.get("update_package_lists_enabled", False) or
            auto_info.get("unattended_upgrade_enabled", False) or
            unattended_info.get("policy_present", False) or
            grep_auto_present
        )

        recent_patch_history_present = False
        if history_file and history_file.success and history_file.content:
            recent_patch_history_present = self.reader.has_patch_history(history_file.content)

        unattended_log_present = False
        if unattended_log_file and unattended_log_file.success and unattended_log_file.content:
            unattended_log_present = self.reader.has_patch_history(unattended_log_file.content)

        hostnamectl_result = command_map.get("hostnamectl")
        uname_result = command_map.get("uname_kernel")
        apt_upgradable_result = command_map.get("apt_upgradable")
        dpkg_unattended_result = command_map.get("dpkg_unattended")

        os_version_info = {}
        if hostnamectl_result and hostnamectl_result.get("status") == "ok":
            os_version_info = self.reader.parse_hostnamectl(
                hostnamectl_result.get("stdout", "")
            )

        kernel_version = ""
        if uname_result and uname_result.get("status") == "ok":
            kernel_version = self.reader.parse_uname_kernel(
                uname_result.get("stdout", "")
            )

        upgradable_packages = []
        if apt_upgradable_result and apt_upgradable_result.get("status") in ("ok", "error"):
            upgradable_packages = self.reader.parse_apt_upgradable(
                apt_upgradable_result.get("stdout", ""),
                apt_upgradable_result.get("stderr", "")
            )

        upgradable_package_count = len(upgradable_packages)

        unattended_installed = False
        if dpkg_unattended_result and dpkg_unattended_result.get("status") in ("ok", "error"):
            unattended_installed = self.reader.detect_unattended_installed(
                dpkg_unattended_result.get("stdout", ""),
                dpkg_unattended_result.get("stderr", "")
            )

        result.add_evidence(
            key="auto_upgrade_config_exists",
            label=self._label("auto_upgrade_config_exists"),
            source="/etc/apt/apt.conf.d/20auto-upgrades",
            value=auto_exists,
            status="ok" if auto_exists else "info"
        )

        result.add_evidence(
            key="unattended_upgrade_config_exists",
            label=self._label("unattended_upgrade_config_exists"),
            source="/etc/apt/apt.conf.d/50unattended-upgrades",
            value=unattended_exists,
            status="ok" if unattended_exists else "info"
        )

        result.add_evidence(
            key="auto_upgrade_enabled",
            label=self._label("auto_upgrade_enabled"),
            source="/etc/apt/apt.conf.d/20auto-upgrades",
            value={
                "enabled": auto_upgrade_enabled,
                "update_package_lists_enabled": auto_info.get("update_package_lists_enabled", False),
                "unattended_upgrade_enabled": auto_info.get("unattended_upgrade_enabled", False),
                "policy_present": unattended_info.get("policy_present", False),
            },
            status="ok" if auto_upgrade_enabled else "fail"
        )

        result.add_evidence(
            key="unattended_installed",
            label=self._label("unattended_installed"),
            source="dpkg -l unattended-upgrades",
            value=unattended_installed,
            status="ok" if unattended_installed else "info",
            notes=self._command_note(dpkg_unattended_result)
        )

        result.add_evidence(
            key="recent_patch_history_present",
            label=self._label("recent_patch_history_present"),
            source="/var/log/apt/history.log",
            value=recent_patch_history_present,
            status="ok" if recent_patch_history_present else "fail"
        )

        result.add_evidence(
            key="unattended_log_present",
            label=self._label("unattended_log_present"),
            source="/var/log/unattended-upgrades/unattended-upgrades.log",
            value=unattended_log_present if unattended_log_exists else False,
            status="ok" if unattended_log_present else ("info" if unattended_log_exists else "info")
        )

        result.add_evidence(
            key="upgradable_packages",
            label=self._label("upgradable_packages"),
            source="apt list --upgradable",
            value=upgradable_packages,
            status="ok" if apt_upgradable_result and apt_upgradable_result.get("status") in ("ok", "error") else "info",
            notes=self._command_note(apt_upgradable_result)
        )

        result.add_evidence(
            key="upgradable_package_count",
            label=self._label("upgradable_package_count"),
            source="apt list --upgradable",
            value=upgradable_package_count,
            status="info"
        )

        result.add_evidence(
            key="os_version_info",
            label=self._label("os_version_info"),
            source="hostnamectl",
            value=os_version_info if os_version_info else {"raw": "(collection failed or command unavailable)"},
            status="ok" if os_version_info else "info",
            notes=self._command_note(hostnamectl_result)
        )

        result.add_evidence(
            key="kernel_version",
            label=self._label("kernel_version"),
            source="uname -r",
            value=kernel_version if kernel_version else "(collection failed or command unavailable)",
            status="ok" if kernel_version else "info",
            notes=self._command_note(uname_result)
        )

        config_signal = bool(auto_upgrade_enabled)
        history_signal = bool(recent_patch_history_present or unattended_log_present)
        status_signal = bool(unattended_installed or (apt_upgradable_result and apt_upgradable_result.get("status") in ("ok", "error")))

        positive_signals = 0
        if config_signal:
            positive_signals += 1
        if history_signal:
            positive_signals += 1
        if status_signal:
            positive_signals += 1

        reasons = []

        if config_signal:
            reasons.append("Automatic update or patch configuration traces were found.")
        else:
            reasons.append("Automatic update or patch configuration traces could not be sufficiently verified.")

        if history_signal:
            reasons.append("Recent patch history or automatic update logs were found.")
        else:
            reasons.append("Recent patch history or automatic update logs were not found.")

        if status_signal:
            reasons.append("Package status or patch management tool traces were found.")
        else:
            reasons.append("Package status or patch management tool traces could not be sufficiently verified.")

        if upgradable_package_count > 0:
            reasons.append("There are currently {0} upgradeable packages.".format(upgradable_package_count))

        minimum_positive_signals = self._get_minimum_positive_signals()

        collectable = self._has_any_collectable_evidence(file_map, command_map)
        if not collectable:
            result.set_status("ERROR", success=False)
            result.summary = self._get_message(
                "error", "summary",
                default="An error occurred while running the check."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "error", "detail",
                    default="An error occurred while collecting patch configuration files or package status."
                ),
                ["Patch-management-related files and command results could not be collected sufficiently."]
            )
            return result

        if positive_signals >= minimum_positive_signals:
            result.set_status("PASS", success=True)
            result.summary = self._get_message(
                "pass", "summary",
                default="Periodic security patch management traces were found."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "pass",
                    "detail",
                    default="Some automatic update settings, recent patch history, or patch management tool traces were found, indicating that security patches are managed at least to a certain level."
                ),
                reasons
            )
            return result

        if positive_signals == 0:
            result.set_status("FAIL", success=False)
            result.summary = self._get_message(
                "fail", "summary",
                default="Periodic security patch management traces are insufficient."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "fail",
                    "detail",
                    default="Because the latest security patches are not applied, the likelihood of an incident exploiting already disclosed vulnerabilities is high."
                ),
                reasons
            )
            return result

        result.set_status("MANUAL", success=True)
        result.summary = self._get_message(
            "manual", "summary",
            default="Patch management status requires additional verification."
        )
        result.detail = self._merge_detail(
            self._get_message(
                "manual",
                "detail",
                default="Some settings or logs exist, but additional review is required to verify whether they are actually managed according to a periodic security patch policy."
            ),
            reasons
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

    @staticmethod
    def _serialize_file_map(file_map):
        result = {}
        for path, file_result in file_map.items():
            result[path] = file_result.to_dict() if file_result else None
        return result

    @staticmethod
    def _command_note(command_result):
        if not command_result:
            return ""
        status = to_text(command_result.get("status", ""))
        return "{0} (rc={1})".format(
            status,
            command_result.get("returncode")
        )

    def _get_minimum_positive_signals(self):
        thresholds = self.policy.get("thresholds", {})
        value = thresholds.get("minimum_positive_signals_for_pass", 2)
        try:
            return int(value)
        except Exception:
            return 2

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
            code="U-64",
            name="Apply Periodic Security Patches and Vendor Advisories",
            severity="high",
            category="patch_management",
            status="ERROR",
            success=False,
            summary="An error occurred while running the check.",
            detail=to_text(message),
            requires_root="required"
        )
        result.add_error(to_text(message))
        return result