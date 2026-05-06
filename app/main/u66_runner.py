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
from app.collectors.logging_policy_reader import LoggingPolicyReader
from app.models.check_result import CheckResult


class U66Runner(object):
    """
    U-66 Configure System Logging According to Policy 점검 실행기
    1차 구현:
    - rsyslog/syslog 설정 흔적 확인
    - rsyslog/Whether the syslog service is active 확인
    - Whether major log files exist 확인
    """

    def __init__(self, check_dir=None):
        self.app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.check_dir = check_dir or os.path.join(
            self.app_dir,
            "checks",
            "u66_system_logging_policy"
        )
        self.reader = LoggingPolicyReader()

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
            code=self.metadata.get("code", "U-66"),
            name=self.metadata.get("name", "Configure System Logging According to Policy"),
            severity=self.metadata.get("severity", "high"),
            category=self.metadata.get("category", "logging_and_audit"),
            status="MANUAL",
            success=True,
            summary=self._get_message("manual", "summary", default="System logging policy compliance requires additional verification."),
            detail=self._get_message("manual", "detail", default="Some logging traces exist, but additional review is required to verify whether settings match organizational policy and whether actual operating policy documents exist."),
            requires_root=self.metadata.get("requires_root", "partial"),
            remediation_summary=self.messages.get("remediation", {}).get("summary"),
            remediation_steps=remediation_steps
        )

        file_map = self._collect_files()
        command_map = self._collect_commands()
        service_map = self._collect_services()

        result.raw["files"] = self._serialize_file_map(file_map)
        result.raw["commands"] = command_map
        result.raw["services"] = self._serialize_service_map(service_map)

        rsyslog_conf = file_map.get("/etc/rsyslog.conf")
        rsyslog_default_conf = file_map.get("/etc/rsyslog.d/default.conf")
        syslog_conf = file_map.get("/etc/syslog.conf")

        rsyslog_conf_exists = self.reader.file_exists(rsyslog_conf)
        syslog_conf_exists = self.reader.file_exists(syslog_conf)

        pattern_list = self._get_policy_patterns()

        policy_lines = []
        policy_lines.extend(self._extract_policy_lines(rsyslog_conf, pattern_list))
        policy_lines.extend(self._extract_policy_lines(rsyslog_default_conf, pattern_list))
        policy_lines.extend(self._extract_policy_lines(syslog_conf, pattern_list))
        policy_lines = self._dedupe_keep_order(policy_lines)

        rsyslog_service = service_map.get("rsyslog")
        syslog_service = service_map.get("syslog")

        rsyslog_service_active = self.reader.is_service_active(rsyslog_service)
        syslog_service_active = self.reader.is_service_active(syslog_service)

        major_log_paths = [
            "/var/log/syslog",
            "/var/log/messages",
            "/var/log/auth.log",
            "/var/log/secure",
        ]
        major_log_files = self._collect_major_log_files(file_map, major_log_paths)
        major_log_file_count = len(major_log_files)

        result.add_evidence(
            key="rsyslog_conf_exists",
            label=self._label("rsyslog_conf_exists"),
            source="/etc/rsyslog.conf",
            value=rsyslog_conf_exists,
            status="ok" if rsyslog_conf_exists else "info"
        )

        result.add_evidence(
            key="syslog_conf_exists",
            label=self._label("syslog_conf_exists"),
            source="/etc/syslog.conf",
            value=syslog_conf_exists,
            status="ok" if syslog_conf_exists else "info"
        )

        result.add_evidence(
            key="logging_policy_lines",
            label=self._label("logging_policy_lines"),
            source="rsyslog/syslog",
            value=policy_lines,
            status="ok" if policy_lines else "fail"
        )

        result.add_evidence(
            key="rsyslog_service_active",
            label=self._label("rsyslog_service_active"),
            source="rsyslog",
            value=rsyslog_service_active,
            status="ok" if rsyslog_service_active else "info",
            notes=self._service_note(rsyslog_service)
        )

        result.add_evidence(
            key="syslog_service_active",
            label=self._label("syslog_service_active"),
            source="syslog",
            value=syslog_service_active,
            status="ok" if syslog_service_active else "info",
            notes=self._service_note(syslog_service)
        )

        result.add_evidence(
            key="major_log_files",
            label=self._label("major_log_files"),
            source="/var/log/*",
            value=major_log_files,
            status="ok" if major_log_files else "fail"
        )

        result.add_evidence(
            key="major_log_file_count",
            label=self._label("major_log_file_count"),
            source="/var/log/*",
            value=major_log_file_count,
            status="info"
        )

        result.add_evidence(
            key="logging_policy_document_note",
            label=self._label("logging_policy_document_note"),
            source="manual",
            value="Organizational log policy documents require separate verification as operational evidence.",
            status="manual"
        )

        config_signal = bool(policy_lines)
        service_signal = bool(rsyslog_service_active or syslog_service_active)
        log_signal = bool(major_log_file_count > 0)

        positive_signals = 0
        if config_signal:
            positive_signals += 1
        if service_signal:
            positive_signals += 1
        if log_signal:
            positive_signals += 1

        reasons = []

        if config_signal:
            reasons.append("Active logging configuration traces were found in logging configuration files.")
        else:
            reasons.append("Valid active logging settings could not be sufficiently verified in logging configuration files.")

        if service_signal:
            if rsyslog_service_active:
                reasons.append("The rsyslog service is active.")
            if syslog_service_active:
                reasons.append("The syslog service is active.")
        else:
            reasons.append("The active status of rsyslog or syslog service could not be verified.")

        if log_signal:
            reasons.append("Major log files actually exist. (count: {0})".format(major_log_file_count))
        else:
            reasons.append("Major log file existence could not be verified.")

        minimum_positive_signals = self._get_minimum_positive_signals()
        collectable = self._has_any_collectable_evidence(file_map, command_map, service_map)

        if not collectable:
            result.set_status("ERROR", success=False)
            result.summary = self._get_message(
                "error", "summary",
                default="An error occurred while running the check."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "error", "detail",
                    default="An error occurred while collecting logging configuration files, service status, or log files."
                ),
                ["Information related to logging configuration and service status could not be collected sufficiently."]
            )
            return result

        if positive_signals >= minimum_positive_signals:
            result.set_status("PASS", success=True)
            result.summary = self._get_message(
                "pass", "summary",
                default="System logging configuration traces according to policy were found."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "pass",
                    "detail",
                    default="Some logging settings, service status, or major log files were found, indicating that the system logging structure is operating at least to a certain level."
                ),
                reasons
            )
            return result

        if positive_signals == 0:
            result.set_status("FAIL", success=False)
            result.summary = self._get_message(
                "fail", "summary",
                default="System logging configuration is insufficient or policy traces are lacking."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "fail",
                    "detail",
                    default="Because system logging is not configured or does not comply with policy, identifying causes and securing evidence during incidents is difficult."
                ),
                reasons
            )
            return result

        result.set_status("MANUAL", success=True)
        result.summary = self._get_message(
            "manual", "summary",
            default="System logging policy compliance requires additional verification."
        )
        result.detail = self._merge_detail(
            self._get_message(
                "manual",
                "detail",
                default="Some logging traces exist, but additional review is required to verify whether settings match organizational policy and whether actual operating policy documents exist."
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

    def _collect_services(self):
        return {
            "rsyslog": self.reader.inspect_service("rsyslog", aliases=["rsyslog.service"]),
            "syslog": self.reader.inspect_service("syslog", aliases=["syslog.service"]),
        }

    def _extract_policy_lines(self, file_result, patterns):
        if file_result is None or (not file_result.success) or (not file_result.content):
            return []

        active_lines = self.reader.extract_active_lines(file_result.content)
        return self.reader.filter_logging_policy_lines(active_lines, patterns)

    @staticmethod
    def _collect_major_log_files(file_map, candidate_paths):
        items = []

        for path in candidate_paths:
            file_result = file_map.get(path)
            if file_result and file_result.metadata.exists:
                items.append({
                    "path": path,
                    "exists": True
                })

        return items

    def _get_policy_patterns(self):
        rule = self.policy.get("rules", {}).get("logging_config_rule", {})
        return rule.get("policy_presence_patterns", [])

    def _get_minimum_positive_signals(self):
        thresholds = self.policy.get("thresholds", {})
        value = thresholds.get("minimum_positive_signals_for_pass", 2)
        try:
            return int(value)
        except Exception:
            return 2

    @staticmethod
    def _serialize_file_map(file_map):
        result = {}
        for path, file_result in file_map.items():
            result[path] = file_result.to_dict() if file_result else None
        return result

    @staticmethod
    def _serialize_service_map(service_map):
        result = {}
        for name, service_result in service_map.items():
            result[name] = service_result.to_dict() if service_result else None
        return result

    @staticmethod
    def _service_note(service_result):
        if service_result is None:
            return ""

        try:
            return "{0}: {1}".format(
                to_text(service_result.status),
                to_text(service_result.message)
            )
        except Exception:
            return ""

    @staticmethod
    def _has_any_collectable_evidence(file_map, command_map, service_map):
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

        for service_result in service_map.values():
            if service_result is not None:
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
            code="U-66",
            name="Configure System Logging According to Policy",
            severity="high",
            category="logging_and_audit",
            status="ERROR",
            success=False,
            summary="An error occurred while running the check.",
            detail=to_text(message),
            requires_root="partial"
        )
        result.add_error(to_text(message))
        return result