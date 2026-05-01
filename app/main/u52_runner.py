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
from app.collectors.network_service_reader import NetworkServiceReader
from app.models.check_result import CheckResult


class U52Runner(object):
    """
    U-52 Telnet 서비스 비활성화 점검 실행기

    주석/설명: 한국어
    사용자 출력: 영어
    Python 2.7 ~ 3.x 호환

    기능:
    - /etc/inetd.conf 에서 Telnet 활성 엔트리 확인
    - /etc/xinetd.d/telnet 에서 disable 값 확인
    - systemd telnet service/socket active/enabled 상태 확인
    - Telnet이 inetd/xinetd/systemd 중 하나라도 활성화되어 있으면 FAIL
    - 설정 파일이 없고 서비스도 비활성 또는 미존재이면 PASS

    차별점:
    - U-36 r 서비스 점검과 같은 network_service_reader.py를 재사용한다.
    - U-36은 rsh/rlogin/rexec 여러 서비스를 보지만,
      U-52는 telnet/telnetd/in.telnetd 계열만 집중적으로 확인한다.
    """

    def __init__(self, check_dir=None):
        self.app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.check_dir = check_dir or os.path.join(
            self.app_dir,
            "checks",
            "u52_telnet_disabled"
        )

        self.reader = NetworkServiceReader()

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
            code=self.metadata.get("code", "U-52"),
            name=self.metadata.get("name", "Disable Telnet Service"),
            severity=self.metadata.get("severity", "high"),
            category=self.metadata.get("category", "service_management"),
            status="MANUAL",
            success=True,
            summary=self._get_message(
                "manual",
                "summary",
                default="Telnet service status requires manual verification."
            ),
            detail=self._get_message(
                "manual",
                "detail",
                default="Some Telnet-related configuration files or service states could not be fully verified."
            ),
            requires_root=self.metadata.get("requires_root", "partial"),
            remediation_summary=self._get_remediation_summary(),
            remediation_steps=self._get_remediation_steps()
        )

        files = self._collect_files()
        result.raw["files"] = self._serialize_file_map(files)

        inetd_info = self._check_inetd(files)
        xinetd_info = self._check_xinetd(files)
        systemd_info = self._check_systemd()

        result.raw["inetd_info"] = inetd_info
        result.raw["xinetd_info"] = xinetd_info
        result.raw["systemd_info"] = systemd_info

        active_telnet_services = []
        active_telnet_services.extend(inetd_info.get("active_services", []))
        active_telnet_services.extend(xinetd_info.get("active_services", []))
        active_telnet_services.extend(systemd_info.get("active_services", []))
        active_telnet_services = self._dedupe_keep_order(active_telnet_services)

        missing_optional_paths = self._collect_missing_optional_paths(files)
        missing_optional_paths = self._dedupe_keep_order(missing_optional_paths)

        manual_reasons = []
        manual_reasons.extend(xinetd_info.get("manual_reasons", []))
        manual_reasons.extend(systemd_info.get("manual_reasons", []))

        # 1. inetd 증적
        result.add_evidence(
            key="inetd_telnet_entries",
            label=self._label("inetd_telnet_entries", "Telnet entries in inetd.conf"),
            source="/etc/inetd.conf",
            value=inetd_info.get("active_entries", []) if inetd_info.get("active_entries", []) else ["(none)"],
            status="fail" if inetd_info.get("active_entries") else "ok"
        )

        # 2. xinetd 증적
        result.add_evidence(
            key="xinetd_telnet_entries",
            label=self._label("xinetd_telnet_entries", "Telnet entries in xinetd configuration"),
            source="/etc/xinetd.d/telnet",
            value=xinetd_info.get("items", []),
            status="fail" if xinetd_info.get("active_services") else (
                "manual" if xinetd_info.get("manual_reasons") else "ok"
            )
        )

        # 3. systemd 증적
        result.add_evidence(
            key="systemd_telnet_status",
            label=self._label("systemd_telnet_status", "Telnet service status from systemd"),
            source="systemd",
            value=systemd_info.get("items", []),
            status="fail" if systemd_info.get("active_services") else (
                "manual" if systemd_info.get("manual_reasons") else "ok"
            )
        )

        # 4. 활성 Telnet 서비스 증적
        result.add_evidence(
            key="active_telnet_services",
            label=self._label("active_telnet_services", "Active Telnet services"),
            source="inetd, xinetd, systemd",
            value=active_telnet_services if active_telnet_services else ["(none)"],
            status="fail" if active_telnet_services else "ok"
        )

        # 5. 누락된 선택 경로 증적
        result.add_evidence(
            key="missing_optional_paths",
            label=self._label("missing_optional_paths", "Missing optional paths"),
            source="Telnet related paths",
            value=missing_optional_paths if missing_optional_paths else ["(none)"],
            status="manual" if missing_optional_paths else "ok",
            notes="Missing Telnet configuration files are usually normal on modern Linux systems."
        )

        # 6. SSH 대체 사용 여부는 별도 확인 대상으로 남긴다.
        result.add_evidence(
            key="ssh_replacement_note",
            label=self._label("ssh_replacement_note", "SSH replacement verification"),
            source="manual",
            value="Verify that SSH is used instead of Telnet for secure remote administration.",
            status="manual"
        )

        reasons = []

        if active_telnet_services:
            reasons.append(
                "Active Telnet configuration or service state was detected: {0}".format(
                    ", ".join(active_telnet_services)
                )
            )

        if manual_reasons:
            reasons.extend(manual_reasons)

        if missing_optional_paths:
            reasons.append(
                "Some optional Telnet-related paths are missing, which is usually normal on modern Linux systems."
            )

        reasons.append(
            "SSH replacement usage should be verified separately if remote administration is required."
        )

        # Telnet이 하나라도 활성화되어 있으면 FAIL
        if active_telnet_services:
            result.set_status("FAIL", success=False)
            result.summary = self._get_message(
                "fail",
                "summary",
                default="Telnet service is enabled or running."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "fail",
                    "detail",
                    default="Telnet transmits usernames and passwords in plaintext, making it highly vulnerable to network sniffing and credential theft."
                ),
                reasons
            )
            return result

        # 상태 확인 자체가 불명확한 경우 MANUAL
        if manual_reasons:
            result.set_status("MANUAL", success=True)
            result.summary = self._get_message(
                "manual",
                "summary",
                default="Telnet service status requires manual verification."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "manual",
                    "detail",
                    default="Some Telnet-related configuration files or service states could not be fully verified."
                ),
                reasons
            )
            return result

        # Telnet 활성 흔적이 없으면 PASS
        result.set_status("PASS", success=True)
        result.summary = self._get_message(
            "pass",
            "summary",
            default="Telnet service is disabled."
        )
        result.detail = self._merge_detail(
            self._get_message(
                "pass",
                "detail",
                default="Telnet is not active in inetd, xinetd, or systemd configuration."
            ),
            ["No active Telnet service or socket was detected."]
        )
        return result

    def _collect_files(self):
        """
        targets.yaml에 정의된 선택 파일을 수집한다.
        """
        collected = {}

        for item in self.targets.get("files", {}).get("optional", []):
            path = to_text(item.get("path", "")).strip()

            if not path:
                continue

            collected[path] = self.reader.read_file(path)

        return collected

    def _check_inetd(self, files):
        """
        /etc/inetd.conf에서 Telnet 활성 라인을 확인한다.
        """
        rule = self.policy.get("rules", {}).get("inetd_rule", {})
        service_names = rule.get("service_names", ["telnet"])

        path = "/etc/inetd.conf"
        file_result = files.get(path)

        if not self.reader.file_exists(file_result):
            return {
                "exists": False,
                "active_entries": [],
                "active_services": [],
            }

        if not file_result.success or not file_result.content:
            return {
                "exists": True,
                "active_entries": [],
                "active_services": [],
                "manual_reasons": [
                    "inetd.conf exists but could not be fully read."
                ],
            }

        # network_service_reader의 기존 함수는 이름은 r 서비스용이지만
        # service_names를 받기 때문에 Telnet 탐지에도 재사용 가능하다.
        parsed = self.reader.parse_inetd_r_services(
            file_result.content,
            service_names=service_names
        )

        active_services = []
        for service in parsed.get("matched_services", []):
            active_services.append("inetd:{0}".format(service))

        return {
            "exists": True,
            "active_entries": parsed.get("active_entries", []),
            "active_services": active_services,
        }

    def _check_xinetd(self, files):
        """
        /etc/xinetd.d/telnet에서 disable 값을 확인한다.
        """
        rule = self.policy.get("rules", {}).get("xinetd_rule", {})
        target_file = to_text(rule.get("target_file", "/etc/xinetd.d/telnet")).strip()
        service_name = to_text(rule.get("service_name", "telnet")).strip()
        fail_values = self._normalize_lower_list(rule.get("fail_values", ["no"]))

        items = []
        active_services = []
        manual_reasons = []

        file_result = files.get(target_file)

        if not self.reader.file_exists(file_result):
            items.append({
                "path": target_file,
                "exists": False,
                "disable_value": "(missing)",
                "status": "not-found",
            })

            return {
                "items": items,
                "active_services": active_services,
                "manual_reasons": manual_reasons,
            }

        if not file_result.success or not file_result.content:
            items.append({
                "path": target_file,
                "exists": True,
                "disable_value": "(unreadable)",
                "status": "manual",
            })
            manual_reasons.append(
                "{0} exists but could not be fully read.".format(target_file)
            )

            return {
                "items": items,
                "active_services": active_services,
                "manual_reasons": manual_reasons,
            }

        parsed = self.reader.parse_xinetd_r_service(
            file_result.content,
            service_name=service_name
        )

        disable_value = to_text(parsed.get("disable_value", "")).lower()

        status = "ok"
        if disable_value in fail_values:
            status = "active"
            active_services.append("xinetd:{0}".format(service_name))
        elif not disable_value:
            status = "manual"
            manual_reasons.append(
                "{0} does not contain a clear disable value.".format(target_file)
            )

        items.append({
            "path": target_file,
            "exists": True,
            "service_name": service_name,
            "disable_value": disable_value if disable_value else "(not detected)",
            "matched_lines": parsed.get("matched_lines", []),
            "status": status,
        })

        return {
            "items": items,
            "active_services": active_services,
            "manual_reasons": manual_reasons,
        }

    def _check_systemd(self):
        """
        systemd에서 telnet 관련 service/socket 상태를 확인한다.
        """
        services = self.targets.get("services", [])

        items = []
        active_services = []
        manual_reasons = []

        for service in services:
            name = to_text(service.get("name", "")).strip()
            aliases = service.get("aliases", [])

            if not name:
                continue

            inspected = self.reader.inspect_systemd_service(
                name,
                aliases=aliases
            )

            items.append(inspected)

            if inspected.get("active") or inspected.get("enabled"):
                active_services.append("systemd:{0}".format(name))

            units = inspected.get("units", [])
            unknown_count = 0

            for unit in units:
                if (
                    unit.get("active_state") == "unknown" and
                    unit.get("enabled_state") == "unknown"
                ):
                    unknown_count += 1

            if unknown_count == len(units) and units:
                manual_reasons.append(
                    "systemd state for {0} could not be fully verified.".format(
                        name
                    )
                )

        return {
            "items": items,
            "active_services": active_services,
            "manual_reasons": manual_reasons,
        }

    @staticmethod
    def _serialize_file_map(file_map):
        result = {}

        for path, file_result in file_map.items():
            result[path] = file_result.to_dict() if file_result else None

        return result

    def _collect_missing_optional_paths(self, files):
        missing = []

        for path, file_result in files.items():
            if not self.reader.file_exists(file_result):
                missing.append(path)

        return missing

    @staticmethod
    def _normalize_lower_list(values):
        result = []

        for item in values or []:
            text = to_text(item).strip().lower()

            if text:
                result.append(text)

        return result

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
                    "Disable Telnet and use SSH for secure remote access."
                )
            )

        return "Disable Telnet and use SSH for secure remote access."

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
            code="U-52",
            name="Disable Telnet Service",
            severity="high",
            category="service_management",
            status="ERROR",
            success=False,
            summary="An error occurred while running the check.",
            detail=to_text(message),
            requires_root="partial"
        )
        result.add_error(to_text(message))
        return result