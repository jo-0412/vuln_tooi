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
from app.collectors.account_policy_reader import AccountPolicyReader
from app.models.check_result import CheckResult


class U06Runner(object):
    """
    U-06 사용자 계정 su 기능 제한 점검 실행기

    판정 기준 개요:
    1) /etc/group 에 wheel 그룹이 존재하는지 확인
    2) /etc/pam.d/su 가 존재하면 PAM 방식으로 pam_wheel 적용 여부를 우선 판정
    3) PAM 파일이 없으면 /usr/bin/su 그룹/권한으로 비PAM 방식 판정
    """

    def __init__(self, check_dir=None):
        self.app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.check_dir = check_dir or os.path.join(
            self.app_dir,
            "checks",
            "u06_su_restriction"
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

        raw_steps = self.messages.get("remediation", {}).get("actions", [])
        remediation_steps = self._dedupe_keep_order(raw_steps)

        result = CheckResult(
            code=self.metadata.get("code", "U-06"),
            name=self.metadata.get("name", "Restrict su Command Usage to Authorized Accounts"),
            severity=self.metadata.get("severity", "high"),
            category=self.metadata.get("category", "account_management"),
            status="MANUAL",
            success=True,
            summary=self._get_message(
                "manual",
                "summary",
                default="The su restriction policy requires manual verification."
            ),
            detail=self._get_message(
                "manual",
                "detail",
                default="Some related settings are present, but additional manual verification is required."
            ),
            requires_root=self.metadata.get("requires_root", "partial"),
            remediation_summary=self.messages.get("remediation", {}).get("summary"),
            remediation_steps=remediation_steps
        )

        # 1. 필수/선택 파일 읽기
        group_file = self.reader.read_file("/etc/group")
        pam_file = self.reader.read_file("/etc/pam.d/su")
        su_stat = self.reader.inspect_file("/usr/bin/su")

        result.raw["group_file"] = group_file.to_dict() if group_file else None
        result.raw["pam_file"] = pam_file.to_dict() if pam_file else None
        result.raw["su_stat"] = su_stat

        # 2. 필수 파일 존재 여부 확인
        if not self.reader.file_exists(group_file):
            return self._build_missing_required_result(
                result,
                "/etc/group is missing or could not be read."
            )

        if not su_stat.get("exists"):
            return self._build_missing_required_result(
                result,
                "/usr/bin/su is missing or could not be inspected."
            )

        # 3. 정책 기준 읽기
        allowed_group_names = self._get_allowed_group_names()
        required_su_group_names = self._get_required_su_group_names()
        required_su_mode = self._get_required_su_mode()

        accepted_patterns = self._get_pam_accepted_patterns()
        accepted_modules = self._get_pam_accepted_modules()

        # 4. 그룹 파일 파싱
        group_info = self.reader.parse_group_file(group_file.content)
        groups = group_info.get("groups", [])

        allowed_group = self.reader.find_group(groups, allowed_group_names)
        wheel_group_exists = bool(allowed_group)
        wheel_group_members = []
        wheel_group_excerpt = ""

        if allowed_group:
            wheel_group_members = allowed_group.get("members", [])
            wheel_group_excerpt = to_text(allowed_group.get("raw_line", ""))

        # 5. PAM 파일 파싱
        pam_su_file_exists = self.reader.file_exists(pam_file)
        pam_wheel_enabled = False
        pam_wheel_mode = ""
        pam_excerpt = ""
        pam_module_found = False

        if pam_su_file_exists and pam_file and pam_file.success and pam_file.content:
            pam_info = self.reader.parse_su_pam(
                pam_file.content,
                accepted_patterns=accepted_patterns,
                accepted_modules=accepted_modules
            )
            pam_wheel_enabled = bool(pam_info.get("pam_wheel_enabled"))
            pam_wheel_mode = to_text(pam_info.get("pam_wheel_mode", ""))
            pam_excerpt = to_text(pam_info.get("matched_line", ""))
            pam_module_found = bool(pam_info.get("module_found"))

            result.raw["pam_info"] = pam_info

        # 6. su 실행 파일 메타데이터 확인
        su_binary_exists = bool(su_stat.get("exists"))
        su_binary_group = to_text(su_stat.get("group_name", ""))
        su_binary_mode = to_text(su_stat.get("mode_octal", ""))
        su_binary_group_ok = self.reader.is_group_allowed(
            su_binary_group,
            required_su_group_names
        )
        su_binary_mode_ok = self.reader.is_mode_at_most(
            su_binary_mode,
            required_su_mode
        )

        # 7. 제한 방식 판정
        restriction_method = "none"
        reasons = []

        if pam_su_file_exists:
            # PAM 파일이 있으면 PAM 방식 판정을 우선한다.
            if wheel_group_exists and pam_wheel_enabled:
                restriction_method = "pam"
                reasons.append("The authorized su group exists.")
                reasons.append("The PAM configuration for su includes pam_wheel.so.")
                if pam_wheel_mode:
                    reasons.append(
                        "The detected PAM restriction mode is '{0}'.".format(
                            pam_wheel_mode
                        )
                    )

                result.set_status("PASS", success=True)
                result.summary = self._get_message(
                    "pass",
                    "summary",
                    default="The use of the su command is restricted to an authorized group."
                )
                result.detail = self._merge_detail(
                    self._get_message(
                        "pass",
                        "detail",
                        default="The configuration confirms that su command usage is limited to an authorized group."
                    ),
                    reasons
                )
            else:
                restriction_method = "pam_not_enforced"
                if not wheel_group_exists:
                    reasons.append(
                        "The authorized su group '{0}' does not exist.".format(
                            allowed_group_names[0] if allowed_group_names else "wheel"
                        )
                    )
                if not pam_wheel_enabled:
                    if pam_module_found:
                        reasons.append(
                            "pam_wheel.so was found, but the required PAM pattern was not matched."
                        )
                    else:
                        reasons.append(
                            "The PAM configuration for su does not include a valid pam_wheel.so rule."
                        )

                result.set_status("FAIL", success=False)
                result.summary = self._get_message(
                    "fail",
                    "summary",
                    default="The su command is not adequately restricted."
                )
                result.detail = self._merge_detail(
                    self._get_message(
                        "fail",
                        "detail",
                        default="Ordinary users may be able to use the su command without proper restriction."
                    ),
                    reasons
                )
        else:
            # PAM 파일이 없으면 실행 파일 그룹/권한 기반으로 판정한다.
            if wheel_group_exists and su_binary_group_ok and su_binary_mode_ok:
                restriction_method = "binary_permission"
                reasons.append("The authorized su group exists.")
                reasons.append(
                    "/usr/bin/su belongs to the authorized group '{0}'.".format(
                        su_binary_group
                    )
                )
                reasons.append(
                    "/usr/bin/su permission is restricted to {0}, which meets the required maximum of {1}.".format(
                        su_binary_mode,
                        required_su_mode
                    )
                )

                result.set_status("PASS", success=True)
                result.summary = self._get_message(
                    "pass",
                    "summary",
                    default="The use of the su command is restricted to an authorized group."
                )
                result.detail = self._merge_detail(
                    self._get_message(
                        "pass",
                        "detail",
                        default="The configuration confirms that su command usage is limited to an authorized group."
                    ),
                    reasons
                )
            else:
                restriction_method = "binary_not_enforced"
                reasons.append(
                    "The PAM configuration file for su is missing, so binary-based restriction was evaluated."
                )

                if not wheel_group_exists:
                    reasons.append(
                        "The authorized su group '{0}' does not exist.".format(
                            allowed_group_names[0] if allowed_group_names else "wheel"
                        )
                    )
                if not su_binary_group_ok:
                    reasons.append(
                        "/usr/bin/su is not assigned to the required group. Current group: {0}".format(
                            su_binary_group or "(unknown)"
                        )
                    )
                if not su_binary_mode_ok:
                    reasons.append(
                        "/usr/bin/su permission is not restricted enough. Current mode: {0}, required maximum: {1}".format(
                            su_binary_mode or "(unknown)",
                            required_su_mode
                        )
                    )

                result.set_status("FAIL", success=False)
                result.summary = self._get_message(
                    "fail",
                    "summary",
                    default="The su command is not adequately restricted."
                )
                result.detail = self._merge_detail(
                    self._get_message(
                        "fail",
                        "detail",
                        default="Ordinary users may be able to use the su command without proper restriction."
                    ),
                    reasons
                )

        # 8. 증적 추가
        result.add_evidence(
            key="wheel_group_exists",
            label=self._label("wheel_group_exists"),
            source="/etc/group",
            value=wheel_group_exists,
            status="ok" if wheel_group_exists else "fail",
            excerpt=wheel_group_excerpt
        )

        result.add_evidence(
            key="wheel_group_members",
            label=self._label("wheel_group_members"),
            source="/etc/group",
            value=wheel_group_members if wheel_group_members else ["(none)"],
            status="ok" if wheel_group_exists else "fail",
            excerpt=wheel_group_excerpt
        )

        result.add_evidence(
            key="pam_su_file_exists",
            label=self._label("pam_su_file_exists"),
            source="/etc/pam.d/su",
            value=pam_su_file_exists,
            status="ok" if pam_su_file_exists else "manual"
        )

        result.add_evidence(
            key="pam_wheel_enabled",
            label=self._label("pam_wheel_enabled"),
            source="/etc/pam.d/su",
            value=pam_wheel_enabled,
            status="ok" if pam_wheel_enabled else ("fail" if pam_su_file_exists else "manual"),
            excerpt=pam_excerpt
        )

        result.add_evidence(
            key="pam_wheel_mode",
            label=self._label("pam_wheel_mode"),
            source="/etc/pam.d/su",
            value=pam_wheel_mode if pam_wheel_mode else "(not detected)",
            status="ok" if pam_wheel_enabled else ("fail" if pam_su_file_exists else "manual"),
            excerpt=pam_excerpt
        )

        result.add_evidence(
            key="su_binary_exists",
            label=self._label("su_binary_exists"),
            source="/usr/bin/su",
            value=su_binary_exists,
            status="ok" if su_binary_exists else "fail"
        )

        result.add_evidence(
            key="su_binary_group",
            label=self._label("su_binary_group"),
            source="/usr/bin/su",
            value=su_binary_group if su_binary_group else "(unknown)",
            status="ok" if su_binary_group_ok else "fail"
        )

        result.add_evidence(
            key="su_binary_mode",
            label=self._label("su_binary_mode"),
            source="/usr/bin/su",
            value=su_binary_mode if su_binary_mode else "(unknown)",
            status="ok" if su_binary_mode_ok else "fail"
        )

        result.add_evidence(
            key="su_restriction_method",
            label=self._label("su_restriction_method"),
            source="/etc/pam.d/su, /usr/bin/su",
            value=restriction_method,
            status="ok" if result.status == "PASS" else ("fail" if result.status == "FAIL" else "manual")
        )

        result.raw["parsed"] = {
            "allowed_group_names": allowed_group_names,
            "required_su_group_names": required_su_group_names,
            "required_su_mode": required_su_mode,
            "wheel_group_exists": wheel_group_exists,
            "wheel_group_members": wheel_group_members,
            "pam_su_file_exists": pam_su_file_exists,
            "pam_wheel_enabled": pam_wheel_enabled,
            "pam_wheel_mode": pam_wheel_mode,
            "su_binary_group": su_binary_group,
            "su_binary_mode": su_binary_mode,
            "restriction_method": restriction_method,
        }

        return result

    def _get_allowed_group_names(self):
        rule = self.policy.get("rules", {}).get("pam_restriction_rule", {})
        values = rule.get("group_requirements", {}).get("allowed_group_names", ["wheel"])
        return self._normalize_text_list(values, default=["wheel"])

    def _get_required_su_group_names(self):
        rule = self.policy.get("rules", {}).get("binary_permission_rule", {})
        values = rule.get("su_binary_requirements", {}).get("allowed_group_names", ["wheel"])
        return self._normalize_text_list(values, default=["wheel"])

    def _get_required_su_mode(self):
        rule = self.policy.get("rules", {}).get("binary_permission_rule", {})
        value = rule.get("su_binary_requirements", {}).get("max_mode_octal", "4750")
        return to_text(value).strip() or "4750"

    def _get_pam_accepted_patterns(self):
        rule = self.policy.get("rules", {}).get("pam_restriction_rule", {})
        values = rule.get("pam_requirements", {}).get("accepted_patterns", [])
        return self._normalize_text_list(values, default=[])

    def _get_pam_accepted_modules(self):
        rule = self.policy.get("rules", {}).get("pam_restriction_rule", {})
        values = rule.get("pam_requirements", {}).get("accepted_modules", ["pam_wheel.so"])
        return self._normalize_text_list(values, default=["pam_wheel.so"])

    @staticmethod
    def _normalize_text_list(values, default=None):
        result = []
        for item in values or []:
            text = to_text(item).strip()
            if text:
                result.append(text)

        if result:
            return result

        return list(default or [])

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

    def _build_missing_required_result(self, base_result, reason):
        base_result.set_status("ERROR", success=False)
        base_result.summary = self._get_message(
            "error",
            "summary",
            default="An error occurred while running the check."
        )
        base_result.detail = self._merge_detail(
            self._get_message(
                "error",
                "detail",
                default="An error occurred while collecting files or metadata related to su access control."
            ),
            [reason]
        )
        base_result.add_error(reason)
        return base_result

    def _build_error_result(self, message):
        result = CheckResult(
            code="U-06",
            name="Restrict su Command Usage to Authorized Accounts",
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