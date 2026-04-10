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


class U18Runner(object):
    """
    U-18 /etc/shadow 파일 소유자 및 권한 설정 점검 실행기
    """

    def __init__(self, check_dir=None):
        self.app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.check_dir = check_dir or os.path.join(
            self.app_dir,
            "checks",
            "u18_shadow_file_permissions"
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
                "설정 파일 로딩 실패: {0}".format(to_text(exc))
            )

        raw_steps = self.messages.get("remediation", {}).get("actions", [])
        remediation_steps = self._dedupe_keep_order(raw_steps)

        result = CheckResult(
            code=self.metadata.get("code", "U-18"),
            name=self.metadata.get("name", "/etc/shadow 파일 소유자 및 권한 설정"),
            severity=self.metadata.get("severity", "high"),
            category=self.metadata.get("category", "account_management"),
            status="MANUAL",
            success=True,
            summary=self._get_message("manual", "summary", default="자동 판정이 어렵습니다."),
            detail=self._get_message("manual", "detail", default="추가 확인이 필요합니다."),
            requires_root=self.metadata.get("requires_root", "required"),
            remediation_summary=self.messages.get("remediation", {}).get("summary"),
            remediation_steps=remediation_steps
        )

        shadow_path = "/etc/shadow"
        aix_path = "/etc/security/passwd"
        trusted_mode_path = "/tcb/files/auth"

        shadow_inspect = self.file_reader.inspect(shadow_path)
        shadow_exists = bool(shadow_inspect and shadow_inspect.metadata.exists)

        aix_exists = os.path.exists(aix_path)
        trusted_mode_exists = os.path.exists(trusted_mode_path)

        result.raw["files"] = {
            "shadow": shadow_inspect.to_dict() if shadow_inspect else None,
            "aix_passwd_exists": aix_exists,
            "trusted_mode_path_exists": trusted_mode_exists,
        }

        self._add_bool_evidence(
            result,
            key="shadow_exists",
            source=shadow_path,
            value=shadow_exists,
            status="ok" if shadow_exists else "manual"
        )

        self._add_bool_evidence(
            result,
            key="aix_passwd_exists",
            source=aix_path,
            value=aix_exists,
            status="info" if not aix_exists else "ok"
        )

        self._add_bool_evidence(
            result,
            key="trusted_mode_path_exists",
            source=trusted_mode_path,
            value=trusted_mode_exists,
            status="info" if not trusted_mode_exists else "ok"
        )

        if not shadow_exists:
            reasons = []

            if aix_exists or trusted_mode_exists:
                reasons.append("Linux 표준 경로(/etc/shadow)는 없지만 플랫폼별 대체 저장 경로가 존재합니다.")
            else:
                reasons.append("/etc/shadow 파일을 찾지 못했습니다.")

            result.set_status("MANUAL", success=True)
            result.summary = self._get_message(
                "manual", "summary",
                default="자동 판정이 어렵습니다."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "manual", "detail",
                    default="Linux 표준 경로가 아니거나 플랫폼별 대체 저장 구조가 확인되어 추가 확인이 필요합니다."
                ),
                reasons
            )
            return result

        shadow_stat = self._get_file_stat(shadow_path)
        if shadow_stat is None:
            result.add_error("/etc/shadow 파일 메타데이터를 확인하지 못했습니다.")
            result.set_status("ERROR", success=False)
            result.summary = self._get_message(
                "error", "summary",
                default="점검 실행 중 오류가 발생했습니다."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "error", "detail",
                    default="필수 파일 확인 또는 메타데이터 수집 중 오류가 발생했습니다."
                ),
                ["/etc/shadow 파일 메타데이터를 수집할 수 없습니다."]
            )
            return result

        owner_uid = shadow_stat.get("uid")
        group_gid = shadow_stat.get("gid")
        mode_int = shadow_stat.get("mode_int")
        mode_octal = shadow_stat.get("mode_octal")

        owner_constraint = self._get_owner_constraint()
        mode_constraint = self._get_mode_constraint()

        owner_ok = self._evaluate_constraint(owner_uid, owner_constraint)
        mode_ok = self._evaluate_mode_constraint(mode_int, mode_constraint)

        result.add_evidence(
            key="shadow_owner_uid",
            label=self._label("shadow_owner_uid"),
            source=shadow_path,
            value=owner_uid,
            status="ok" if owner_ok else "fail"
        )

        result.add_evidence(
            key="shadow_group_gid",
            label=self._label("shadow_group_gid"),
            source=shadow_path,
            value=group_gid,
            status="info"
        )

        result.add_evidence(
            key="shadow_mode",
            label=self._label("shadow_mode"),
            source=shadow_path,
            value=mode_octal,
            status="ok" if mode_ok else "fail"
        )

        result.raw["shadow_stat"] = shadow_stat

        reasons = []

        if not owner_ok:
            reasons.append(
                "/etc/shadow 소유자 UID가 기준을 충족하지 않습니다. (현재: {0}, 기준: {1} {2})".format(
                    owner_uid,
                    to_text(owner_constraint.get("operator", "==")),
                    owner_constraint.get("value")
                )
            )

        if not mode_ok:
            reasons.append(
                "/etc/shadow 권한이 기준을 초과합니다. (현재: {0}, 기준: <= {1})".format(
                    mode_octal,
                    mode_constraint.get("value")
                )
            )

        if owner_ok and mode_ok:
            result.set_status("PASS", success=True)
            result.summary = self._get_message(
                "pass", "summary",
                default="/etc/shadow 파일의 소유자 및 권한이 적절합니다."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "pass", "detail",
                    default="비밀번호 해시 파일이 관리자만 제어할 수 있도록 보호되고 있어 비인가자의 접근 및 변조 위험이 낮습니다."
                ),
                [
                    "/etc/shadow 소유자 UID가 root(0)입니다.",
                    "/etc/shadow 권한이 {0} 이며 기준(<= {1})을 충족합니다.".format(
                        mode_octal,
                        mode_constraint.get("value")
                    )
                ]
            )
            return result

        result.set_status("FAIL", success=False)
        result.summary = self._get_message(
            "fail", "summary",
            default="/etc/shadow 파일의 소유자 또는 권한 설정이 미흡합니다."
        )
        result.detail = self._merge_detail(
            self._get_message(
                "fail", "detail",
                default="비밀번호 해시 파일 권한이 과도하거나 소유자가 부적절하여 비인가자가 해시를 수집해 크래킹 공격을 시도할 수 있습니다."
            ),
            reasons
        )
        return result

    def _get_file_stat(self, path):
        try:
            st = os.lstat(path)
            mode_int = st.st_mode & 0o777
            return {
                "uid": st.st_uid,
                "gid": st.st_gid,
                "mode_int": mode_int,
                "mode_octal": "%04o" % mode_int,
            }
        except Exception:
            return None

    def _get_owner_constraint(self):
        rule = self.policy.get("rules", {}).get("shadow_permission_rule", {})
        return rule.get("shadow_requirements", {}).get("owner_uid", {
            "operator": "==",
            "value": 0,
        })

    def _get_mode_constraint(self):
        rule = self.policy.get("rules", {}).get("shadow_permission_rule", {})
        return rule.get("shadow_requirements", {}).get("max_mode_octal", {
            "value": "0400",
        })

    def _evaluate_constraint(self, current, constraint):
        if current is None:
            return False

        operator = to_text(constraint.get("operator", "==")).strip()
        expected = constraint.get("value")

        if operator == "==":
            return current == expected
        if operator == "!=":
            return current != expected
        if operator == ">=":
            return current >= expected
        if operator == "<=":
            return current <= expected
        if operator == ">":
            return current > expected
        if operator == "<":
            return current < expected
        return False

    def _evaluate_mode_constraint(self, current_mode_int, constraint):
        if current_mode_int is None:
            return False

        max_mode_text = to_text(constraint.get("value", "0400")).strip()
        try:
            max_mode_int = int(max_mode_text, 8)
        except Exception:
            return False

        return current_mode_int <= max_mode_int

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
            code="U-18",
            name="/etc/shadow 파일 소유자 및 권한 설정",
            severity="high",
            category="account_management",
            status="ERROR",
            success=False,
            summary="점검 실행 중 오류가 발생했습니다.",
            detail=to_text(message),
            requires_root="required"
        )
        result.add_error(to_text(message))
        return result