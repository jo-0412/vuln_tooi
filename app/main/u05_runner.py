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
    U-05 root 이외의 UID가 0 금지 점검 실행기
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
                "설정 파일 로딩 실패: {0}".format(to_text(exc))
            )

        raw_steps = self.messages.get("remediation", {}).get("actions", [])
        remediation_steps = self._dedupe_keep_order(raw_steps)

        result = CheckResult(
            code=self.metadata.get("code", "U-05"),
            name=self.metadata.get("name", "root 이외의 UID가 0 금지"),
            severity=self.metadata.get("severity", "high"),
            category=self.metadata.get("category", "account_management"),
            status="MANUAL",
            success=True,
            summary=self._get_message("manual", "summary", default="자동 판정이 어렵습니다."),
            detail=self._get_message("manual", "detail", default="추가 확인이 필요합니다."),
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
            result.add_error("/etc/passwd 파일을 읽지 못했습니다.")
            result.set_status("ERROR", success=False)
            result.summary = self._get_message(
                "error", "summary",
                default="점검 실행 중 오류가 발생했습니다."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "error", "detail",
                    default="필수 파일을 읽지 못했거나 점검에 필요한 정보 수집 중 오류가 발생했습니다."
                ),
                ["/etc/passwd 파일을 읽지 못해 UID 0 계정을 판정할 수 없습니다."]
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
            value=root_line if root_line is not None else "(root 계정 없음)",
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
                "/etc/passwd 내 형식이 비정상인 행이 존재합니다. (개수: {0})".format(
                    len(malformed_lines)
                )
            )

        if not root_found:
            result.set_status("MANUAL", success=True)
            result.summary = self._get_message(
                "manual", "summary",
                default="자동 판정이 어렵습니다."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "manual", "detail",
                    default="passwd 구조가 비정상적이거나 root 계정 식별이 어려워 추가 확인이 필요합니다."
                ),
                reasons + ["root 계정을 /etc/passwd 에서 찾지 못했습니다."]
            )
            return result

        if uid_zero_non_root_accounts:
            reasons.append(
                "root 외 UID 0 계정이 존재합니다: {0}".format(
                    ", ".join(uid_zero_non_root_accounts)
                )
            )
            result.set_status("FAIL", success=False)
            result.summary = self._get_message(
                "fail", "summary",
                default="root 외 UID가 0인 계정이 존재합니다."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "fail", "detail",
                    default="root 외에 UID 0 계정이 존재하여 숨은 관리자 계정으로 악용될 수 있고, 감사 추적도 어려워집니다."
                ),
                reasons
            )
            return result

        if uid_zero_accounts == ["root"]:
            result.set_status("PASS", success=True)
            result.summary = self._get_message(
                "pass", "summary",
                default="root 외 UID가 0인 계정이 존재하지 않습니다."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "pass", "detail",
                    default="UID가 0인 계정이 root 하나뿐이어서 숨은 관리자 계정에 의한 권한 위장 가능성이 낮습니다."
                ),
                ["UID가 0인 계정이 root 하나뿐입니다."]
            )
            return result

        if uid_zero_count == 0:
            result.set_status("MANUAL", success=True)
            result.summary = self._get_message(
                "manual", "summary",
                default="자동 판정이 어렵습니다."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "manual", "detail",
                    default="passwd 구조가 비정상적이거나 root 계정 식별이 어려워 추가 확인이 필요합니다."
                ),
                ["UID가 0인 계정을 찾지 못했습니다. passwd 구조를 확인해야 합니다."]
            )
            return result

        result.set_status("MANUAL", success=True)
        result.summary = self._get_message(
            "manual", "summary",
            default="자동 판정이 어렵습니다."
        )
        result.detail = self._merge_detail(
            self._get_message(
                "manual", "detail",
                default="추가 확인이 필요합니다."
            ),
            reasons if reasons else ["UID 0 계정 구조를 추가 확인해야 합니다."]
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
            code="U-05",
            name="root 이외의 UID가 0 금지",
            severity="high",
            category="account_management",
            status="ERROR",
            success=False,
            summary="점검 실행 중 오류가 발생했습니다.",
            detail=to_text(message),
            requires_root="partial"
        )
        result.add_error(to_text(message))
        return result