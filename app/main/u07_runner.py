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
from app.collectors.account_policy_reader import AccountPolicyReader
from app.models.check_result import CheckResult


class U07Runner(object):
    """
    U-07 불필요한 계정 제거 점검 실행기

    주석/설명: 한국어
    사용자 출력: 영어
    Python 2.7 ~ 3.x 호환
    """

    def __init__(self, check_dir=None):
        self.app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.check_dir = check_dir or os.path.join(
            self.app_dir,
            "checks",
            "u07_unnecessary_accounts"
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

        result = CheckResult(
            code=self.metadata.get("code", "U-07"),
            name=self.metadata.get("name", "Remove Unnecessary Accounts"),
            severity=self.metadata.get("severity", "high"),
            category=self.metadata.get("category", "account_management"),
            status="MANUAL",
            success=True,
            summary=self._get_message(
                "manual",
                "summary",
                default="Some accounts require manual verification."
            ),
            detail=self._get_message(
                "manual",
                "detail",
                default="Some accounts do not have login history and require manual verification."
            ),
            requires_root=self.metadata.get("requires_root", "partial"),
            remediation_summary=self._get_remediation_summary(),
            remediation_steps=self._get_remediation_steps()
        )

        # 1. /etc/passwd 읽기
        passwd_file = self.reader.read_file("/etc/passwd")

        result.raw["passwd_file"] = passwd_file.to_dict() if passwd_file else None

        if not self.reader.file_exists(passwd_file):
            return self._build_missing_required_result(
                result,
                "/etc/passwd is missing or could not be read."
            )

        # 2. passwd 파싱
        passwd_info = self.reader.parse_passwd_file(passwd_file.content)
        accounts = passwd_info.get("accounts", [])

        # 3. last 명령 실행 및 로그인 사용자 파싱
        last_output = self.reader.run_last()
        logged_in_users = self.reader.parse_last_output(last_output)

        # 4. 정책 기준 읽기
        account_policy = self._get_account_policy()

        # 5. 불필요 계정 탐지
        finding = self.reader.find_unnecessary_accounts(
            accounts,
            logged_in_users,
            account_policy
        )

        unnecessary_accounts = finding.get("unnecessary", [])
        no_login_accounts = finding.get("no_login", [])

        unnecessary_names = self._account_names(unnecessary_accounts)
        no_login_names = self._account_names(no_login_accounts)

        default_accounts = account_policy.get("default_accounts", [])
        exclude_accounts = account_policy.get("exclude_accounts", [])

        result.raw["parsed"] = {
            "account_count": len(accounts),
            "logged_in_users": logged_in_users,
            "default_accounts": default_accounts,
            "exclude_accounts": exclude_accounts,
            "unnecessary_accounts": unnecessary_accounts,
            "accounts_without_login_history": no_login_accounts,
        }

        # 6. Evidence 추가
        result.add_evidence(
            key="account_list",
            label=self._label("account_list", "Full account list"),
            source="/etc/passwd",
            value=[self._account_brief(acc) for acc in accounts],
            status="info",
            notes="count={0}".format(len(accounts))
        )

        result.add_evidence(
            key="default_account_candidates",
            label=self._label("default_account_candidates", "Default account candidates"),
            source="/etc/passwd",
            value=default_accounts,
            status="info"
        )

        result.add_evidence(
            key="recent_login_users",
            label=self._label("recent_login_users", "Users found in login history"),
            source="last",
            value=logged_in_users if logged_in_users else ["(none detected)"],
            status="ok" if logged_in_users else "manual"
        )

        result.add_evidence(
            key="unnecessary_accounts",
            label=self._label("unnecessary_accounts", "Unnecessary accounts"),
            source="/etc/passwd",
            value=[self._account_brief(acc) for acc in unnecessary_accounts],
            status="fail" if unnecessary_accounts else "ok",
            notes="count={0}".format(len(unnecessary_accounts))
        )

        result.add_evidence(
            key="accounts_without_login_history",
            label=self._label("accounts_without_login_history", "Accounts without login history"),
            source="/etc/passwd, last",
            value=[self._account_brief(acc) for acc in no_login_accounts],
            status="manual" if no_login_accounts else "ok",
            notes="count={0}".format(len(no_login_accounts))
        )

        result.add_evidence(
            key="deletion_candidate_accounts",
            label=self._label("deletion_candidate_accounts", "Deletion candidate accounts"),
            source="/etc/passwd",
            value=unnecessary_names if unnecessary_names else ["(none)"],
            status="fail" if unnecessary_names else "ok"
        )

        # 7. 최종 판정
        reasons = []

        if unnecessary_accounts:
            reasons.append(
                "Unnecessary or default accounts were found: {0}".format(
                    ", ".join(unnecessary_names)
                )
            )

        if no_login_accounts:
            reasons.append(
                "Some accounts have no login history and require manual review: {0}".format(
                    ", ".join(no_login_names[:10])
                )
            )

        if unnecessary_accounts:
            result.set_status("FAIL", success=False)
            result.summary = self._get_message(
                "fail",
                "summary",
                default="Unnecessary accounts were detected on the system."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "fail",
                    "detail",
                    default="Unnecessary accounts may increase the risk of unauthorized access or misuse."
                ),
                reasons
            )
            return result

        if no_login_accounts:
            result.set_status("MANUAL", success=True)
            result.summary = self._get_message(
                "manual",
                "summary",
                default="Some accounts require manual verification."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "manual",
                    "detail",
                    default="Some accounts do not have login history and require manual verification."
                ),
                reasons
            )
            return result

        result.set_status("PASS", success=True)
        result.summary = self._get_message(
            "pass",
            "summary",
            default="No unnecessary accounts were found."
        )
        result.detail = self._merge_detail(
            self._get_message(
                "pass",
                "detail",
                default="All accounts appear to be necessary and properly managed."
            ),
            ["No unnecessary default accounts were detected."]
        )
        return result

    def _get_account_policy(self):
        """
        policy.yaml에서 U-07 계정 판정 정책을 읽는다.
        """
        policy_block = self.policy.get("policy", {})
        unnecessary_policy = policy_block.get("unnecessary_accounts", {})

        default_accounts = unnecessary_policy.get("default_accounts", [])
        exclude_accounts = unnecessary_policy.get("exclude_accounts", [])

        return {
            "default_accounts": self._normalize_text_list(default_accounts),
            "exclude_accounts": self._normalize_text_list(exclude_accounts),
            "inactivity_threshold_days": unnecessary_policy.get(
                "inactivity_threshold_days",
                90
            )
        }

    @staticmethod
    def _account_names(accounts):
        names = []
        for acc in accounts:
            username = to_text(acc.get("username", "")).strip()
            if username:
                names.append(username)
        return names

    @staticmethod
    def _account_brief(account):
        return {
            "username": to_text(account.get("username", "")),
            "uid": account.get("uid"),
            "gid": account.get("gid"),
            "home": to_text(account.get("home", "")),
            "shell": to_text(account.get("shell", "")),
        }

    @staticmethod
    def _normalize_text_list(values):
        result = []
        for item in values or []:
            text = to_text(item).strip()
            if text:
                result.append(text)
        return result

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

    def _get_message(self, status, field, default=""):
        """
        messages.yaml 구조가 두 방식이어도 동작하게 처리한다.

        방식 1:
        pass:
          summary: ...

        방식 2:
        summary:
          pass: ...
        """
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
            return to_text(remediation.get("summary", "Remove unnecessary or unused accounts."))
        return "Remove unnecessary or unused accounts."

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
                default="An error occurred while collecting account information."
            ),
            [reason]
        )
        base_result.add_error(reason)
        return base_result

    def _build_error_result(self, message):
        result = CheckResult(
            code="U-07",
            name="Remove Unnecessary Accounts",
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