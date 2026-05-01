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


class U13Runner(object):
    """
    U-13 안전한 비밀번호 암호화 알고리즘 사용 점검 실행기

    주석/설명: 한국어
    사용자 출력: 영어
    Python 2.7 ~ 3.x 호환
    """

    def __init__(self, check_dir=None):
        self.app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.check_dir = check_dir or os.path.join(
            self.app_dir,
            "checks",
            "u13_password_hash_algorithm"
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
            code=self.metadata.get("code", "U-13"),
            name=self.metadata.get("name", "Use Secure Password Hashing Algorithm"),
            severity=self.metadata.get("severity", "high"),
            category=self.metadata.get("category", "account_management"),
            status="MANUAL",
            success=True,
            summary=self._get_message(
                "manual",
                "summary",
                default="Password hashing algorithm requires manual verification."
            ),
            detail=self._get_message(
                "manual",
                "detail",
                default="Some configuration or hash information could not be fully verified."
            ),
            requires_root=self.metadata.get("requires_root", "partial"),
            remediation_summary=self._get_remediation_summary(),
            remediation_steps=self._get_remediation_steps()
        )

        shadow_file = self.reader.read_file("/etc/shadow")
        login_defs_file = self.reader.read_file("/etc/login.defs")
        system_auth_file = self.reader.read_file("/etc/pam.d/system-auth")
        common_password_file = self.reader.read_file("/etc/pam.d/common-password")

        result.raw["files"] = {
            "/etc/shadow": shadow_file.to_dict() if shadow_file else None,
            "/etc/login.defs": login_defs_file.to_dict() if login_defs_file else None,
            "/etc/pam.d/system-auth": system_auth_file.to_dict() if system_auth_file else None,
            "/etc/pam.d/common-password": common_password_file.to_dict() if common_password_file else None,
        }

        hash_prefix_map = self._get_hash_prefix_map()
        secure_algorithms = self._get_secure_algorithms()
        weak_algorithms = self._get_weak_algorithms()
        ignored_markers = self._get_ignored_password_markers()

        secure_pam_options = self._get_secure_pam_options()
        weak_pam_options = self._get_weak_pam_options()
        accepted_encrypt_methods = self._get_accepted_encrypt_methods()
        weak_encrypt_methods = self._get_weak_encrypt_methods()

        shadow_exists = self.reader.file_exists(shadow_file)
        shadow_readable = bool(shadow_file and shadow_file.success and shadow_file.content)

        shadow_info = {
            "accounts": [],
            "hash_prefixes": [],
            "algorithms": [],
        }

        if shadow_readable:
            shadow_info = self.reader.parse_shadow_hashes(
                shadow_file.content,
                hash_prefix_map=hash_prefix_map,
                ignored_markers=ignored_markers
            )

        active_hash_accounts = []
        weak_hash_accounts = []

        for account in shadow_info.get("accounts", []):
            if not account.get("active"):
                continue

            active_hash_accounts.append(account)

            algorithm = to_text(account.get("algorithm", "")).lower()
            if algorithm in weak_algorithms or algorithm == "unknown":
                weak_hash_accounts.append(account)

        detected_algorithms = shadow_info.get("algorithms", [])
        shadow_hash_prefixes = shadow_info.get("hash_prefixes", [])

        login_defs_exists = self.reader.file_exists(login_defs_file)
        login_defs_info = {
            "encrypt_method": "",
            "matched_line": "",
            "active_lines": [],
        }

        if login_defs_exists and login_defs_file and login_defs_file.success and login_defs_file.content:
            login_defs_info = self.reader.parse_login_defs_encrypt_method(
                login_defs_file.content
            )

        encrypt_method = to_text(login_defs_info.get("encrypt_method", "")).upper()
        encrypt_method_secure = encrypt_method in accepted_encrypt_methods
        encrypt_method_weak = encrypt_method in weak_encrypt_methods

        pam_infos = []
        pam_detected_options = []
        pam_secure_options = []
        pam_weak_options = []
        pam_matched_lines = []

        pam_targets = [
            ("/etc/pam.d/system-auth", system_auth_file),
            ("/etc/pam.d/common-password", common_password_file),
        ]

        for path, file_result in pam_targets:
            if not self.reader.file_exists(file_result):
                continue

            if not file_result.success or not file_result.content:
                continue

            pam_info = self.reader.parse_pam_unix_hash_options(
                file_result.content,
                secure_options=secure_pam_options,
                weak_options=weak_pam_options
            )

            pam_info["path"] = path
            pam_infos.append(pam_info)

            for item in pam_info.get("detected_options", []):
                pam_detected_options.append(item)

            for item in pam_info.get("secure_options", []):
                pam_secure_options.append(item)

            for item in pam_info.get("weak_options", []):
                pam_weak_options.append(item)

            for line in pam_info.get("matched_lines", []):
                pam_matched_lines.append(path + ": " + line)

        pam_detected_options = self._dedupe_keep_order(pam_detected_options)
        pam_secure_options = self._dedupe_keep_order(pam_secure_options)
        pam_weak_options = self._dedupe_keep_order(pam_weak_options)
        pam_matched_lines = self._dedupe_keep_order(pam_matched_lines)

        result.raw["parsed"] = {
            "shadow_exists": shadow_exists,
            "shadow_readable": shadow_readable,
            "shadow_info": shadow_info,
            "login_defs_info": login_defs_info,
            "pam_infos": pam_infos,
            "weak_hash_accounts": weak_hash_accounts,
            "detected_algorithms": detected_algorithms,
            "pam_detected_options": pam_detected_options,
        }

        result.add_evidence(
            key="shadow_file_exists",
            label=self._label("shadow_file_exists", "/etc/shadow exists"),
            source="/etc/shadow",
            value=shadow_exists,
            status="ok" if shadow_exists else "manual"
        )

        result.add_evidence(
            key="shadow_hash_prefixes",
            label=self._label("shadow_hash_prefixes", "Password hash prefixes"),
            source="/etc/shadow",
            value=shadow_hash_prefixes if shadow_hash_prefixes else ["(not detected)"],
            status="ok" if shadow_hash_prefixes else ("manual" if not shadow_readable else "info")
        )

        result.add_evidence(
            key="detected_hash_algorithms",
            label=self._label("detected_hash_algorithms", "Detected password hash algorithms"),
            source="/etc/shadow",
            value=detected_algorithms if detected_algorithms else ["(not detected)"],
            status="ok" if detected_algorithms else ("manual" if not shadow_readable else "info")
        )

        result.add_evidence(
            key="weak_hash_accounts",
            label=self._label("weak_hash_accounts", "Accounts using weak password hashes"),
            source="/etc/shadow",
            value=[self._shadow_account_brief(acc) for acc in weak_hash_accounts],
            status="fail" if weak_hash_accounts else ("ok" if shadow_readable else "manual"),
            notes="count={0}".format(len(weak_hash_accounts))
        )

        result.add_evidence(
            key="login_defs_encrypt_method",
            label=self._label("login_defs_encrypt_method", "ENCRYPT_METHOD value"),
            source="/etc/login.defs",
            value=encrypt_method if encrypt_method else "(not configured)",
            status="ok" if encrypt_method_secure else ("fail" if encrypt_method_weak else "manual"),
            excerpt=to_text(login_defs_info.get("matched_line", ""))
        )

        result.add_evidence(
            key="pam_unix_hash_options",
            label=self._label("pam_unix_hash_options", "pam_unix.so hash options"),
            source="PAM password files",
            value={
                "detected_options": pam_detected_options if pam_detected_options else ["(not detected)"],
                "secure_options": pam_secure_options,
                "weak_options": pam_weak_options,
                "matched_lines": pam_matched_lines,
            },
            status="fail" if pam_weak_options else ("ok" if pam_secure_options else "manual")
        )

        effective_policy = self._build_effective_policy(
            shadow_readable,
            detected_algorithms,
            weak_hash_accounts,
            encrypt_method,
            pam_secure_options,
            pam_weak_options
        )

        result.add_evidence(
            key="effective_password_hash_policy",
            label=self._label("effective_password_hash_policy", "Effective password hash policy"),
            source="/etc/shadow, /etc/login.defs, PAM",
            value=effective_policy,
            status="fail" if effective_policy.get("weak_detected") else (
                "ok" if effective_policy.get("secure_detected") else "manual"
            )
        )

        reasons = []

        if shadow_readable:
            if weak_hash_accounts:
                reasons.append(
                    "One or more active accounts use weak password hashes."
                )
            elif active_hash_accounts:
                reasons.append(
                    "Active password hashes were checked and no weak hash was detected."
                )
            else:
                reasons.append(
                    "/etc/shadow was readable, but no active password hashes were detected."
                )
        else:
            reasons.append(
                "/etc/shadow could not be fully read, so actual password hashes require manual verification."
            )

        if encrypt_method:
            reasons.append(
                "ENCRYPT_METHOD is configured as {0}.".format(encrypt_method)
            )
        else:
            reasons.append(
                "ENCRYPT_METHOD was not configured in /etc/login.defs."
            )

        if pam_secure_options:
            reasons.append(
                "Secure pam_unix.so hash options were detected: {0}".format(
                    ", ".join(pam_secure_options)
                )
            )

        if pam_weak_options:
            reasons.append(
                "Weak pam_unix.so hash options were detected: {0}".format(
                    ", ".join(pam_weak_options)
                )
            )

        if weak_hash_accounts or encrypt_method_weak or pam_weak_options:
            result.set_status("FAIL", success=False)
            result.summary = self._get_message(
                "fail",
                "summary",
                default="Weak password hashing algorithms were detected."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "fail",
                    "detail",
                    default="Weak password hashing algorithms may allow attackers to crack leaked password hashes more easily."
                ),
                reasons
            )
            return result

        if shadow_readable and active_hash_accounts:
            # 실제 shadow 값이 가장 강한 증적이다.
            if self._all_algorithms_secure(detected_algorithms, secure_algorithms):
                result.set_status("PASS", success=True)
                result.summary = self._get_message(
                    "pass",
                    "summary",
                    default="Secure password hashing algorithms are being used."
                )
                result.detail = self._merge_detail(
                    self._get_message(
                        "pass",
                        "detail",
                        default="Password hashes and related configuration indicate that secure algorithms are used."
                    ),
                    reasons
                )
                return result

        if encrypt_method_secure or pam_secure_options:
            result.set_status("MANUAL", success=True)
            result.summary = self._get_message(
                "manual",
                "summary",
                default="Password hashing algorithm requires manual verification."
            )
            result.detail = self._merge_detail(
                self._get_message(
                    "manual",
                    "detail",
                    default="Some configuration appears secure, but actual password hashes could not be fully verified."
                ),
                reasons
            )
            return result

        result.set_status("MANUAL", success=True)
        result.summary = self._get_message(
            "manual",
            "summary",
            default="Password hashing algorithm requires manual verification."
        )
        result.detail = self._merge_detail(
            self._get_message(
                "manual",
                "detail",
                default="The effective password hashing algorithm could not be fully determined."
            ),
            reasons
        )
        return result

    def _get_hash_prefix_map(self):
        rule = self.policy.get("rules", {}).get("shadow_hash_rule", {})
        return rule.get("hash_prefix_map", {
            "$1$": "md5",
            "$5$": "sha256",
            "$6$": "sha512",
            "$y$": "yescrypt",
        })

    def _get_secure_algorithms(self):
        rule = self.policy.get("rules", {}).get("shadow_hash_rule", {})
        return self._normalize_lower_list(
            rule.get("secure_algorithms", ["sha256", "sha512", "yescrypt", "bcrypt"])
        )

    def _get_weak_algorithms(self):
        rule = self.policy.get("rules", {}).get("shadow_hash_rule", {})
        return self._normalize_lower_list(
            rule.get("weak_algorithms", ["des", "md5"])
        )

    def _get_ignored_password_markers(self):
        rule = self.policy.get("rules", {}).get("shadow_hash_rule", {})
        return self._normalize_text_list(
            rule.get("ignored_password_markers", ["!", "*", "!!", "x", ""])
        )

    def _get_accepted_encrypt_methods(self):
        rule = self.policy.get("rules", {}).get("login_defs_rule", {})
        values = rule.get("accepted_encrypt_methods", ["SHA256", "SHA512", "YESCRYPT", "BCRYPT"])
        return self._normalize_upper_list(values)

    def _get_weak_encrypt_methods(self):
        rule = self.policy.get("rules", {}).get("login_defs_rule", {})
        values = rule.get("weak_encrypt_methods", ["MD5", "DES"])
        return self._normalize_upper_list(values)

    def _get_secure_pam_options(self):
        rule = self.policy.get("rules", {}).get("pam_hash_rule", {})
        values = rule.get("secure_options", ["sha256", "sha512", "yescrypt", "bcrypt"])
        return self._normalize_lower_list(values)

    def _get_weak_pam_options(self):
        rule = self.policy.get("rules", {}).get("pam_hash_rule", {})
        values = rule.get("weak_options", ["md5", "bigcrypt", "crypt"])
        return self._normalize_lower_list(values)

    @staticmethod
    def _all_algorithms_secure(algorithms, secure_algorithms):
        if not algorithms:
            return False

        secure_set = set(secure_algorithms)

        for algorithm in algorithms:
            if to_text(algorithm).lower() not in secure_set:
                return False

        return True

    @staticmethod
    def _shadow_account_brief(account):
        return {
            "username": to_text(account.get("username", "")),
            "hash_prefix": to_text(account.get("hash_prefix", "")),
            "algorithm": to_text(account.get("algorithm", "")),
            "password_field_preview": to_text(account.get("password_field_preview", "")),
        }

    @staticmethod
    def _build_effective_policy(shadow_readable, detected_algorithms, weak_hash_accounts,
                                encrypt_method, pam_secure_options, pam_weak_options):
        weak_detected = bool(weak_hash_accounts or pam_weak_options)
        secure_detected = bool(detected_algorithms or encrypt_method or pam_secure_options)

        return {
            "shadow_readable": shadow_readable,
            "detected_algorithms": detected_algorithms,
            "weak_hash_account_count": len(weak_hash_accounts),
            "login_defs_encrypt_method": encrypt_method if encrypt_method else "(not configured)",
            "pam_secure_options": pam_secure_options,
            "pam_weak_options": pam_weak_options,
            "secure_detected": secure_detected,
            "weak_detected": weak_detected,
        }

    @staticmethod
    def _normalize_text_list(values):
        result = []
        for item in values or []:
            text = to_text(item).strip()
            if text:
                result.append(text)
        return result

    @staticmethod
    def _normalize_lower_list(values):
        result = []
        for item in values or []:
            text = to_text(item).strip().lower()
            if text:
                result.append(text)
        return result

    @staticmethod
    def _normalize_upper_list(values):
        result = []
        for item in values or []:
            text = to_text(item).strip().upper()
            if text:
                result.append(text)
        return result

    @staticmethod
    def _dedupe_keep_order(items):
        seen = set()
        result = []

        for item in items or []:
            text = to_text(item).strip()
            if not text:
                continue

            if text not in seen:
                seen.add(text)
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
                    "Configure the system to use a secure password hashing algorithm."
                )
            )
        return "Configure the system to use a secure password hashing algorithm."

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
            code="U-13",
            name="Use Secure Password Hashing Algorithm",
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