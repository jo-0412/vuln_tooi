# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

import io
import os
import subprocess

try:
    import yaml
except ImportError as exc:  # pragma: no cover
    yaml = None
    _yaml_import_error = exc
else:
    _yaml_import_error = None

from app.compat import to_text
from app.collectors.file_reader import FileReader
from app.collectors.pam_reader import PamReader
from app.models.check_result import CheckResult


class U03Runner(object):
    """
    U-03 계정 잠금 임계값 설정 점검 실행기
    """

    def __init__(self, check_dir=None):
        self.app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.check_dir = check_dir or os.path.join(
            self.app_dir,
            "checks",
            "u03_account_lockout"
        )
        self.file_reader = FileReader()
        self.pam_reader = PamReader()

        self.metadata = {}
        self.targets = {}
        self.policy = {}
        self.messages = {}

    def run(self):
        try:
            self._load_configs()
        except Exception as exc:
            return self._build_error_result(
                "설정 파일 로딩 실패: {0}".format(exc)
            )

        raw_steps = self.messages.get("remediation", {}).get("actions", [])
        remediation_steps = self._dedupe_keep_order(raw_steps)

        result = CheckResult(
            code=self.metadata.get("code", "U-03"),
            name=self.metadata.get("name", "계정 잠금 임계값 설정"),
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

        auth_paths = self._collect_rule_paths("auth_targets")
        account_paths = self._collect_rule_paths("account_targets")

        auth_pam = self._read_first_existing_pam(auth_paths)
        account_pam = self._read_first_existing_pam(account_paths)
        faillock_conf = self._read_path("/etc/security/faillock.conf")
        authselect_info = self._run_command(["authselect", "current"])

        result.raw["files"] = {
            "auth_pam": auth_pam.to_dict() if auth_pam else None,
            "account_pam": account_pam.to_dict() if account_pam else None,
            "faillock_conf": faillock_conf.to_dict() if faillock_conf else None,
        }
        result.raw["commands"] = {
            "authselect_current": authselect_info,
        }

        self._add_authselect_evidence(result, authselect_info)

        tally_result = self._evaluate_tally(result, auth_pam, account_pam)
        faillock_result = self._evaluate_faillock(result, auth_pam, account_pam, faillock_conf)

        result.raw["tally_evaluation"] = tally_result
        result.raw["faillock_evaluation"] = faillock_result

        detected_backends = []
        if tally_result.get("detected"):
            detected_backends.append("pam_tally/pam_tally2")
        if faillock_result.get("detected"):
            detected_backends.append("pam_faillock")

        effective_deny = None
        effective_unlock_time = None

        if tally_result.get("deny") is not None:
            effective_deny = tally_result.get("deny")
        elif faillock_result.get("deny") is not None:
            effective_deny = faillock_result.get("deny")

        if tally_result.get("unlock_time") is not None:
            effective_unlock_time = tally_result.get("unlock_time")
        elif faillock_result.get("unlock_time") is not None:
            effective_unlock_time = faillock_result.get("unlock_time")

        self._add_value_evidence(
            result,
            key="lockout_backend",
            source="pam/common-auth, pam/common-account, faillock.conf",
            value=detected_backends if detected_backends else "(미탐지)",
            status="ok" if detected_backends else "fail",
            notes="탐지된 계정 잠금 정책 구현 방식"
        )

        deny_status = self._status_for_constraint(
            effective_deny,
            self._get_required_constraint("deny")
        )
        unlock_status = self._status_for_constraint(
            effective_unlock_time,
            self._get_recommended_constraint("unlock_time"),
            missing_status="manual"
        )

        self._add_value_evidence(
            result,
            key="deny",
            source=self._select_source_for_value(tally_result, faillock_result, "deny"),
            value=effective_deny if effective_deny is not None else "(설정 없음)",
            status=deny_status,
        )

        self._add_value_evidence(
            result,
            key="unlock_time",
            source=self._select_source_for_value(tally_result, faillock_result, "unlock_time"),
            value=effective_unlock_time if effective_unlock_time is not None else "(설정 없음)",
            status=unlock_status,
        )

        reasons = []

        if tally_result.get("reason"):
            reasons.append(tally_result.get("reason"))

        if faillock_result.get("reason"):
            reasons.append(faillock_result.get("reason"))

        reasons = self._dedupe_keep_order(reasons)

        all_unreadable = (
            (auth_pam is None or not auth_pam.success) and
            (account_pam is None or not account_pam.success) and
            (faillock_conf is None or not faillock_conf.success)
        )

        if all_unreadable:
            result.set_status("MANUAL", success=True)
            result.summary = self._get_message("manual", "summary", default="자동 판정이 어렵습니다.")
            base_detail = self._get_message("manual", "detail", default="추가 확인이 필요합니다.")
            result.detail = self._merge_detail(
                base_detail,
                ["PAM 관련 설정 파일 또는 faillock.conf 를 읽지 못해 수동 확인이 필요합니다."]
            )
            return result

        if tally_result.get("status") == "pass" or faillock_result.get("status") == "pass":
            result.set_status("PASS", success=True)
            result.summary = self._get_message(
                "pass", "summary",
                default="계정 잠금 임계값이 적절히 설정되어 있습니다."
            )
            base_detail = self._get_message(
                "pass",
                "detail",
                default="로그인 실패 누적에 따른 계정 잠금 정책이 적절히 적용되어 있습니다."
            )
            result.detail = self._merge_detail(base_detail, reasons)
            return result

        if detected_backends:
            result.set_status("FAIL", success=False)
            result.summary = self._get_message(
                "fail", "summary",
                default="계정 잠금 임계값이 없거나 기준에 맞지 않습니다."
            )
            base_detail = self._get_message(
                "fail",
                "detail",
                default="로그인 실패 누적에 따른 계정 잠금이 없어 공격자가 무제한으로 비밀번호를 시도할 수 있습니다."
            )
            result.detail = self._merge_detail(base_detail, reasons)
            return result

        result.set_status("FAIL", success=False)
        result.summary = self._get_message(
            "fail", "summary",
            default="계정 잠금 임계값이 없거나 기준에 맞지 않습니다."
        )
        base_detail = self._get_message(
            "fail",
            "detail",
            default="로그인 실패 누적에 따른 계정 잠금이 없어 공격자가 무제한으로 비밀번호를 시도할 수 있습니다."
        )
        result.detail = self._merge_detail(
            base_detail,
            ["pam_tally, pam_tally2, pam_faillock 기반 계정 잠금 정책을 찾지 못했습니다."]
        )
        return result

    def _evaluate_tally(self, result, auth_pam, account_pam):
        rule = self.policy.get("rules", {}).get("tally_rule", {})
        module_names = rule.get("accepted_modules", ["pam_tally.so", "pam_tally2.so"])
        deny_constraint = rule.get("required_options", {}).get("deny", {})
        unlock_constraint = rule.get("recommended_options", {}).get("unlock_time", {})
        requires_reset = bool(
            rule.get("account_requirements", {}).get("requires_reset_option", False)
        )

        auth_entries = self._find_entries(auth_pam, "auth", module_names)
        account_entries = self._find_entries(account_pam, "account", module_names)

        tally_present = self._has_module_name(auth_entries, "pam_tally.so") or self._has_module_name(account_entries, "pam_tally.so")
        tally2_present = self._has_module_name(auth_entries, "pam_tally2.so") or self._has_module_name(account_entries, "pam_tally2.so")

        self._add_bool_evidence(
            result,
            key="pam_tally_module",
            source=self._pam_source(auth_pam, account_pam),
            value=tally_present,
            status="ok" if tally_present else "fail",
        )
        self._add_bool_evidence(
            result,
            key="pam_tally2_module",
            source=self._pam_source(auth_pam, account_pam),
            value=tally2_present,
            status="ok" if tally2_present else "fail",
        )

        detected = bool(auth_entries or account_entries)

        deny_value, deny_entry = self._get_first_option_from_entries(
            auth_entries + account_entries,
            "deny"
        )
        unlock_value, unlock_entry = self._get_first_option_from_entries(
            auth_entries + account_entries,
            "unlock_time"
        )

        reset_present = False
        for entry in account_entries:
            if "reset" in entry.options:
                reset_present = True
                break

        self._add_bool_evidence(
            result,
            key="reset_option",
            source=account_pam.path if account_pam else "/etc/pam.d/common-account",
            value=reset_present,
            status="ok" if reset_present else "fail",
        )

        if not detected:
            return {
                "backend": "tally",
                "detected": False,
                "status": "absent",
                "reason": "",
                "deny": None,
                "unlock_time": None,
                "source_for_deny": self._entry_source(deny_entry, auth_pam, account_pam),
                "source_for_unlock_time": self._entry_source(unlock_entry, auth_pam, account_pam),
            }

        reasons = []

        if not auth_entries:
            reasons.append("pam_tally 또는 pam_tally2 가 auth 체인에 적용되어 있지 않습니다.")

        if requires_reset and not reset_present:
            reasons.append("pam_tally 또는 pam_tally2 사용 시 account 체인에 reset 옵션이 필요합니다.")

        if not self._evaluate_constraint(deny_value, deny_constraint):
            reasons.append(
                "계정 잠금 임계값(deny)이 기준을 충족하지 않습니다. (현재: {0}, 기준: {1} {2})".format(
                    deny_value,
                    to_text(deny_constraint.get("operator", "==")),
                    deny_constraint.get("value")
                )
            )

        if unlock_value is None:
            reasons.append("잠금 해제 시간(unlock_time) 설정을 찾지 못했습니다.")
        elif not self._evaluate_constraint(unlock_value, unlock_constraint):
            reasons.append(
                "잠금 해제 시간(unlock_time)이 권장 기준에 미달합니다. (현재: {0}, 기준: {1} {2})".format(
                    unlock_value,
                    to_text(unlock_constraint.get("operator", "==")),
                    unlock_constraint.get("value")
                )
            )

        if reasons:
            return {
                "backend": "tally",
                "detected": True,
                "status": "fail",
                "reason": " / ".join(self._dedupe_keep_order(reasons)),
                "deny": deny_value,
                "unlock_time": unlock_value,
                "source_for_deny": self._entry_source(deny_entry, auth_pam, account_pam),
                "source_for_unlock_time": self._entry_source(unlock_entry, auth_pam, account_pam),
            }

        return {
            "backend": "tally",
            "detected": True,
            "status": "pass",
            "reason": "pam_tally 또는 pam_tally2 기반 계정 잠금 정책이 적용되어 있고 deny 값이 기준을 충족합니다.",
            "deny": deny_value,
            "unlock_time": unlock_value,
            "source_for_deny": self._entry_source(deny_entry, auth_pam, account_pam),
            "source_for_unlock_time": self._entry_source(unlock_entry, auth_pam, account_pam),
        }

    def _evaluate_faillock(self, result, auth_pam, account_pam, faillock_conf):
        rule = self.policy.get("rules", {}).get("faillock_rule", {})
        module_names = rule.get("accepted_modules", ["pam_faillock.so"])
        deny_constraint = rule.get("required_options", {}).get("deny", {})
        unlock_constraint = rule.get("recommended_options", {}).get("unlock_time", {})
        required_auth_occurrences = rule.get("required_auth_occurrences", ["preauth", "authfail"])
        requires_account_module = bool(
            rule.get("account_requirements", {}).get("requires_account_module", True)
        )

        auth_entries = self._find_entries(auth_pam, "auth", module_names)
        account_entries = self._find_entries(account_pam, "account", module_names)

        faillock_values = {}
        faillock_lines = {}
        if faillock_conf and faillock_conf.success and faillock_conf.content:
            faillock_values, faillock_lines = self._parse_key_value_config(faillock_conf.content)

        auth_present = bool(auth_entries)
        account_present = bool(account_entries)

        self._add_bool_evidence(
            result,
            key="pam_faillock_auth_module",
            source=auth_pam.path if auth_pam else "/etc/pam.d/common-auth",
            value=auth_present,
            status="ok" if auth_present else "fail",
        )
        self._add_bool_evidence(
            result,
            key="pam_faillock_account_module",
            source=account_pam.path if account_pam else "/etc/pam.d/common-account",
            value=account_present,
            status="ok" if account_present else "fail",
        )

        detected = auth_present or account_present

        deny_value, deny_entry = self._get_first_option_from_entries(auth_entries + account_entries, "deny")
        unlock_value, unlock_entry = self._get_first_option_from_entries(auth_entries + account_entries, "unlock_time")

        if deny_value is None:
            deny_value = faillock_values.get("deny")
        if unlock_value is None:
            unlock_value = faillock_values.get("unlock_time")

        preauth_present = self._any_option_present(auth_entries, "preauth")
        authfail_present = self._any_option_present(auth_entries, "authfail")

        if not detected and (deny_value is not None or unlock_value is not None):
            detected = True

        if not detected:
            return {
                "backend": "faillock",
                "detected": False,
                "status": "absent",
                "reason": "",
                "deny": deny_value,
                "unlock_time": unlock_value,
                "source_for_deny": self._select_faillock_value_source(deny_entry, faillock_conf, faillock_lines, "deny"),
                "source_for_unlock_time": self._select_faillock_value_source(unlock_entry, faillock_conf, faillock_lines, "unlock_time"),
            }

        reasons = []

        if "preauth" in required_auth_occurrences and not preauth_present:
            reasons.append("pam_faillock.so auth 체인에 preauth 적용이 없습니다.")

        if "authfail" in required_auth_occurrences and not authfail_present:
            reasons.append("pam_faillock.so auth 체인에 authfail 적용이 없습니다.")

        if requires_account_module and not account_present:
            reasons.append("pam_faillock.so 가 account 체인에 적용되어 있지 않습니다.")

        if not self._evaluate_constraint(deny_value, deny_constraint):
            reasons.append(
                "계정 잠금 임계값(deny)이 기준을 충족하지 않습니다. (현재: {0}, 기준: {1} {2})".format(
                    deny_value,
                    to_text(deny_constraint.get("operator", "==")),
                    deny_constraint.get("value")
                )
            )

        if unlock_value is None:
            reasons.append("잠금 해제 시간(unlock_time) 설정을 찾지 못했습니다.")
        elif not self._evaluate_constraint(unlock_value, unlock_constraint):
            reasons.append(
                "잠금 해제 시간(unlock_time)이 권장 기준에 미달합니다. (현재: {0}, 기준: {1} {2})".format(
                    unlock_value,
                    to_text(unlock_constraint.get("operator", "==")),
                    unlock_constraint.get("value")
                )
            )

        if reasons:
            return {
                "backend": "faillock",
                "detected": True,
                "status": "fail",
                "reason": " / ".join(self._dedupe_keep_order(reasons)),
                "deny": deny_value,
                "unlock_time": unlock_value,
                "source_for_deny": self._select_faillock_value_source(deny_entry, faillock_conf, faillock_lines, "deny"),
                "source_for_unlock_time": self._select_faillock_value_source(unlock_entry, faillock_conf, faillock_lines, "unlock_time"),
            }

        return {
            "backend": "faillock",
            "detected": True,
            "status": "pass",
            "reason": "pam_faillock 기반 계정 잠금 정책이 적용되어 있고 deny 값이 기준을 충족합니다.",
            "deny": deny_value,
            "unlock_time": unlock_value,
            "source_for_deny": self._select_faillock_value_source(deny_entry, faillock_conf, faillock_lines, "deny"),
            "source_for_unlock_time": self._select_faillock_value_source(unlock_entry, faillock_conf, faillock_lines, "unlock_time"),
        }

    def _collect_rule_paths(self, key_name):
        paths = []
        for rule_name in ("tally_rule", "faillock_rule"):
            rule = self.policy.get("rules", {}).get(rule_name, {})
            for path in rule.get(key_name, []):
                path_text = to_text(path)
                if path_text not in paths:
                    paths.append(path_text)
        return paths

    def _find_entries(self, pam_result, interface_name, module_names):
        entries = []
        if pam_result is None or not pam_result.success:
            return entries

        normalized_modules = []
        for module_name in module_names:
            normalized_modules.append(module_name.rsplit("/", 1)[-1])

        for entry in pam_result.entries:
            if entry.interface != interface_name:
                continue
            if entry.module_name in normalized_modules:
                entries.append(entry)
        return entries

    @staticmethod
    def _has_module_name(entries, module_name):
        normalized = module_name.rsplit("/", 1)[-1]
        for entry in entries:
            if entry.module_name == normalized:
                return True
        return False

    @staticmethod
    def _any_option_present(entries, option_name):
        for entry in entries:
            if option_name in entry.options:
                return True
        return False

    @staticmethod
    def _get_first_option_from_entries(entries, option_name):
        for entry in entries:
            if option_name in entry.options:
                return entry.options.get(option_name), entry
        return None, None

    def _read_path(self, path):
        result = self.file_reader.read(path)
        return result if result else None

    def _read_first_existing_pam(self, preferred):
        for path in preferred:
            parsed = self.pam_reader.read(path)
            if parsed.success:
                return parsed

        for path in preferred:
            inspect = self.file_reader.inspect(path)
            if inspect.metadata.exists:
                return self.pam_reader.read(path)

        return None

    def _add_authselect_evidence(self, result, command_info):
        if command_info.get("status") == "ok":
            value = command_info.get("stdout") or "(출력 없음)"
            status = "ok"
        elif command_info.get("status") == "not_found":
            value = "(명령 없음)"
            status = "manual"
        else:
            value = command_info.get("stderr") or "(실행 실패)"
            status = "manual"

        result.add_evidence(
            key="authselect_profile",
            label=self._label("authselect_profile"),
            source="authselect current",
            value=value,
            status=status,
            notes=command_info.get("status")
        )

    def _add_bool_evidence(self, result, key, source, value, status):
        result.add_evidence(
            key=key,
            label=self._label(key),
            source=source,
            value=bool(value),
            status=status
        )

    def _add_value_evidence(self, result, key, source, value, status, notes=None):
        result.add_evidence(
            key=key,
            label=self._label(key),
            source=source,
            value=value,
            status=status,
            notes=notes
        )

    def _select_source_for_value(self, tally_result, faillock_result, key_name):
        if tally_result.get(key_name) is not None:
            return tally_result.get("source_for_{0}".format(key_name)) or "pam_tally/pam_tally2"
        if faillock_result.get(key_name) is not None:
            return faillock_result.get("source_for_{0}".format(key_name)) or "pam_faillock"
        return "pam/common-auth, pam/common-account, faillock.conf"

    @staticmethod
    def _entry_source(entry, auth_pam, account_pam):
        if entry is None:
            return "/etc/pam.d/common-auth or /etc/pam.d/common-account"

        if entry.interface == "account" and account_pam is not None:
            return account_pam.path

        if auth_pam is not None:
            return auth_pam.path

        return "/etc/pam.d/common-auth"

    @staticmethod
    def _select_faillock_value_source(entry, faillock_conf, faillock_lines, key_name):
        if entry is not None:
            return "/etc/pam.d/common-auth or /etc/pam.d/common-account"
        if faillock_conf and faillock_conf.success and key_name in faillock_lines:
            return faillock_conf.path
        return "/etc/security/faillock.conf"

    @staticmethod
    def _pam_source(auth_pam, account_pam):
        sources = []
        if auth_pam is not None and auth_pam.success:
            sources.append(auth_pam.path)
        if account_pam is not None and account_pam.success:
            sources.append(account_pam.path)
        if not sources:
            return "/etc/pam.d/common-auth or /etc/pam.d/common-account"
        return ", ".join(sources)

    def _run_command(self, command):
        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = proc.communicate()

            return {
                "status": "ok" if proc.returncode == 0 else "error",
                "returncode": proc.returncode,
                "stdout": to_text(stdout).strip(),
                "stderr": to_text(stderr).strip(),
                "command": command,
            }
        except OSError as exc:
            return {
                "status": "not_found",
                "returncode": 127,
                "stdout": "",
                "stderr": to_text(exc),
                "command": command,
            }
        except Exception as exc:
            return {
                "status": "error",
                "returncode": 999,
                "stdout": "",
                "stderr": to_text(exc),
                "command": command,
            }

    def _parse_key_value_config(self, content):
        values = {}
        raw_lines = {}

        for raw_line in content.splitlines():
            stripped = raw_line.strip()

            if (not stripped) or stripped.startswith("#"):
                continue

            line = stripped
            if "#" in line:
                line = line.split("#", 1)[0].strip()
            if not line:
                continue

            if "=" in line:
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()
                values[key] = value
                raw_lines[key] = raw_line.strip()
                continue

            parts = line.split()
            if len(parts) >= 2:
                key = parts[0].strip()
                value = " ".join(parts[1:]).strip()
                values[key] = value
                raw_lines[key] = raw_line.strip()
            elif len(parts) == 1:
                key = parts[0].strip()
                values[key] = True
                raw_lines[key] = raw_line.strip()

        return values, raw_lines

    def _get_required_constraint(self, key_name):
        for rule_name in ("tally_rule", "faillock_rule"):
            rule = self.policy.get("rules", {}).get(rule_name, {})
            constraint = rule.get("required_options", {}).get(key_name)
            if constraint:
                return constraint
        return {}

    def _get_recommended_constraint(self, key_name):
        for rule_name in ("tally_rule", "faillock_rule"):
            rule = self.policy.get("rules", {}).get(rule_name, {})
            constraint = rule.get("recommended_options", {}).get(key_name)
            if constraint:
                return constraint
        return {}

    def _status_for_constraint(self, current, constraint, missing_status="fail"):
        if current is None:
            return missing_status
        if self._evaluate_constraint(current, constraint):
            return "ok"
        return "fail"

    def _evaluate_constraint(self, current, constraint):
        if current is None:
            return False

        operator = to_text(constraint.get("operator", "==")).strip()
        expected = constraint.get("value")

        if isinstance(current, bool):
            current_value = current
        else:
            current_text = to_text(current).strip()
            if self._is_int_like(current_text) and isinstance(expected, (int, float)):
                current_value = int(current_text)
            else:
                current_value = current_text

        if operator == ">=":
            return current_value >= expected
        if operator == "<=":
            return current_value <= expected
        if operator == ">":
            return current_value > expected
        if operator == "<":
            return current_value < expected
        if operator == "!=":
            return current_value != expected
        return current_value == expected

    @staticmethod
    def _is_int_like(value):
        try:
            int(value)
            return True
        except Exception:
            return False

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

    def _load_configs(self):
        if yaml is None:
            raise RuntimeError(
                "PyYAML이 필요합니다. 설치 후 다시 실행하세요. 원인: {0}".format(
                    _yaml_import_error
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
            code="U-03",
            name="계정 잠금 임계값 설정",
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