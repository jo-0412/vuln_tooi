from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

try:
    import yaml
except ImportError as exc:  # pragma: no cover
    yaml = None
    _yaml_import_error = exc
else:
    _yaml_import_error = None

from app.collectors.file_reader import FileReadResult, FileReader
from app.collectors.pam_reader import PamParseResult, PamReader
from app.models.check_result import CheckResult


class U02Runner:
    """
    U-02 비밀번호 관리정책 설정 점검 실행기
    """

    def __init__(self, check_dir: Optional[Path] = None) -> None:
        self.app_dir = Path(__file__).resolve().parents[1]
        self.check_dir = check_dir or (self.app_dir / "checks" / "u02_password_policy")
        self.file_reader = FileReader()
        self.pam_reader = PamReader()

        self.metadata: dict[str, Any] = {}
        self.targets: dict[str, Any] = {}
        self.policy: dict[str, Any] = {}
        self.messages: dict[str, Any] = {}

    def run(self) -> CheckResult:
        try:
            self._load_configs()
        except Exception as exc:
            return self._build_error_result(f"설정 파일 로딩 실패: {exc}")

        result = CheckResult(
            code=self.metadata.get("code", "U-02"),
            name=self.metadata.get("name", "비밀번호 관리정책 설정"),
            severity=self.metadata.get("severity", "high"),
            category=self.metadata.get("category", "account_management"),
            status="MANUAL",
            success=True,
            summary=self._get_message("manual", "summary", default="자동 판정이 어렵습니다."),
            detail=self._get_message("manual", "detail", default="추가 확인이 필요합니다."),
            requires_root=self.metadata.get("requires_root", "partial"),
            remediation_summary=self.messages.get("remediation", {}).get("summary"),
            remediation_steps=self.messages.get("remediation", {}).get("actions", []),
        )

        # 1) 파일 수집
        pwquality_file = self._read_path("/etc/security/pwquality.conf")
        login_defs_file = self._read_path("/etc/login.defs")
        pwhistory_file = self._read_path("/etc/security/pwhistory.conf")
        pam_file = self._read_first_existing_pam(
            preferred=["/etc/pam.d/common-password", "/etc/pam.d/system-auth"]
        )

        result.raw["files"] = {
            "pwquality": pwquality_file.to_dict() if pwquality_file else None,
            "login_defs": login_defs_file.to_dict() if login_defs_file else None,
            "pwhistory": pwhistory_file.to_dict() if pwhistory_file else None,
            "pam": pam_file.to_dict() if pam_file else None,
        }

        states: list[str] = []
        reasons: list[str] = []

        complexity_state, complexity_reason = self._evaluate_complexity(result, pwquality_file)
        states.append(complexity_state)
        reasons.append(complexity_reason)

        aging_state, aging_reason = self._evaluate_aging(result, login_defs_file)
        states.append(aging_state)
        reasons.append(aging_reason)

        history_state, history_reason = self._evaluate_history(result, pwhistory_file, pam_file)
        states.append(history_state)
        reasons.append(history_reason)

        pam_state, pam_reason = self._evaluate_pam(result, pam_file)
        states.append(pam_state)
        reasons.append(pam_reason)

        filtered_reasons = [reason for reason in reasons if reason]

        if "fail" in states:
            result.set_status("FAIL", success=False)
            result.summary = self._get_message(
                "fail", "summary", default="비밀번호 관리정책이 없거나 약하게 설정되어 있습니다."
            )
            base_detail = self._get_message(
                "fail",
                "detail",
                default="비밀번호 정책이 약하거나 없어서 계정 탈취 위험이 높습니다.",
            )
            result.detail = self._merge_detail(base_detail, filtered_reasons)
        elif "manual" in states or "error" in states:
            result.set_status("MANUAL", success=True)
            result.summary = self._get_message("manual", "summary", default="자동 판정이 어렵습니다.")
            base_detail = self._get_message("manual", "detail", default="추가 확인이 필요합니다.")
            result.detail = self._merge_detail(base_detail, filtered_reasons)
        else:
            result.set_status("PASS", success=True)
            result.summary = self._get_message(
                "pass", "summary", default="비밀번호 관리정책이 적절히 설정되어 있습니다."
            )
            base_detail = self._get_message(
                "pass",
                "detail",
                default="최소 길이, 문자 조합, 비밀번호 변경 주기, 재사용 금지 정책이 기준에 맞게 설정되어 있습니다.",
            )
            result.detail = self._merge_detail(base_detail, filtered_reasons)

        result.raw["component_states"] = states
        return result

    def _evaluate_complexity(
        self,
        result: CheckResult,
        file_result: Optional[FileReadResult],
    ) -> tuple[str, str]:
        rule = self.policy.get("rules", {}).get("complexity_rule", {})
        required_keys = rule.get("required_keys", {})

        if file_result is None or not file_result.success or not file_result.content:
            result.add_error("pwquality.conf 파일을 읽지 못했습니다.")
            return "manual", "비밀번호 복잡도 정책 파일(pwquality.conf)을 읽지 못해 수동 확인이 필요합니다."

        values, raw_lines = self._parse_key_value_config(file_result.content)

        self._add_key_evidence(
            result,
            key="minlen",
            source=file_result.path,
            value=values.get("minlen"),
            raw_line=raw_lines.get("minlen"),
        )
        self._add_key_evidence(
            result,
            key="dcredit",
            source=file_result.path,
            value=values.get("dcredit"),
            raw_line=raw_lines.get("dcredit"),
        )
        self._add_key_evidence(
            result,
            key="ucredit",
            source=file_result.path,
            value=values.get("ucredit"),
            raw_line=raw_lines.get("ucredit"),
        )
        self._add_key_evidence(
            result,
            key="lcredit",
            source=file_result.path,
            value=values.get("lcredit"),
            raw_line=raw_lines.get("lcredit"),
        )
        self._add_key_evidence(
            result,
            key="ocredit",
            source=file_result.path,
            value=values.get("ocredit"),
            raw_line=raw_lines.get("ocredit"),
        )
        self._add_key_evidence(
            result,
            key="enforce_for_root",
            source=file_result.path,
            value=values.get("enforce_for_root"),
            raw_line=raw_lines.get("enforce_for_root"),
        )

        failed_conditions: list[str] = []

        for key, constraint in required_keys.items():
            current = values.get(key)
            ok = self._evaluate_constraint(current, constraint)
            if not ok:
                failed_conditions.append(
                    f"{key} 값이 기준을 충족하지 않습니다. (현재: {current}, 기준: {constraint.get('operator')} {constraint.get('value')})"
                )

        if failed_conditions:
            return "fail", " / ".join(failed_conditions)

        return "pass", "pwquality.conf 에 최소 길이 및 문자 조합 정책이 기준을 충족합니다."

    def _evaluate_aging(
        self,
        result: CheckResult,
        file_result: Optional[FileReadResult],
    ) -> tuple[str, str]:
        rule = self.policy.get("rules", {}).get("aging_rule", {})
        required_keys = rule.get("required_keys", {})

        if file_result is None or not file_result.success or not file_result.content:
            result.add_error("login.defs 파일을 읽지 못했습니다.")
            return "manual", "비밀번호 사용기간 정책 파일(login.defs)을 읽지 못해 수동 확인이 필요합니다."

        values, raw_lines = self._parse_key_value_config(file_result.content)

        self._add_key_evidence(
            result,
            key="pass_min_days",
            source=file_result.path,
            value=values.get("PASS_MIN_DAYS"),
            raw_line=raw_lines.get("PASS_MIN_DAYS"),
        )
        self._add_key_evidence(
            result,
            key="pass_max_days",
            source=file_result.path,
            value=values.get("PASS_MAX_DAYS"),
            raw_line=raw_lines.get("PASS_MAX_DAYS"),
        )

        failed_conditions: list[str] = []

        for key, constraint in required_keys.items():
            current = values.get(key)
            ok = self._evaluate_constraint(current, constraint)
            if not ok:
                failed_conditions.append(
                    f"{key} 값이 기준을 충족하지 않습니다. (현재: {current}, 기준: {constraint.get('operator')} {constraint.get('value')})"
                )

        if failed_conditions:
            return "fail", " / ".join(failed_conditions)

        return "pass", "login.defs 의 PASS_MIN_DAYS 및 PASS_MAX_DAYS 설정이 기준을 충족합니다."

    def _evaluate_history(
        self,
        result: CheckResult,
        pwhistory_file: Optional[FileReadResult],
        pam_file: Optional[PamParseResult],
    ) -> tuple[str, str]:
        rule = self.policy.get("rules", {}).get("history_rule", {})
        remember_constraint = rule.get("checks", {}).get("remember", {})

        remember_value: Optional[str | bool] = None
        remember_source = ""
        remember_excerpt: Optional[str] = None

        if pwhistory_file and pwhistory_file.success and pwhistory_file.content:
            values, raw_lines = self._parse_key_value_config(pwhistory_file.content)
            remember_value = values.get("remember")
            remember_source = pwhistory_file.path
            remember_excerpt = raw_lines.get("remember")

        if remember_value is None and pam_file and pam_file.success:
            remember_value, remember_entry = self.pam_reader.get_first_option(
                pam_file,
                ["pam_pwhistory.so", "pam_unix.so"],
                "remember",
            )
            if remember_entry is not None:
                remember_source = pam_file.path
                remember_excerpt = remember_entry.raw_line

        self._add_key_evidence(
            result,
            key="remember",
            source=remember_source or "/etc/security/pwhistory.conf",
            value=remember_value,
            raw_line=remember_excerpt,
        )

        if remember_value is None:
            return "fail", "최근 비밀번호 재사용 금지(remember) 설정을 찾지 못했습니다."

        if not self._evaluate_constraint(remember_value, remember_constraint):
            return (
                "fail",
                f"최근 비밀번호 재사용 금지 횟수가 기준 미달입니다. (현재: {remember_value}, 기준: {remember_constraint.get('operator')} {remember_constraint.get('value')})",
            )

        return "pass", "최근 비밀번호 재사용 금지 횟수 설정이 기준을 충족합니다."

    def _evaluate_pam(
        self,
        result: CheckResult,
        pam_result: Optional[PamParseResult],
    ) -> tuple[str, str]:
        rule = self.policy.get("rules", {}).get("pam_rule", {})
        required_modules = rule.get("required_modules", [])
        optional_modules = rule.get("optional_modules", [])
        order_constraints = rule.get("order_constraints", [])

        if pam_result is None or not pam_result.success:
            result.add_error("PAM 정책 파일을 읽지 못했습니다.")
            return "manual", "PAM 정책 파일(common-password/system-auth)을 읽지 못해 수동 확인이 필요합니다."

        module_summary = self.pam_reader.build_module_summary(pam_result)

        pwquality_entry = self.pam_reader.get_first_module(pam_result, "pam_pwquality.so")
        pwhistory_entry = self.pam_reader.get_first_module(pam_result, "pam_pwhistory.so")
        unix_entry = self.pam_reader.get_first_module(pam_result, "pam_unix.so")

        self._add_pam_module_evidence(
            result,
            key="pam_pwquality_module",
            module_entry=pwquality_entry,
            source=pam_result.path,
        )
        self._add_pam_module_evidence(
            result,
            key="pam_pwhistory_module",
            module_entry=pwhistory_entry,
            source=pam_result.path,
        )
        self._add_pam_module_evidence(
            result,
            key="pam_unix_module",
            module_entry=unix_entry,
            source=pam_result.path,
        )

        failed_conditions: list[str] = []

        for module_name in required_modules:
            if not self.pam_reader.has_module(pam_result, module_name):
                failed_conditions.append(f"{module_name} 모듈이 없습니다.")

        order_results: list[dict[str, Any]] = []
        for constraint in order_constraints:
            before = constraint.get("before")
            after = constraint.get("after")
            ordered, before_line, after_line = self.pam_reader.check_order(
                pam_result,
                before=before,
                after=after,
            )

            order_results.append(
                {
                    "before": before,
                    "after": after,
                    "ordered": ordered,
                    "before_line": before_line,
                    "after_line": after_line,
                }
            )

            # optional module이 없으면 순서 판정 생략
            if before in optional_modules and before_line is None:
                continue

            if ordered is False:
                failed_conditions.append(
                    f"{before} 가 {after} 보다 앞에 있어야 합니다. (현재 라인: {before_line}, {after_line})"
                )

        result.add_evidence(
            key="pam_module_order",
            label=self._label("pam_module_order"),
            source=pam_result.path,
            value=order_results,
            status="ok" if not failed_conditions else "fail",
            notes="PAM 모듈 적용 순서 점검 결과",
        )

        result.raw["pam_module_summary"] = module_summary

        if failed_conditions:
            return "fail", " / ".join(failed_conditions)

        return "pass", "PAM 비밀번호 정책 모듈이 존재하며 적용 순서도 기준을 충족합니다."

    def _read_path(self, path: str) -> Optional[FileReadResult]:
        result = self.file_reader.read(path)
        return result if result else None

    def _read_first_existing_pam(self, preferred: list[str]) -> Optional[PamParseResult]:
        for path in preferred:
            parsed = self.pam_reader.read(path)
            if parsed.success:
                return parsed

        for path in preferred:
            inspect = self.file_reader.inspect(path)
            if inspect.metadata.exists:
                return self.pam_reader.read(path)

        return None

    def _add_key_evidence(
        self,
        result: CheckResult,
        *,
        key: str,
        source: str,
        value: Any,
        raw_line: Optional[str],
    ) -> None:
        status = "ok" if value not in (None, "") else "fail"
        result.add_evidence(
            key=key,
            label=self._label(key),
            source=source,
            value=value if value is not None else "(설정 없음)",
            status=status,
            excerpt=raw_line,
        )

    def _add_pam_module_evidence(
        self,
        result: CheckResult,
        *,
        key: str,
        module_entry: Any,
        source: str,
    ) -> None:
        if module_entry is None:
            result.add_evidence(
                key=key,
                label=self._label(key),
                source=source,
                value=False,
                status="fail",
            )
            return

        result.add_evidence(
            key=key,
            label=self._label(key),
            source=source,
            value=True,
            status="ok",
            excerpt=module_entry.raw_line,
            notes=f"line={module_entry.line_number}",
        )

    def _label(self, key: str) -> str:
        return self.messages.get("evidence_labels", {}).get(key, key)

    def _parse_key_value_config(self, content: str) -> tuple[dict[str, str | bool], dict[str, str]]:
        values: dict[str, str | bool] = {}
        raw_lines: dict[str, str] = {}

        for raw_line in content.splitlines():
            stripped = raw_line.strip()

            if not stripped or stripped.startswith("#"):
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

    def _evaluate_constraint(self, current: Any, constraint: dict[str, Any]) -> bool:
        if current is None:
            return False

        operator = str(constraint.get("operator", "==")).strip()
        expected = constraint.get("value")

        if isinstance(current, bool):
            current_value: Any = current
        else:
            current_text = str(current).strip()
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
    def _is_int_like(value: str) -> bool:
        try:
            int(value)
            return True
        except Exception:
            return False

    def _load_configs(self) -> None:
        if yaml is None:  # pragma: no cover
            raise RuntimeError(
                f"PyYAML이 필요합니다. 설치 후 다시 실행하세요. 원인: {_yaml_import_error}"
            )

        self.metadata = self._load_yaml(self.check_dir / "metadata.yaml")
        self.targets = self._load_yaml(self.check_dir / "targets.yaml")
        self.policy = self._load_yaml(self.check_dir / "policy.yaml")
        self.messages = self._load_yaml(self.check_dir / "messages.yaml")

    @staticmethod
    def _load_yaml(path: Path) -> dict[str, Any]:
        if not path.exists():
            raise FileNotFoundError(f"설정 파일을 찾을 수 없습니다: {path}")

        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        if not isinstance(data, dict):
            raise ValueError(f"YAML 최상위 구조는 dict 여야 합니다: {path}")

        return data

    def _get_message(self, section: str, field: str, *, default: str) -> str:
        return str(self.messages.get(section, {}).get(field, default))

    @staticmethod
    def _merge_detail(base_detail: str, reasons: list[str]) -> str:
        filtered = [reason.strip() for reason in reasons if reason and reason.strip()]
        if not filtered:
            return base_detail.strip()

        merged = [base_detail.strip(), "", "판정 근거:"]
        merged.extend(f"- {reason}" for reason in filtered)
        return "\n".join(merged)

    def _build_error_result(self, message: str) -> CheckResult:
        result = CheckResult(
            code="U-02",
            name="비밀번호 관리정책 설정",
            severity="high",
            category="account_management",
            status="ERROR",
            success=False,
            summary="점검 실행 중 오류가 발생했습니다.",
            detail=message,
            requires_root="partial",
        )
        result.add_error(message)
        return result