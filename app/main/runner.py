from __future__ import annotations

from pathlib import Path
from typing import Any, Optional
import re

try:
    import yaml
except ImportError as exc:  # pragma: no cover
    yaml = None
    _yaml_import_error = exc
else:
    _yaml_import_error = None

from app.collectors.file_reader import FileReadResult, FileReader
from app.collectors.service_reader import ServiceReader, ServiceStatusResult
from app.models.check_result import CheckResult


class U01Runner:
    """
    U-01 root 계정 원격 접속 제한 점검 실행기
    """

    def __init__(self, check_dir: Optional[Path] = None) -> None:
        self.app_dir = Path(__file__).resolve().parents[1]
        self.check_dir = check_dir or (self.app_dir / "checks" / "u01_root_remote_login")
        self.file_reader = FileReader()
        self.service_reader = ServiceReader(timeout=5)

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
            code=self.metadata.get("code", "U-01"),
            name=self.metadata.get("name", "root 계정 원격 접속 제한"),
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

        ssh_service = self._inspect_named_service("ssh")
        telnet_service = self._inspect_named_service("telnet")

        result.raw["service_statuses"] = {
            "ssh": ssh_service.to_dict(),
            "telnet": telnet_service.to_dict(),
        }

        self._add_service_evidence(result, "ssh_service", "SSH 서비스 상태", ssh_service)
        self._add_service_evidence(result, "telnet_service", "Telnet 계열 서비스 상태", telnet_service)

        ssh_in_use = bool(ssh_service.active)
        telnet_in_use = bool(telnet_service.active)

        component_states: list[str] = []
        detail_reasons: list[str] = []

        # SSH 판정
        ssh_state, ssh_reason = self._evaluate_ssh(result, ssh_in_use)
        if ssh_state:
            component_states.append(ssh_state)
        if ssh_reason:
            detail_reasons.append(ssh_reason)

        # Telnet 판정
        telnet_state, telnet_reason = self._evaluate_telnet(result, telnet_in_use)
        if telnet_state:
            component_states.append(telnet_state)
        if telnet_reason:
            detail_reasons.append(telnet_reason)

        # 최종 판정
        if not ssh_in_use and not telnet_in_use:
            result.set_status("PASS", success=True)
            result.summary = self._get_message(
                "pass", "summary", default="root 계정의 원격 직접 접속이 차단되어 있습니다."
            )
            base_detail = self._get_message(
                "pass",
                "detail",
                default="원격 터미널 서비스를 사용하지 않거나 root 직접 로그인이 차단되어 있습니다.",
            )
            result.detail = self._merge_detail(base_detail, ["SSH/Telnet 원격 터미널 서비스가 활성 상태가 아닙니다."])
            result.raw["component_states"] = component_states
            return result

        if "fail" in component_states:
            result.set_status("FAIL", success=False)
            result.summary = self._get_message(
                "fail", "summary", default="root 계정의 원격 직접 접속이 허용되어 있습니다."
            )
            base_detail = self._get_message(
                "fail",
                "detail",
                default="현재 서버는 root 계정의 원격 직접 로그인을 허용하고 있습니다.",
            )
            result.detail = self._merge_detail(base_detail, detail_reasons)
        elif "manual" in component_states or "error" in component_states:
            result.set_status("MANUAL", success=True)
            result.summary = self._get_message("manual", "summary", default="자동 판정이 어렵습니다.")
            base_detail = self._get_message("manual", "detail", default="추가 확인이 필요합니다.")
            result.detail = self._merge_detail(base_detail, detail_reasons)
        else:
            result.set_status("PASS", success=True)
            result.summary = self._get_message(
                "pass", "summary", default="root 계정의 원격 직접 접속이 차단되어 있습니다."
            )
            base_detail = self._get_message(
                "pass",
                "detail",
                default="원격 터미널 서비스를 사용하지 않거나, 사용 중인 서비스에서 root 직접 로그인이 제한되어 있습니다.",
            )
            result.detail = self._merge_detail(base_detail, detail_reasons)

        result.raw["component_states"] = component_states
        return result

    def _evaluate_ssh(self, result: CheckResult, ssh_in_use: bool) -> tuple[Optional[str], Optional[str]]:
        if not ssh_in_use:
            return "not_used", "SSH 서비스가 활성 상태가 아니므로 SSH 기준으로는 원격 root 접속이 노출되지 않습니다."

        ssh_paths = self._get_paths_by_parser("sshd_config")
        ssh_file = self._read_first_readable(ssh_paths)

        if ssh_file is None:
            result.add_error("SSH 설정 파일을 찾지 못했습니다.")
            return "manual", "SSH 서비스는 활성 상태지만 sshd_config 파일을 찾지 못해 수동 확인이 필요합니다."

        self._add_file_evidence(
            result,
            key="sshd_config_path",
            label="실제 사용한 SSH 설정 파일",
            source=ssh_file.path,
            value=ssh_file.path,
            status="ok" if ssh_file.success else ssh_file.status,
        )

        if not ssh_file.success or not ssh_file.content:
            result.add_error(f"SSH 설정 파일 읽기 실패: {ssh_file.path}")
            return "manual", "SSH 설정 파일을 읽지 못해 PermitRootLogin 값을 자동 판정할 수 없습니다."

        permit_value, permit_line = self._parse_sshd_key(ssh_file.content, "PermitRootLogin")
        label = self.messages.get("evidence_labels", {}).get(
            "permit_root_login", "sshd_config 내 PermitRootLogin 값"
        )

        result.add_evidence(
            key="permit_root_login",
            label=label,
            source=ssh_file.path,
            value=permit_value if permit_value is not None else "(설정 없음)",
            status="ok" if permit_value is not None else "manual",
            excerpt=permit_line,
        )

        ssh_rule = self.policy.get("rules", {}).get("ssh_rule", {})
        acceptable_values = {str(v).strip().lower() for v in ssh_rule.get("acceptable_values", ["no"])}
        vulnerable_values = {str(v).strip().lower() for v in ssh_rule.get("vulnerable_values", ["yes"])}

        if permit_value is None:
            return "manual", "SSH 서비스는 활성 상태지만 PermitRootLogin 설정이 없어 기본값 해석이 필요합니다."

        normalized = permit_value.strip().lower()

        if normalized in acceptable_values:
            return "pass", f"SSH 서비스 활성 상태에서 PermitRootLogin={permit_value} 이므로 root 직접 로그인이 차단됩니다."

        if normalized in vulnerable_values:
            return "fail", f"SSH 서비스 활성 상태에서 PermitRootLogin={permit_value} 이므로 root 직접 로그인이 허용됩니다."

        return "manual", f"SSH 서비스 활성 상태에서 PermitRootLogin={permit_value} 이며 정책상 명확한 자동 판정이 어렵습니다."

    def _evaluate_telnet(self, result: CheckResult, telnet_in_use: bool) -> tuple[Optional[str], Optional[str]]:
        if not telnet_in_use:
            return "not_used", "Telnet 계열 서비스가 활성 상태가 아닙니다."

        login_file = self.file_reader.read("/etc/pam.d/login")
        securetty_file = self.file_reader.read("/etc/securetty")

        pam_label = self.messages.get("evidence_labels", {}).get(
            "pam_securetty", "/etc/pam.d/login 내 pam_securetty 적용 여부"
        )
        securetty_label = self.messages.get("evidence_labels", {}).get(
            "securetty_pts_entries", "/etc/securetty 내 pts 허용 여부"
        )

        if login_file.success and login_file.content:
            pam_present, pam_line = self._contains_token_line(login_file.content, "pam_securetty")
            result.add_evidence(
                key="pam_securetty",
                label=pam_label,
                source=login_file.path,
                value=pam_present,
                status="ok" if pam_present else "fail",
                excerpt=pam_line,
            )
        else:
            result.add_evidence(
                key="pam_securetty",
                label=pam_label,
                source="/etc/pam.d/login",
                value="읽기 실패 또는 파일 없음",
                status="manual",
            )

        if securetty_file.success and securetty_file.content is not None:
            pts_entries = self._extract_pts_entries(securetty_file.content)
            result.add_evidence(
                key="securetty_pts_entries",
                label=securetty_label,
                source=securetty_file.path,
                value=pts_entries,
                status="fail" if pts_entries else "ok",
            )
        else:
            result.add_evidence(
                key="securetty_pts_entries",
                label=securetty_label,
                source="/etc/securetty",
                value="읽기 실패 또는 파일 없음",
                status="manual",
            )

        if not login_file.success or not securetty_file.success:
            return "manual", "Telnet 계열 서비스는 활성 상태지만 /etc/pam.d/login 또는 /etc/securetty 확인이 필요합니다."

        pam_present, _ = self._contains_token_line(login_file.content or "", "pam_securetty")
        pts_entries = self._extract_pts_entries(securetty_file.content or "")

        if pam_present and not pts_entries:
            return "pass", "Telnet 계열 서비스 사용 시 pam_securetty 가 적용되어 있고 /etc/securetty 에 pts/* 허용 항목이 없습니다."

        return "fail", "Telnet 계열 서비스 사용 시 pam_securetty 미적용 또는 /etc/securetty 의 pts/* 허용 항목이 존재합니다."

    def _inspect_named_service(self, logical_name: str) -> ServiceStatusResult:
        service_target = self._find_service_target(logical_name)
        if service_target is None:
            # 서비스 정의가 없어도 기본 이름으로 시도
            return self.service_reader.inspect(logical_name)

        return self.service_reader.inspect(
            service_target.get("name", logical_name),
            aliases=service_target.get("aliases", []),
        )

    def _find_service_target(self, logical_name: str) -> Optional[dict[str, Any]]:
        for service in self.targets.get("services", []):
            if service.get("name") == logical_name:
                return service
        return None

    def _get_paths_by_parser(self, parser_name: str) -> list[str]:
        paths: list[str] = []
        files = self.targets.get("files", {})
        for section in ("required", "optional"):
            for item in files.get(section, []):
                if item.get("parser") == parser_name and item.get("path"):
                    paths.append(str(item["path"]))
        return paths

    def _read_first_readable(self, paths: list[str]) -> Optional[FileReadResult]:
        for path in paths:
            result = self.file_reader.read(path)
            if result.success:
                return result

        for path in paths:
            inspected = self.file_reader.inspect(path)
            if inspected.metadata.exists:
                return self.file_reader.read(path)

        return None

    def _add_service_evidence(
        self,
        result: CheckResult,
        key: str,
        label: str,
        service_result: ServiceStatusResult,
    ) -> None:
        result.add_evidence(
            key=key,
            label=label,
            source=service_result.matched_name or service_result.query_name,
            value={
                "installed": service_result.installed,
                "enabled": service_result.enabled,
                "active": service_result.active,
                "load_state": service_result.load_state,
                "unit_file_state": service_result.unit_file_state,
                "active_state": service_result.active_state,
            },
            status="ok" if service_result.success else service_result.status,
            notes=service_result.message,
        )

    def _add_file_evidence(
        self,
        result: CheckResult,
        *,
        key: str,
        label: str,
        source: str,
        value: Any,
        status: str = "info",
        excerpt: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> None:
        result.add_evidence(
            key=key,
            label=label,
            source=source,
            value=value,
            status=status,
            excerpt=excerpt,
            notes=notes,
        )

    @staticmethod
    def _parse_sshd_key(content: str, key: str) -> tuple[Optional[str], Optional[str]]:
        key_lower = key.lower()
        found_value: Optional[str] = None
        found_line: Optional[str] = None

        for raw_line in content.splitlines():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            no_inline_comment = re.sub(r"\s+#.*$", "", stripped).strip()
            parts = re.split(r"\s+", no_inline_comment, maxsplit=1)
            if len(parts) < 2:
                continue

            current_key, current_value = parts[0].strip().lower(), parts[1].strip()
            if current_key == key_lower:
                found_value = current_value
                found_line = raw_line.strip()

        return found_value, found_line

    @staticmethod
    def _contains_token_line(content: str, token: str) -> tuple[bool, Optional[str]]:
        for raw_line in content.splitlines():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if token in stripped:
                return True, raw_line.strip()
        return False, None

    @staticmethod
    def _extract_pts_entries(content: str) -> list[str]:
        entries: list[str] = []
        for raw_line in content.splitlines():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if re.match(r"^pts(?:/|\d)", stripped):
                entries.append(stripped)
        return entries

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
            code="U-01",
            name="root 계정 원격 접속 제한",
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