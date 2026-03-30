from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable, Optional
import shutil
import subprocess


@dataclass
class ServiceCommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ServiceStatusResult:
    query_name: str
    matched_name: Optional[str]
    systemd_available: bool
    exists: bool
    installed: bool
    enabled: Optional[bool]
    active: Optional[bool]
    load_state: Optional[str]
    unit_file_state: Optional[str]
    active_state: Optional[str]
    sub_state: Optional[str]
    fragment_path: Optional[str]
    status: str
    success: bool
    message: str
    error_type: Optional[str] = None
    error_detail: Optional[str] = None
    evidence: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ServiceReader:
    """
    systemd 기반 공통 서비스 상태 수집기.
    특정 취약점 항목(U-01 등)에 의존하지 않고,
    서비스의 존재 여부 / 설치 여부 / 활성화 여부 / 실행 여부를 표준 형식으로 반환한다.
    """

    def __init__(self, timeout: int = 5) -> None:
        self.timeout = timeout

    def is_systemd_available(self) -> bool:
        """
        systemctl 명령 사용 가능 여부 확인
        """
        return shutil.which("systemctl") is not None

    def inspect(
        self,
        name: str,
        *,
        aliases: Optional[list[str]] = None,
    ) -> ServiceStatusResult:
        """
        하나의 서비스(또는 별칭 목록)를 확인한다.
        """
        if not self.is_systemd_available():
            return ServiceStatusResult(
                query_name=name,
                matched_name=None,
                systemd_available=False,
                exists=False,
                installed=False,
                enabled=None,
                active=None,
                load_state=None,
                unit_file_state=None,
                active_state=None,
                sub_state=None,
                fragment_path=None,
                status="systemd_unavailable",
                success=False,
                message="systemctl을 사용할 수 없는 환경입니다.",
                error_type="SystemdUnavailableError",
                evidence={"checked_candidates": []},
            )

        candidates = self._build_candidates(name, aliases or [])
        last_evidence: dict[str, Any] = {"checked_candidates": candidates, "commands": []}

        for candidate in candidates:
            cmd_result = self._run_show(candidate)
            last_evidence["commands"].append(cmd_result.to_dict())

            if cmd_result.returncode not in (0, 1):
                continue

            parsed = self._parse_show_output(cmd_result.stdout)
            load_state = parsed.get("LoadState")
            unit_file_state = parsed.get("UnitFileState")
            active_state = parsed.get("ActiveState")
            sub_state = parsed.get("SubState")
            fragment_path = parsed.get("FragmentPath")
            unit_id = parsed.get("Id") or candidate

            exists = load_state is not None
            installed = load_state not in (None, "not-found")
            enabled = self._to_enabled(unit_file_state) if installed else False
            active = active_state == "active" if installed else False

            if installed:
                return ServiceStatusResult(
                    query_name=name,
                    matched_name=unit_id,
                    systemd_available=True,
                    exists=exists,
                    installed=installed,
                    enabled=enabled,
                    active=active,
                    load_state=load_state,
                    unit_file_state=unit_file_state,
                    active_state=active_state,
                    sub_state=sub_state,
                    fragment_path=fragment_path or None,
                    status="ok",
                    success=True,
                    message="서비스 상태 확인에 성공했습니다.",
                    evidence=last_evidence,
                )

        return ServiceStatusResult(
            query_name=name,
            matched_name=None,
            systemd_available=True,
            exists=False,
            installed=False,
            enabled=False,
            active=False,
            load_state="not-found",
            unit_file_state=None,
            active_state=None,
            sub_state=None,
            fragment_path=None,
            status="not_found",
            success=False,
            message="해당 서비스 유닛을 찾지 못했습니다.",
            error_type="ServiceNotFoundError",
            evidence=last_evidence,
        )

    def inspect_many(
        self,
        services: Iterable[dict[str, Any] | str],
    ) -> list[ServiceStatusResult]:
        """
        여러 서비스를 순차적으로 확인한다.

        입력 예시:
        - ["ssh", "cron"]
        - [{"name": "ssh", "aliases": ["sshd"]}, {"name": "telnet", "aliases": ["inetd", "xinetd"]}]
        """
        results: list[ServiceStatusResult] = []

        for item in services:
            if isinstance(item, str):
                results.append(self.inspect(item))
            else:
                name = item.get("name", "")
                aliases = item.get("aliases", [])
                results.append(self.inspect(name, aliases=aliases))

        return results

    def is_active(self, name: str, *, aliases: Optional[list[str]] = None) -> bool:
        result = self.inspect(name, aliases=aliases)
        return bool(result.active)

    def is_enabled(self, name: str, *, aliases: Optional[list[str]] = None) -> bool:
        result = self.inspect(name, aliases=aliases)
        return bool(result.enabled)

    def is_installed(self, name: str, *, aliases: Optional[list[str]] = None) -> bool:
        result = self.inspect(name, aliases=aliases)
        return bool(result.installed)

    def _run_show(self, unit_name: str) -> ServiceCommandResult:
        command = [
            "systemctl",
            "show",
            unit_name,
            "--no-pager",
            "--property",
            "Id,LoadState,UnitFileState,ActiveState,SubState,FragmentPath",
        ]

        try:
            completed = subprocess.run(
                command,
                text=True,
                capture_output=True,
                timeout=self.timeout,
                check=False,
            )
            return ServiceCommandResult(
                command=command,
                returncode=completed.returncode,
                stdout=completed.stdout.strip(),
                stderr=completed.stderr.strip(),
            )

        except subprocess.TimeoutExpired as exc:
            return ServiceCommandResult(
                command=command,
                returncode=124,
                stdout="",
                stderr=f"timeout: {exc}",
            )

        except Exception as exc:
            return ServiceCommandResult(
                command=command,
                returncode=999,
                stdout="",
                stderr=str(exc),
            )

    @staticmethod
    def _build_candidates(name: str, aliases: list[str]) -> list[str]:
        """
        확인 후보 유닛명을 생성한다.
        예:
        - ssh -> ssh, ssh.service, ssh.socket
        - sshd -> sshd, sshd.service, sshd.socket
        """
        ordered = [name, *aliases]
        candidates: list[str] = []
        seen: set[str] = set()

        for item in ordered:
            if not item:
                continue

            expanded = [item]

            if "." not in item:
                expanded.extend(
                    [
                        f"{item}.service",
                        f"{item}.socket",
                        f"{item}.target",
                    ]
                )

            for unit in expanded:
                if unit not in seen:
                    candidates.append(unit)
                    seen.add(unit)

        return candidates

    @staticmethod
    def _parse_show_output(output: str) -> dict[str, str]:
        """
        systemctl show 결과를 key=value 딕셔너리로 변환
        """
        parsed: dict[str, str] = {}

        for line in output.splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            parsed[key.strip()] = value.strip()

        return parsed

    @staticmethod
    def _to_enabled(unit_file_state: Optional[str]) -> Optional[bool]:
        if unit_file_state is None:
            return None

        enabled_states = {
            "enabled",
            "enabled-runtime",
            "linked",
            "linked-runtime",
            "alias",
        }

        disabled_states = {
            "disabled",
            "masked",
            "masked-runtime",
            "static",
            "indirect",
            "generated",
            "transient",
            "bad",
        }

        if unit_file_state in enabled_states:
            return True

        if unit_file_state in disabled_states:
            return False

        return None


def inspect_service(
    name: str,
    *,
    aliases: Optional[list[str]] = None,
    timeout: int = 5,
) -> ServiceStatusResult:
    """
    간단 호출용 헬퍼 함수.
    """
    reader = ServiceReader(timeout=timeout)
    return reader.inspect(name, aliases=aliases)


def inspect_services(
    services: Iterable[dict[str, Any] | str],
    *,
    timeout: int = 5,
) -> list[ServiceStatusResult]:
    """
    여러 서비스 간단 호출용 헬퍼 함수.
    """
    reader = ServiceReader(timeout=timeout)
    return reader.inspect_many(services)