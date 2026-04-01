# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

import subprocess

try:
    import shutil
except Exception:
    shutil = None

try:
    from distutils.spawn import find_executable
except Exception:  # pragma: no cover
    find_executable = None


def _to_text(value, encoding="utf-8", errors="replace"):
    if value is None:
        return ""
    try:
        return value.decode(encoding, errors)
    except Exception:
        try:
            return str(value)
        except Exception:
            return ""


class ServiceCommandResult(object):
    def __init__(self, command, returncode, stdout, stderr):
        self.command = command
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr

    def to_dict(self):
        return {
            "command": self.command,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


class ServiceStatusResult(object):
    def __init__(self, query_name, matched_name, systemd_available,
                 exists, installed, enabled, active, load_state,
                 unit_file_state, active_state, sub_state,
                 fragment_path, status, success, message,
                 error_type=None, error_detail=None, evidence=None):
        self.query_name = query_name
        self.matched_name = matched_name
        self.systemd_available = systemd_available
        self.exists = exists
        self.installed = installed
        self.enabled = enabled
        self.active = active
        self.load_state = load_state
        self.unit_file_state = unit_file_state
        self.active_state = active_state
        self.sub_state = sub_state
        self.fragment_path = fragment_path
        self.status = status
        self.success = success
        self.message = message
        self.error_type = error_type
        self.error_detail = error_detail
        self.evidence = evidence or {}

    def to_dict(self):
        return {
            "query_name": self.query_name,
            "matched_name": self.matched_name,
            "systemd_available": self.systemd_available,
            "exists": self.exists,
            "installed": self.installed,
            "enabled": self.enabled,
            "active": self.active,
            "load_state": self.load_state,
            "unit_file_state": self.unit_file_state,
            "active_state": self.active_state,
            "sub_state": self.sub_state,
            "fragment_path": self.fragment_path,
            "status": self.status,
            "success": self.success,
            "message": self.message,
            "error_type": self.error_type,
            "error_detail": self.error_detail,
            "evidence": self.evidence,
        }


class ServiceReader(object):
    """
    systemd 기반 공통 서비스 상태 수집기.
    특정 취약점 항목(U-01 등)에 의존하지 않고,
    서비스의 존재 여부 / 설치 여부 / 활성화 여부 / 실행 여부를 표준 형식으로 반환한다.
    """

    def __init__(self, timeout=5):
        self.timeout = timeout

    def _which(self, name):
        if shutil is not None and hasattr(shutil, "which"):
            try:
                return shutil.which(name)
            except Exception:
                pass

        if find_executable is not None:
            try:
                return find_executable(name)
            except Exception:
                pass

        return None

    def is_systemd_available(self):
        return self._which("systemctl") is not None

    def inspect(self, name, aliases=None):
        aliases = aliases or []

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

        candidates = self._build_candidates(name, aliases)
        last_evidence = {"checked_candidates": candidates, "commands": []}

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
            active = (active_state == "active") if installed else False

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

    def inspect_many(self, services):
        results = []

        for item in services:
            if isinstance(item, dict):
                name = item.get("name", "")
                aliases = item.get("aliases", [])
                results.append(self.inspect(name, aliases=aliases))
            else:
                results.append(self.inspect(item))

        return results

    def is_active(self, name, aliases=None):
        result = self.inspect(name, aliases=aliases)
        return bool(result.active)

    def is_enabled(self, name, aliases=None):
        result = self.inspect(name, aliases=aliases)
        return bool(result.enabled)

    def is_installed(self, name, aliases=None):
        result = self.inspect(name, aliases=aliases)
        return bool(result.installed)

    def _run_show(self, unit_name):
        command = [
            "systemctl",
            "show",
            unit_name,
            "--no-pager",
            "--property",
            "Id,LoadState,UnitFileState,ActiveState,SubState,FragmentPath",
        ]

        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = proc.communicate()

            return ServiceCommandResult(
                command=command,
                returncode=proc.returncode,
                stdout=_to_text(stdout).strip(),
                stderr=_to_text(stderr).strip(),
            )

        except Exception as exc:
            return ServiceCommandResult(
                command=command,
                returncode=999,
                stdout="",
                stderr=str(exc),
            )

    @staticmethod
    def _build_candidates(name, aliases):
        ordered = [name] + list(aliases)
        candidates = []
        seen = set()

        for item in ordered:
            if not item:
                continue

            expanded = [item]
            if "." not in item:
                expanded.extend([
                    item + ".service",
                    item + ".socket",
                    item + ".target",
                ])

            for unit in expanded:
                if unit not in seen:
                    candidates.append(unit)
                    seen.add(unit)

        return candidates

    @staticmethod
    def _parse_show_output(output):
        parsed = {}

        for line in output.splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            parsed[key.strip()] = value.strip()

        return parsed

    @staticmethod
    def _to_enabled(unit_file_state):
        if unit_file_state is None:
            return None

        enabled_states = set([
            "enabled",
            "enabled-runtime",
            "linked",
            "linked-runtime",
            "alias",
        ])

        disabled_states = set([
            "disabled",
            "masked",
            "masked-runtime",
            "static",
            "indirect",
            "generated",
            "transient",
            "bad",
        ])

        if unit_file_state in enabled_states:
            return True

        if unit_file_state in disabled_states:
            return False

        return None


def inspect_service(name, aliases=None, timeout=5):
    reader = ServiceReader(timeout=timeout)
    return reader.inspect(name, aliases=aliases)


def inspect_services(services, timeout=5):
    reader = ServiceReader(timeout=timeout)
    return reader.inspect_many(services)