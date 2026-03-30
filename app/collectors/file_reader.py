from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Optional
import os
import stat


@dataclass
class FileMetadata:
    path: str
    exists: bool
    is_file: bool
    is_symlink: bool
    size: Optional[int]
    mode: Optional[str]
    uid: Optional[int]
    gid: Optional[int]


@dataclass
class FileReadResult:
    path: str
    status: str
    success: bool
    message: str
    metadata: FileMetadata
    content: Optional[str] = None
    encoding: Optional[str] = None
    line_count: int = 0
    error_type: Optional[str] = None
    error_detail: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class FileReader:
    """
    공통 파일 읽기 수집기.
    특정 취약점 항목(U-01 등)에 의존하지 않고,
    파일 존재/권한/내용 읽기 결과를 표준 형식으로 반환한다.
    """

    def __init__(
        self,
        default_encoding: str = "utf-8",
        default_errors: str = "replace",
        default_max_bytes: Optional[int] = None,
    ) -> None:
        self.default_encoding = default_encoding
        self.default_errors = default_errors
        self.default_max_bytes = default_max_bytes

    def inspect(self, path: str | Path) -> FileReadResult:
        """
        파일 내용은 읽지 않고 메타데이터만 확인한다.
        """
        target = Path(path)
        metadata = self._build_metadata(target)

        if not metadata.exists:
            return FileReadResult(
                path=str(target),
                status="not_found",
                success=False,
                message="파일이 존재하지 않습니다.",
                metadata=metadata,
                error_type="FileNotFoundError",
            )

        if not metadata.is_file:
            return FileReadResult(
                path=str(target),
                status="not_file",
                success=False,
                message="경로가 일반 파일이 아닙니다.",
                metadata=metadata,
                error_type="NotAFileError",
            )

        return FileReadResult(
            path=str(target),
            status="ok",
            success=True,
            message="파일 메타데이터 확인에 성공했습니다.",
            metadata=metadata,
        )

    def read(
        self,
        path: str | Path,
        *,
        encoding: Optional[str] = None,
        errors: Optional[str] = None,
        max_bytes: Optional[int] = None,
        follow_symlinks: bool = True,
    ) -> FileReadResult:
        """
        파일을 안전하게 읽어 표준 결과로 반환한다.
        """
        target = Path(path)
        metadata = self._build_metadata(target)

        if not metadata.exists:
            return FileReadResult(
                path=str(target),
                status="not_found",
                success=False,
                message="파일이 존재하지 않습니다.",
                metadata=metadata,
                error_type="FileNotFoundError",
            )

        if not metadata.is_file:
            return FileReadResult(
                path=str(target),
                status="not_file",
                success=False,
                message="경로가 일반 파일이 아닙니다.",
                metadata=metadata,
                error_type="NotAFileError",
            )

        if metadata.is_symlink and not follow_symlinks:
            return FileReadResult(
                path=str(target),
                status="symlink_blocked",
                success=False,
                message="심볼릭 링크는 허용되지 않습니다.",
                metadata=metadata,
                error_type="SymlinkNotAllowedError",
            )

        use_encoding = encoding or self.default_encoding
        use_errors = errors or self.default_errors
        use_max_bytes = max_bytes if max_bytes is not None else self.default_max_bytes

        try:
            raw = self._read_bytes(target, use_max_bytes)
            content = raw.decode(use_encoding, errors=use_errors)
            line_count = self._count_lines(content)

            return FileReadResult(
                path=str(target),
                status="ok",
                success=True,
                message="파일 읽기에 성공했습니다.",
                metadata=metadata,
                content=content,
                encoding=use_encoding,
                line_count=line_count,
            )

        except PermissionError as exc:
            return FileReadResult(
                path=str(target),
                status="permission_denied",
                success=False,
                message="파일 읽기 권한이 없습니다.",
                metadata=metadata,
                error_type=type(exc).__name__,
                error_detail=str(exc),
            )

        except IsADirectoryError as exc:
            return FileReadResult(
                path=str(target),
                status="not_file",
                success=False,
                message="경로가 디렉터리입니다.",
                metadata=metadata,
                error_type=type(exc).__name__,
                error_detail=str(exc),
            )

        except OSError as exc:
            return FileReadResult(
                path=str(target),
                status="read_error",
                success=False,
                message="파일 읽기 중 운영체제 오류가 발생했습니다.",
                metadata=metadata,
                error_type=type(exc).__name__,
                error_detail=str(exc),
            )

        except Exception as exc:
            return FileReadResult(
                path=str(target),
                status="unknown_error",
                success=False,
                message="알 수 없는 오류가 발생했습니다.",
                metadata=metadata,
                error_type=type(exc).__name__,
                error_detail=str(exc),
            )

    def read_many(
        self,
        paths: Iterable[str | Path],
        *,
        encoding: Optional[str] = None,
        errors: Optional[str] = None,
        max_bytes: Optional[int] = None,
        follow_symlinks: bool = True,
    ) -> list[FileReadResult]:
        """
        여러 파일을 순차적으로 읽는다.
        """
        results: list[FileReadResult] = []
        for path in paths:
            results.append(
                self.read(
                    path,
                    encoding=encoding,
                    errors=errors,
                    max_bytes=max_bytes,
                    follow_symlinks=follow_symlinks,
                )
            )
        return results

    def exists(self, path: str | Path) -> bool:
        return Path(path).exists()

    def _build_metadata(self, path: Path) -> FileMetadata:
        try:
            st = path.lstat()
            mode_str = stat.filemode(st.st_mode)

            return FileMetadata(
                path=str(path),
                exists=True,
                is_file=path.is_file(),
                is_symlink=path.is_symlink(),
                size=st.st_size,
                mode=mode_str,
                uid=st.st_uid,
                gid=st.st_gid,
            )

        except FileNotFoundError:
            return FileMetadata(
                path=str(path),
                exists=False,
                is_file=False,
                is_symlink=False,
                size=None,
                mode=None,
                uid=None,
                gid=None,
            )

        except PermissionError:
            # 파일 존재는 하지만 stat 확인이 제한될 수도 있음
            return FileMetadata(
                path=str(path),
                exists=True,
                is_file=False,
                is_symlink=False,
                size=None,
                mode=None,
                uid=None,
                gid=None,
            )

        except OSError:
            return FileMetadata(
                path=str(path),
                exists=False,
                is_file=False,
                is_symlink=False,
                size=None,
                mode=None,
                uid=None,
                gid=None,
            )

    @staticmethod
    def _read_bytes(path: Path, max_bytes: Optional[int]) -> bytes:
        with path.open("rb") as f:
            if max_bytes is None:
                return f.read()
            return f.read(max_bytes)

    @staticmethod
    def _count_lines(content: str) -> int:
        if not content:
            return 0
        return len(content.splitlines())


def read_file(
    path: str | Path,
    *,
    encoding: str = "utf-8",
    errors: str = "replace",
    max_bytes: Optional[int] = None,
    follow_symlinks: bool = True,
) -> FileReadResult:
    """
    간단 호출용 헬퍼 함수.
    """
    reader = FileReader(
        default_encoding=encoding,
        default_errors=errors,
        default_max_bytes=max_bytes,
    )
    return reader.read(
        path,
        encoding=encoding,
        errors=errors,
        max_bytes=max_bytes,
        follow_symlinks=follow_symlinks,
    )


def inspect_file(path: str | Path) -> FileReadResult:
    """
    메타데이터만 확인하는 간단 호출용 헬퍼 함수.
    """
    reader = FileReader()
    return reader.inspect(path)