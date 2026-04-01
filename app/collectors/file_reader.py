# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

import errno
import os
import stat


def _format_mode(st_mode):
    try:
        if hasattr(stat, "filemode"):
            return stat.filemode(st_mode)
    except Exception:
        pass
    return oct(st_mode & 0o7777)


class FileMetadata(object):
    def __init__(self, path, exists, is_file, is_symlink,
                 size=None, mode=None, uid=None, gid=None):
        self.path = path
        self.exists = exists
        self.is_file = is_file
        self.is_symlink = is_symlink
        self.size = size
        self.mode = mode
        self.uid = uid
        self.gid = gid

    def to_dict(self):
        return {
            "path": self.path,
            "exists": self.exists,
            "is_file": self.is_file,
            "is_symlink": self.is_symlink,
            "size": self.size,
            "mode": self.mode,
            "uid": self.uid,
            "gid": self.gid,
        }


class FileReadResult(object):
    def __init__(self, path, status, success, message, metadata,
                 content=None, encoding=None, line_count=0,
                 error_type=None, error_detail=None):
        self.path = path
        self.status = status
        self.success = success
        self.message = message
        self.metadata = metadata
        self.content = content
        self.encoding = encoding
        self.line_count = line_count
        self.error_type = error_type
        self.error_detail = error_detail

    def to_dict(self):
        return {
            "path": self.path,
            "status": self.status,
            "success": self.success,
            "message": self.message,
            "metadata": self.metadata.to_dict(),
            "content": self.content,
            "encoding": self.encoding,
            "line_count": self.line_count,
            "error_type": self.error_type,
            "error_detail": self.error_detail,
        }


class FileReader(object):
    """
    공통 파일 읽기 수집기.
    특정 취약점 항목(U-01 등)에 의존하지 않고,
    파일 존재/권한/내용 읽기 결과를 표준 형식으로 반환한다.
    """

    def __init__(self, default_encoding="utf-8",
                 default_errors="replace", default_max_bytes=None):
        self.default_encoding = default_encoding
        self.default_errors = default_errors
        self.default_max_bytes = default_max_bytes

    def exists(self, path):
        return os.path.exists(path)

    def inspect(self, path):
        metadata = self._build_metadata(path)

        if not metadata.exists:
            return FileReadResult(
                path=path,
                status="not_found",
                success=False,
                message="파일이 존재하지 않습니다.",
                metadata=metadata,
                error_type="FileNotFoundError",
            )

        if not metadata.is_file:
            return FileReadResult(
                path=path,
                status="not_file",
                success=False,
                message="경로가 일반 파일이 아닙니다.",
                metadata=metadata,
                error_type="NotAFileError",
            )

        return FileReadResult(
            path=path,
            status="ok",
            success=True,
            message="파일 메타데이터 확인에 성공했습니다.",
            metadata=metadata,
        )

    def read(self, path, encoding=None, errors=None,
             max_bytes=None, follow_symlinks=True):
        metadata = self._build_metadata(path)

        if not metadata.exists:
            return FileReadResult(
                path=path,
                status="not_found",
                success=False,
                message="파일이 존재하지 않습니다.",
                metadata=metadata,
                error_type="FileNotFoundError",
            )

        if not metadata.is_file:
            return FileReadResult(
                path=path,
                status="not_file",
                success=False,
                message="경로가 일반 파일이 아닙니다.",
                metadata=metadata,
                error_type="NotAFileError",
            )

        if metadata.is_symlink and not follow_symlinks:
            return FileReadResult(
                path=path,
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
            raw = self._read_bytes(path, use_max_bytes)
            content = raw.decode(use_encoding, use_errors)
            line_count = self._count_lines(content)

            return FileReadResult(
                path=path,
                status="ok",
                success=True,
                message="파일 읽기에 성공했습니다.",
                metadata=metadata,
                content=content,
                encoding=use_encoding,
                line_count=line_count,
            )

        except (IOError, OSError) as exc:
            err_no = getattr(exc, "errno", None)

            if err_no == errno.EACCES:
                return FileReadResult(
                    path=path,
                    status="permission_denied",
                    success=False,
                    message="파일 읽기 권한이 없습니다.",
                    metadata=metadata,
                    error_type=type(exc).__name__,
                    error_detail=str(exc),
                )

            if err_no == errno.EISDIR:
                return FileReadResult(
                    path=path,
                    status="not_file",
                    success=False,
                    message="경로가 디렉터리입니다.",
                    metadata=metadata,
                    error_type=type(exc).__name__,
                    error_detail=str(exc),
                )

            return FileReadResult(
                path=path,
                status="read_error",
                success=False,
                message="파일 읽기 중 운영체제 오류가 발생했습니다.",
                metadata=metadata,
                error_type=type(exc).__name__,
                error_detail=str(exc),
            )

        except Exception as exc:
            return FileReadResult(
                path=path,
                status="unknown_error",
                success=False,
                message="알 수 없는 오류가 발생했습니다.",
                metadata=metadata,
                error_type=type(exc).__name__,
                error_detail=str(exc),
            )

    def read_many(self, paths, encoding=None, errors=None,
                  max_bytes=None, follow_symlinks=True):
        results = []
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

    def _build_metadata(self, path):
        try:
            st = os.lstat(path)
            mode_str = _format_mode(st.st_mode)

            return FileMetadata(
                path=path,
                exists=True,
                is_file=os.path.isfile(path),
                is_symlink=os.path.islink(path),
                size=st.st_size,
                mode=mode_str,
                uid=st.st_uid,
                gid=st.st_gid,
            )

        except (IOError, OSError):
            return FileMetadata(
                path=path,
                exists=False,
                is_file=False,
                is_symlink=False,
                size=None,
                mode=None,
                uid=None,
                gid=None,
            )

    @staticmethod
    def _read_bytes(path, max_bytes):
        f = open(path, "rb")
        try:
            if max_bytes is None:
                return f.read()
            return f.read(max_bytes)
        finally:
            f.close()

    @staticmethod
    def _count_lines(content):
        if not content:
            return 0
        return len(content.splitlines())


def read_file(path, encoding="utf-8", errors="replace",
              max_bytes=None, follow_symlinks=True):
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


def inspect_file(path):
    reader = FileReader()
    return reader.inspect(path)