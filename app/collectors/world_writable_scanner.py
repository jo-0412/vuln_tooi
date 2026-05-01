# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

import os
import stat

try:
    import pwd
except Exception:  # pragma: no cover
    pwd = None

try:
    import grp
except Exception:  # pragma: no cover
    grp = None

from app.compat import to_text


class WorldWritableFileItem(object):
    """
    world writable 파일 1개의 정보를 담는 객체

    기능:
    - 파일 경로
    - 권한 값
    - 소유자/그룹
    - 일반 파일 여부
    - evidence 출력용 dict 변환

    U-23 permission_scanner와의 차이점:
    - U-23은 SUID/SGID/Sticky bit를 찾음
    - 이 스캐너는 others write 권한이 있는 일반 파일만 찾음
    """

    def __init__(self, path, mode_octal, mode_text,
                 uid, gid, owner_name, group_name):
        self.path = path
        self.mode_octal = mode_octal
        self.mode_text = mode_text
        self.uid = uid
        self.gid = gid
        self.owner_name = owner_name
        self.group_name = group_name

    def to_dict(self):
        return {
            "path": self.path,
            "mode_octal": self.mode_octal,
            "mode_text": self.mode_text,
            "uid": self.uid,
            "gid": self.gid,
            "owner_name": self.owner_name,
            "group_name": self.group_name,
        }


class WorldWritableScanResult(object):
    """
    world writable 스캔 결과 객체

    기능:
    - 스캔 성공/부분 성공/실패 상태 저장
    - 탐지 파일 목록 저장
    - 오류 및 경고 저장
    - 통계 정보 저장
    """

    def __init__(self, status, success, roots, exclude_paths,
                 world_writable_files=None, errors=None,
                 warnings=None, stats=None):
        self.status = status
        self.success = success
        self.roots = roots or []
        self.exclude_paths = exclude_paths or []
        self.world_writable_files = world_writable_files or []
        self.errors = errors or []
        self.warnings = warnings or []
        self.stats = stats or {}

    def to_dict(self):
        return {
            "status": self.status,
            "success": self.success,
            "roots": self.roots,
            "exclude_paths": self.exclude_paths,
            "world_writable_files": [
                item.to_dict() for item in self.world_writable_files
            ],
            "errors": self.errors,
            "warnings": self.warnings,
            "stats": self.stats,
        }


class WorldWritableScanner(object):
    """
    U-25 world writable 파일 점검용 스캐너

    주요 기능:
    - 전체 파일시스템 또는 지정 경로 순회
    - 일반 파일만 검사
    - others write 권한이 있는 파일 수집
    - /proc, /sys, /dev 같은 제외 경로 건너뛰기
    - xdev=True일 때 다른 파일시스템으로 넘어가지 않음

    차별점:
    - subprocess로 find 명령을 실행하지 않고 Python os.walk 기반으로 동작
    - Python 2.7 ~ 3.x 호환
    - 결과를 객체 형태로 반환해서 runner에서 evidence로 쓰기 쉬움
    """

    def __init__(self, follow_symlinks=False):
        self.follow_symlinks = follow_symlinks

    def scan(self, roots=None, exclude_paths=None, xdev=True):
        roots = roots or ["/"]
        exclude_paths = exclude_paths or []

        normalized_roots = self._normalize_paths(roots)
        normalized_excludes = self._normalize_paths(exclude_paths)

        world_writable_files = []
        errors = []
        warnings = []

        seen_paths = set()
        total_files = 0
        total_dirs = 0

        for root in normalized_roots:
            if not os.path.exists(root):
                warnings.append("Scan root does not exist: {0}".format(root))
                continue

            if self._is_excluded(root, normalized_excludes):
                warnings.append("Scan root is excluded: {0}".format(root))
                continue

            root_dev = None
            if xdev:
                try:
                    root_dev = os.lstat(root).st_dev
                except Exception as exc:
                    errors.append(
                        "Failed to inspect root device: {0} ({1})".format(
                            root,
                            to_text(exc)
                        )
                    )
                    continue

            onerror = self._build_onerror(errors)

            for dirpath, dirnames, filenames in os.walk(
                root,
                topdown=True,
                onerror=onerror,
                followlinks=self.follow_symlinks
            ):
                # 제외 경로와 다른 파일시스템을 사전에 가지치기한다.
                pruned_dirs = []

                for dirname in list(dirnames):
                    full_dir = os.path.join(dirpath, dirname)

                    if self._is_excluded(full_dir, normalized_excludes):
                        continue

                    if xdev:
                        try:
                            st_dir = os.lstat(full_dir)
                            if st_dir.st_dev != root_dev:
                                continue
                        except Exception as exc:
                            warnings.append(
                                "Failed to inspect directory metadata: {0} ({1})".format(
                                    full_dir,
                                    to_text(exc)
                                )
                            )
                            continue

                    pruned_dirs.append(dirname)

                dirnames[:] = pruned_dirs

                try:
                    total_dirs += 1
                except Exception:
                    pass

                for filename in filenames:
                    full_path = os.path.join(dirpath, filename)

                    if self._is_excluded(full_path, normalized_excludes):
                        continue

                    try:
                        st_file = os.lstat(full_path)
                        total_files += 1
                    except Exception as exc:
                        warnings.append(
                            "Failed to inspect file metadata: {0} ({1})".format(
                                full_path,
                                to_text(exc)
                            )
                        )
                        continue

                    # 일반 파일만 검사한다. 심볼릭 링크, 디렉터리, 장치 파일은 제외한다.
                    if not stat.S_ISREG(st_file.st_mode):
                        continue

                    if xdev and root_dev is not None and st_file.st_dev != root_dev:
                        continue

                    # others write 권한이 있는지 확인한다.
                    if not (st_file.st_mode & stat.S_IWOTH):
                        continue

                    if full_path in seen_paths:
                        continue

                    seen_paths.add(full_path)

                    world_writable_files.append(
                        self._build_item(full_path, st_file)
                    )

        if errors and not world_writable_files:
            status = "error"
            success = False
        elif errors or warnings:
            status = "partial"
            success = True
        else:
            status = "ok"
            success = True

        stats = {
            "world_writable_count": len(world_writable_files),
            "total_files_scanned": total_files,
            "total_dirs_scanned": total_dirs,
        }

        return WorldWritableScanResult(
            status=status,
            success=success,
            roots=normalized_roots,
            exclude_paths=normalized_excludes,
            world_writable_files=world_writable_files,
            errors=errors,
            warnings=warnings,
            stats=stats,
        )

    def _build_item(self, path, st_obj):
        mode_octal = "%04o" % (st_obj.st_mode & 0o7777)
        mode_text = self._format_mode_text(st_obj.st_mode)

        return WorldWritableFileItem(
            path=to_text(path),
            mode_octal=mode_octal,
            mode_text=mode_text,
            uid=st_obj.st_uid,
            gid=st_obj.st_gid,
            owner_name=self._resolve_owner(st_obj.st_uid),
            group_name=self._resolve_group(st_obj.st_gid),
        )

    @staticmethod
    def _build_onerror(errors):
        def _handler(exc):
            filename = getattr(exc, "filename", "")
            if filename:
                errors.append("Directory traversal error: {0}".format(
                    to_text(filename)
                ))
            else:
                errors.append("Directory traversal error: {0}".format(
                    to_text(exc)
                ))
        return _handler

    @staticmethod
    def _normalize_paths(paths):
        normalized = []
        seen = set()

        for path in paths:
            value = os.path.abspath(to_text(path).strip())
            if not value:
                continue

            if value not in seen:
                seen.add(value)
                normalized.append(value)

        return normalized

    @staticmethod
    def _is_excluded(path, exclude_paths):
        norm_path = os.path.abspath(to_text(path))

        for excluded in exclude_paths:
            if norm_path == excluded:
                return True

            if norm_path.startswith(excluded + os.sep):
                return True

        return False

    @staticmethod
    def _format_mode_text(st_mode):
        type_char = "-"

        perms = []

        perms.append("r" if st_mode & stat.S_IRUSR else "-")
        perms.append("w" if st_mode & stat.S_IWUSR else "-")
        perms.append("x" if st_mode & stat.S_IXUSR else "-")

        perms.append("r" if st_mode & stat.S_IRGRP else "-")
        perms.append("w" if st_mode & stat.S_IWGRP else "-")
        perms.append("x" if st_mode & stat.S_IXGRP else "-")

        perms.append("r" if st_mode & stat.S_IROTH else "-")
        perms.append("w" if st_mode & stat.S_IWOTH else "-")
        perms.append("x" if st_mode & stat.S_IXOTH else "-")

        return type_char + "".join(perms)

    @staticmethod
    def _resolve_owner(uid):
        if pwd is None:
            return to_text(uid)

        try:
            return to_text(pwd.getpwuid(uid).pw_name)
        except Exception:
            return to_text(uid)

    @staticmethod
    def _resolve_group(gid):
        if grp is None:
            return to_text(gid)

        try:
            return to_text(grp.getgrgid(gid).gr_name)
        except Exception:
            return to_text(gid)