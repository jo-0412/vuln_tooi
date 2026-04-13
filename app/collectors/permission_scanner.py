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


class PermissionItem(object):
    def __init__(self, path, item_type, mode_octal, mode_text,
                 uid, gid, owner_name, group_name, root_owned):
        self.path = path
        self.item_type = item_type
        self.mode_octal = mode_octal
        self.mode_text = mode_text
        self.uid = uid
        self.gid = gid
        self.owner_name = owner_name
        self.group_name = group_name
        self.root_owned = root_owned

    def to_dict(self):
        return {
            "path": self.path,
            "item_type": self.item_type,
            "mode_octal": self.mode_octal,
            "mode_text": self.mode_text,
            "uid": self.uid,
            "gid": self.gid,
            "owner_name": self.owner_name,
            "group_name": self.group_name,
            "root_owned": self.root_owned,
        }


class PermissionScanResult(object):
    def __init__(self, status, success, roots, exclude_paths,
                 suid_files=None, sgid_files=None, sticky_dirs=None,
                 errors=None, warnings=None, stats=None):
        self.status = status
        self.success = success
        self.roots = roots or []
        self.exclude_paths = exclude_paths or []
        self.suid_files = suid_files or []
        self.sgid_files = sgid_files or []
        self.sticky_dirs = sticky_dirs or []
        self.errors = errors or []
        self.warnings = warnings or []
        self.stats = stats or {}

    def to_dict(self):
        return {
            "status": self.status,
            "success": self.success,
            "roots": self.roots,
            "exclude_paths": self.exclude_paths,
            "suid_files": [item.to_dict() for item in self.suid_files],
            "sgid_files": [item.to_dict() for item in self.sgid_files],
            "sticky_dirs": [item.to_dict() for item in self.sticky_dirs],
            "errors": self.errors,
            "warnings": self.warnings,
            "stats": self.stats,
        }


class PermissionScanner(object):
    """
    전체 파일시스템 또는 지정 경로를 순회하면서
    SUID / SGID / Sticky bit 설정 항목을 수집한다.
    """

    def __init__(self, follow_symlinks=False):
        self.follow_symlinks = follow_symlinks

    def scan(self, roots=None, exclude_paths=None, xdev=True, root_owned_only=True):
        roots = roots or ["/"]
        exclude_paths = exclude_paths or []

        normalized_roots = self._normalize_paths(roots)
        normalized_excludes = self._normalize_paths(exclude_paths)

        suid_files = []
        sgid_files = []
        sticky_dirs = []

        errors = []
        warnings = []

        seen_suid = set()
        seen_sgid = set()
        seen_sticky = set()

        total_files = 0
        total_dirs = 0

        for root in normalized_roots:
            if not os.path.exists(root):
                warnings.append("스캔 시작 경로가 존재하지 않습니다: {0}".format(root))
                continue

            if self._is_excluded(root, normalized_excludes):
                warnings.append("스캔 시작 경로가 제외 목록에 포함되어 건너뜁니다: {0}".format(root))
                continue

            root_dev = None
            if xdev:
                try:
                    root_dev = os.lstat(root).st_dev
                except Exception as exc:
                    errors.append("루트 경로 장치 정보를 확인하지 못했습니다: {0} ({1})".format(
                        root,
                        to_text(exc)
                    ))
                    continue

            onerror = self._build_onerror(errors)

            for dirpath, dirnames, filenames in os.walk(
                root,
                topdown=True,
                onerror=onerror,
                followlinks=self.follow_symlinks
            ):
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
                            warnings.append("디렉터리 장치 정보를 확인하지 못해 제외합니다: {0} ({1})".format(
                                full_dir,
                                to_text(exc)
                            ))
                            continue

                    pruned_dirs.append(dirname)

                dirnames[:] = pruned_dirs

                try:
                    st_current = os.lstat(dirpath)
                    total_dirs += 1

                    if stat.S_ISDIR(st_current.st_mode):
                        if st_current.st_mode & stat.S_ISVTX:
                            item = self._build_item(dirpath, "sticky_dir", st_current)
                            if item.path not in seen_sticky:
                                sticky_dirs.append(item)
                                seen_sticky.add(item.path)
                except Exception as exc:
                    warnings.append("디렉터리 메타데이터를 확인하지 못했습니다: {0} ({1})".format(
                        dirpath,
                        to_text(exc)
                    ))

                for filename in filenames:
                    full_path = os.path.join(dirpath, filename)

                    if self._is_excluded(full_path, normalized_excludes):
                        continue

                    try:
                        st_file = os.lstat(full_path)
                        total_files += 1
                    except Exception as exc:
                        warnings.append("파일 메타데이터를 확인하지 못했습니다: {0} ({1})".format(
                            full_path,
                            to_text(exc)
                        ))
                        continue

                    if not stat.S_ISREG(st_file.st_mode):
                        continue

                    if xdev and st_file.st_dev != root_dev:
                        continue

                    is_root_owned = (st_file.st_uid == 0)

                    if (st_file.st_mode & stat.S_ISUID):
                        if (not root_owned_only) or is_root_owned:
                            item = self._build_item(full_path, "suid_file", st_file)
                            if item.path not in seen_suid:
                                suid_files.append(item)
                                seen_suid.add(item.path)

                    if (st_file.st_mode & stat.S_ISGID):
                        if (not root_owned_only) or is_root_owned:
                            item = self._build_item(full_path, "sgid_file", st_file)
                            if item.path not in seen_sgid:
                                sgid_files.append(item)
                                seen_sgid.add(item.path)

        if errors and not (suid_files or sgid_files or sticky_dirs):
            status = "error"
            success = False
        elif errors or warnings:
            status = "partial"
            success = True
        else:
            status = "ok"
            success = True

        stats = {
            "suid_count": len(suid_files),
            "sgid_count": len(sgid_files),
            "sticky_dir_count": len(sticky_dirs),
            "total_files_scanned": total_files,
            "total_dirs_scanned": total_dirs,
        }

        return PermissionScanResult(
            status=status,
            success=success,
            roots=normalized_roots,
            exclude_paths=normalized_excludes,
            suid_files=suid_files,
            sgid_files=sgid_files,
            sticky_dirs=sticky_dirs,
            errors=errors,
            warnings=warnings,
            stats=stats,
        )

    def _build_onerror(self, errors):
        def _handler(exc):
            filename = getattr(exc, "filename", None)
            if filename:
                errors.append("디렉터리 순회 오류: {0}".format(to_text(filename)))
            else:
                errors.append("디렉터리 순회 오류: {0}".format(to_text(exc)))
        return _handler

    def _build_item(self, path, item_type, st_obj):
        uid = st_obj.st_uid
        gid = st_obj.st_gid
        owner_name = self._resolve_owner(uid)
        group_name = self._resolve_group(gid)
        mode_octal = "%04o" % (st_obj.st_mode & 0o7777)
        mode_text = self._format_mode_text(st_obj.st_mode)

        return PermissionItem(
            path=to_text(path),
            item_type=item_type,
            mode_octal=mode_octal,
            mode_text=mode_text,
            uid=uid,
            gid=gid,
            owner_name=owner_name,
            group_name=group_name,
            root_owned=(uid == 0),
        )

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
        if stat.S_ISDIR(st_mode):
            type_char = "d"
        elif stat.S_ISLNK(st_mode):
            type_char = "l"
        elif stat.S_ISCHR(st_mode):
            type_char = "c"
        elif stat.S_ISBLK(st_mode):
            type_char = "b"
        elif stat.S_ISSOCK(st_mode):
            type_char = "s"
        elif stat.S_ISFIFO(st_mode):
            type_char = "p"
        else:
            type_char = "-"

        perms = []

        # owner
        perms.append("r" if st_mode & stat.S_IRUSR else "-")
        perms.append("w" if st_mode & stat.S_IWUSR else "-")
        if st_mode & stat.S_ISUID:
            perms.append("s" if st_mode & stat.S_IXUSR else "S")
        else:
            perms.append("x" if st_mode & stat.S_IXUSR else "-")

        # group
        perms.append("r" if st_mode & stat.S_IRGRP else "-")
        perms.append("w" if st_mode & stat.S_IWGRP else "-")
        if st_mode & stat.S_ISGID:
            perms.append("s" if st_mode & stat.S_IXGRP else "S")
        else:
            perms.append("x" if st_mode & stat.S_IXGRP else "-")

        # other
        perms.append("r" if st_mode & stat.S_IROTH else "-")
        perms.append("w" if st_mode & stat.S_IWOTH else "-")
        if st_mode & stat.S_ISVTX:
            perms.append("t" if st_mode & stat.S_IXOTH else "T")
        else:
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