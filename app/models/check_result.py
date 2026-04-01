# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

from app.compat import now_iso


VALID_STATUSES = set(["PASS", "FAIL", "MANUAL", "ERROR"])


class EvidenceItem(object):
    def __init__(self, key, label, source, value,
                 status="info", excerpt=None, notes=None):
        self.key = key
        self.label = label
        self.source = source
        self.value = value
        self.status = status
        self.excerpt = excerpt
        self.notes = notes

    def to_dict(self):
        return {
            "key": self.key,
            "label": self.label,
            "source": self.source,
            "value": self.value,
            "status": self.status,
            "excerpt": self.excerpt,
            "notes": self.notes,
        }


class CheckResult(object):
    def __init__(self, code, name, severity, category, status, success,
                 summary, detail, requires_root="unknown",
                 remediation_summary=None, remediation_steps=None,
                 evidences=None, errors=None, raw=None, checked_at=None):
        self.code = code
        self.name = name
        self.severity = severity
        self.category = category
        self.status = str(status).upper()
        self.success = success
        self.summary = summary
        self.detail = detail
        self.requires_root = requires_root
        self.remediation_summary = remediation_summary
        self.remediation_steps = remediation_steps or []
        self.evidences = evidences or []
        self.errors = errors or []
        self.raw = raw or {}
        self.checked_at = checked_at or now_iso()

        if self.status not in VALID_STATUSES:
            raise ValueError("지원하지 않는 상태값입니다: {0}".format(self.status))

    def add_evidence(self, key, label, source, value,
                     status="info", excerpt=None, notes=None):
        self.evidences.append(
            EvidenceItem(
                key=key,
                label=label,
                source=source,
                value=value,
                status=status,
                excerpt=excerpt,
                notes=notes,
            )
        )

    def add_error(self, message):
        if message and message not in self.errors:
            self.errors.append(message)

    def set_status(self, status, success=None):
        normalized = str(status).upper()

        if normalized not in VALID_STATUSES:
            raise ValueError("지원하지 않는 상태값입니다: {0}".format(normalized))

        self.status = normalized

        if success is None:
            self.success = normalized in ("PASS", "MANUAL")
        else:
            self.success = success

    def to_dict(self):
        return {
            "code": self.code,
            "name": self.name,
            "severity": self.severity,
            "category": self.category,
            "status": self.status,
            "success": self.success,
            "summary": self.summary,
            "detail": self.detail,
            "requires_root": self.requires_root,
            "remediation_summary": self.remediation_summary,
            "remediation_steps": self.remediation_steps,
            "evidences": [e.to_dict() for e in self.evidences],
            "errors": self.errors,
            "raw": self.raw,
            "checked_at": self.checked_at,
        }