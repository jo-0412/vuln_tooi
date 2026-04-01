# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

import json
import sys

from app.compat import PY2, to_text


class ConsoleFormatter(object):
    def __init__(self, use_color=None):
        if use_color is None:
            self.use_color = sys.stdout.isatty()
        else:
            self.use_color = use_color

    def format(self, result, verbose=True):
        lines = []

        lines.append("[{0}] {1}".format(result.code, result.name))
        lines.append("상태: {0}".format(self._colorize_status(result.status)))
        lines.append("중요도: {0}".format(result.severity))
        lines.append("분류: {0}".format(result.category))
        lines.append("root 권한 필요 여부: {0}".format(result.requires_root))
        lines.append("점검 시각: {0}".format(result.checked_at))
        lines.append("")

        lines.append("요약")
        lines.append("- {0}".format(result.summary))
        lines.append("")

        lines.append("상세")
        for line in self._split_lines(result.detail):
            lines.append("- {0}".format(line))
        lines.append("")

        if result.remediation_summary or result.remediation_steps:
            lines.append("조치 안내")
            if result.remediation_summary:
                lines.append("- {0}".format(result.remediation_summary))
            for step in result.remediation_steps:
                lines.append("  * {0}".format(step))
            lines.append("")

        if verbose and result.evidences:
            lines.append("수집 증적")
            for evidence in result.evidences:
                lines.extend(self._format_evidence(evidence))
            lines.append("")

        if result.errors:
            lines.append("오류")
            for error in result.errors:
                lines.append("- {0}".format(error))
            lines.append("")

        return "\n".join(lines).rstrip() + "\n"

    def format_json(self, result):
        return json.dumps(result.to_dict(), ensure_ascii=False, indent=2)

    def print_result(self, result, verbose=True):
        output = self.format(result, verbose=verbose)
        self._write(output)

    def _write(self, text):
        text = to_text(text)

        if PY2:
            encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
            try:
                sys.stdout.write(text.encode(encoding, "replace"))
            except Exception:
                sys.stdout.write(text.encode("utf-8", "replace"))
        else:
            sys.stdout.write(text)

    def _format_evidence(self, evidence):
        lines = [
            "- {0}".format(evidence.label),
            "  source: {0}".format(evidence.source),
        ]

        value_text = self._value_to_text(evidence.value)
        value_lines = value_text.splitlines() or [value_text]
        lines.append("  value : {0}".format(value_lines[0]))

        for extra_line in value_lines[1:]:
            lines.append("          {0}".format(extra_line))

        if evidence.status:
            lines.append("  state : {0}".format(evidence.status))

        if evidence.excerpt:
            excerpt_lines = to_text(evidence.excerpt).splitlines()
            if excerpt_lines:
                lines.append("  excerpt: {0}".format(excerpt_lines[0]))
                for extra_line in excerpt_lines[1:]:
                    lines.append("           {0}".format(extra_line))

        if evidence.notes:
            notes_lines = to_text(evidence.notes).splitlines()
            if notes_lines:
                lines.append("  notes  : {0}".format(notes_lines[0]))
                for extra_line in notes_lines[1:]:
                    lines.append("           {0}".format(extra_line))

        return lines

    @staticmethod
    def _split_lines(text):
        text = to_text(text)
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if lines:
            return lines
        return [""]

    @staticmethod
    def _value_to_text(value):
        if isinstance(value, (dict, list, tuple, set)):
            return to_text(json.dumps(value, ensure_ascii=False))
        return to_text(value)

    def _colorize_status(self, status):
        if not self.use_color:
            return status

        color_map = {
            "PASS": "\033[32m",
            "FAIL": "\033[31m",
            "MANUAL": "\033[33m",
            "ERROR": "\033[35m",
        }
        reset = "\033[0m"
        color = color_map.get(status.upper(), "")
        if color:
            return "{0}{1}{2}".format(color, status, reset)
        return status