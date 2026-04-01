# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

import io
import sys
import datetime

PY2 = sys.version_info[0] == 2

if PY2:
    text_type = unicode
    string_types = (basestring,)
else:
    text_type = str
    string_types = (str,)


def to_text(value, encoding='utf-8', errors='replace'):
    if value is None:
        return text_type('')

    if isinstance(value, text_type):
        return value

    try:
        return value.decode(encoding, errors)
    except Exception:
        try:
            return text_type(value)
        except Exception:
            return text_type('')


def read_text(path, encoding='utf-8', errors='replace'):
    with io.open(path, 'r', encoding=encoding, errors=errors) as f:
        return f.read()


def write_text(path, content, encoding='utf-8'):
    with io.open(path, 'w', encoding=encoding) as f:
        f.write(to_text(content))


def now_iso():
    return datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')