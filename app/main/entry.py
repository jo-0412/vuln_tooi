# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

import argparse
import json
import os
import sys

if __package__ is None or __package__ == "":
    project_root = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..")
    )
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

from app.main.u01_runner import U01Runner
from app.main.u02_runner import U02Runner
from app.main.u03_runner import U03Runner
from app.main.u04_runner import U04Runner
from app.main.u05_runner import U05Runner
from app.main.u06_runner import U06Runner
from app.main.u07_runner import U07Runner
from app.main.u13_runner import U13Runner
from app.main.u18_runner import U18Runner
from app.main.u23_runner import U23Runner
from app.main.u25_runner import U25Runner
from app.main.u28_runner import U28Runner
from app.main.u30_runner import U30Runner
from app.main.u36_runner import U36Runner
from app.main.u37_runner import U37Runner
from app.main.u52_runner import U52Runner
from app.main.u54_runner import U54Runner
from app.main.u63_runner import U63Runner
from app.main.u64_runner import U64Runner
from app.main.u66_runner import U66Runner
from app.output.console_formatter import ConsoleFormatter
from app.compat import to_text

EXIT_CODE_MAP = {
    "PASS": 0,
    "FAIL": 1,
    "MANUAL": 2,
    "ERROR": 3,
}


def build_parser():
    parser = argparse.ArgumentParser(
        description="Debian 계열 리눅스 취약점 점검 도구"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="결과를 JSON 형식으로 출력",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="증적 출력 없이 핵심 결과만 표시",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="콘솔 색상 출력 비활성화",
    )
    parser.add_argument(
        "--check",
        default="ALL",
        help="실행할 점검 항목 코드 (U-01, U-02, ALL)",
    )
    return parser


def calculate_exit_code(results):
    """
    여러 결과 중 가장 심각한 상태 기준으로 종료 코드 결정
    ERROR > FAIL > MANUAL > PASS
    """
    statuses = [result.status for result in results]

    if "ERROR" in statuses:
        return EXIT_CODE_MAP["ERROR"]
    if "FAIL" in statuses:
        return EXIT_CODE_MAP["FAIL"]
    if "MANUAL" in statuses:
        return EXIT_CODE_MAP["MANUAL"]
    return EXIT_CODE_MAP["PASS"]


def build_runners(check_code):
    normalized = to_text(check_code).strip().upper()

    if normalized == "U-01":
        return [U01Runner()]

    if normalized == "U-02":
        return [U02Runner()]

    if normalized == "U-03":
        return [U03Runner()]

    if normalized == "U-04":
        return [U04Runner()]

    if normalized == "U-05":
        return [U05Runner()]
    
    if normalized == "U-06":
        return [U06Runner()]
    
    if normalized == "U-07":
        return [U07Runner()]
    
    if normalized == "U-13":
        return [U13Runner()]

    if normalized == "U-18":
        return [U18Runner()]

    if normalized == "U-23":
        return [U23Runner()]
    
    if normalized == "U-25":
        return [U25Runner()]

    if normalized == "U-28":
        return [U28Runner()]
    
    if normalized == "U-30":
        return [U30Runner()]
    
    if normalized == "U-36":
        return [U36Runner()]
    
    if normalized == "U-37":
        return [U37Runner()]
    
    if normalized == "U-52":
        return [U52Runner()]
    
    if normalized == "U-54":
        return [U54Runner()]
    
    if normalized == "U-63":
        return [U63Runner()]

    if normalized == "U-64":
        return [U64Runner()]

    if normalized == "U-66":
        return [U66Runner()]

    if normalized == "ALL":
        return [
            U01Runner(),
            U02Runner(),
            U03Runner(),
            U04Runner(),
            U05Runner(),
            U06Runner(),
            U07Runner(),
            U13Runner(),
            U18Runner(),
            U23Runner(),
            U25Runner(),
            U28Runner(),
            U30Runner(),
            U36Runner(),
            U37Runner(),
            U52Runner(),
            U54Runner(),
            U63Runner(),
            U64Runner(),
            U66Runner(),
        ]

    return None


def main():
    parser = build_parser()
    args = parser.parse_args()

    runners = build_runners(args.check)
    if runners is None:
        print(
            "현재 지원하지 않는 점검 항목입니다: {0}".format(args.check),
            file=sys.stderr
        )
        return 4

    results = []
    for runner in runners:
        results.append(runner.run())

    if args.json:
        print(
            json.dumps(
                [result.to_dict() for result in results],
                ensure_ascii=False,
                indent=2
            )
        )
    else:
        formatter = ConsoleFormatter(use_color=not args.no_color)
        for idx, result in enumerate(results):
            formatter.print_result(result, verbose=not args.quiet)
            if idx < len(results) - 1:
                print("=" * 80)

    return calculate_exit_code(results)


if __name__ == "__main__":
    raise SystemExit(main())