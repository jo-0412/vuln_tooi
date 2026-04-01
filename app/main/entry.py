from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ is None or __package__ == "":
    project_root = Path(__file__).resolve().parents[2]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

from app.main.u01_runner import U01Runner
from app.main.u02_runner import U02Runner
from app.output.console_formatter import ConsoleFormatter


EXIT_CODE_MAP = {
    "PASS": 0,
    "FAIL": 1,
    "MANUAL": 2,
    "ERROR": 3,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Debian 계열 리눅스 취약점 점검 도구")
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
    return parser


def calculate_exit_code(results: list) -> int:
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


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    runners = [
        U01Runner(),
        U02Runner(),
    ]

    results = [runner.run() for runner in runners]

    if args.json:
        print(
            json.dumps(
                [result.to_dict() for result in results],
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        formatter = ConsoleFormatter(use_color=not args.no_color)
        for idx, result in enumerate(results):
            formatter.print(result, verbose=not args.quiet)
            if idx < len(results) - 1:
                print("=" * 80)

    return calculate_exit_code(results)


if __name__ == "__main__":
    raise SystemExit(main())