from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ is None or __package__ == "":
    project_root = Path(__file__).resolve().parents[2]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

from app.main.runner import U01Runner
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
        "--check",
        default="U-01",
        help="실행할 점검 항목 코드 (현재는 U-01만 지원)",
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
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    check_code = str(args.check).strip().upper()

    if check_code != "U-01":
        print(f"현재 지원하지 않는 점검 항목입니다: {check_code}", file=sys.stderr)
        return 4

    runner = U01Runner()
    result = runner.run()

    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    else:
        formatter = ConsoleFormatter(use_color=not args.no_color)
        formatter.print(result, verbose=not args.quiet)

    return EXIT_CODE_MAP.get(result.status, 3)


if __name__ == "__main__":
    raise SystemExit(main())