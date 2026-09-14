#!/usr/bin/env python3
"""공공데이터 API 인증키의 URL 인코딩을 로컬에서 한 번 해제합니다."""

from __future__ import annotations

import argparse
import getpass
import re
import sys
import warnings
from urllib.parse import unquote


def decode_api_key(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("API 키를 입력해 주세요.")
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        raise ValueError(
            "잘못된 URL 인코딩입니다. % 뒤에는 16진수 두 자리가 필요합니다."
        )
    # unquote_plus would corrupt a literal '+' in an authentication key.
    try:
        decoded = unquote(value, encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ValueError("URL 인코딩의 문자 형식이 올바르지 않습니다.") from None
    if any(character.isspace() or not character.isprintable() for character in decoded):
        raise ValueError("API 키에 공백이나 제어 문자가 포함되어 있습니다.")
    return decoded


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--stdin", action="store_true", help="표준 입력에서 키를 읽습니다."
    )
    args = parser.parse_args()
    try:
        if args.stdin:
            value = sys.stdin.read()
        else:
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                value = getpass.getpass("인코딩된 API 키 (입력 숨김): ")
        decoded = decode_api_key(value)
    except getpass.GetPassWarning:
        print(
            "숨김 입력이 가능한 터미널에서 실행하거나 --stdin을 사용해 주세요.",
            file=sys.stderr,
        )
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\n입력을 취소했습니다.", file=sys.stderr)
        return 1
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1
    print(decoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
