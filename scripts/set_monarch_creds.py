#!/usr/bin/env python3
"""Update Monarch credential lines in a server-side .env, reading values from
stdin so that arbitrary special characters never pass through a shell.

Reads exactly three lines from stdin, in order:

    line 1: MONARCH_EMAIL
    line 2: MONARCH_PASSWORD
    line 3: MONARCH_MFA_SECRET

An empty line leaves that key unchanged. Every other line in .env is preserved
verbatim. The value is written literally (Docker Compose `env_file` takes the
text after the first `=` as-is — no quoting needed, and quotes would become
part of the value), so secrets with @, &, %, spaces, etc. are fine.

Usage (on the server, from the repo dir):
    printf '%s\n%s\n%s\n' "$EMAIL" "$PASS" "$MFA" | python3 scripts/set_monarch_creds.py
"""

from __future__ import annotations

import os
import sys
import tempfile

ENV_PATH = os.environ.get("ENV_PATH", ".env")
KEYS = ["MONARCH_EMAIL", "MONARCH_PASSWORD", "MONARCH_MFA_SECRET"]


def main() -> int:
    raw = sys.stdin.read().splitlines()
    # Pad to three entries; missing/blank means "leave unchanged".
    values = [(raw[i].rstrip("\r") if i < len(raw) else "") for i in range(3)]
    updates = {k: v for k, v in zip(KEYS, values) if v != ""}

    if not os.path.exists(ENV_PATH):
        print(f"ERROR: {ENV_PATH} not found (run from the repo dir).", file=sys.stderr)
        return 1

    with open(ENV_PATH, "r", encoding="utf-8") as fh:
        lines = fh.readlines()

    seen = set()
    out = []
    for line in lines:
        key = line.split("=", 1)[0].strip() if "=" in line else None
        if key in updates:
            out.append(f"{key}={updates[key]}\n")
            seen.add(key)
        else:
            out.append(line)
    # Append any keys that were not already present.
    for key in KEYS:
        if key in updates and key not in seen:
            out.append(f"{key}={updates[key]}\n")

    # Write atomically with 0600 perms, preserving the file's directory.
    d = os.path.dirname(os.path.abspath(ENV_PATH)) or "."
    fd, tmp = tempfile.mkstemp(dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.writelines(out)
        os.chmod(tmp, 0o600)
        os.replace(tmp, ENV_PATH)
    except BaseException:
        os.unlink(tmp)
        raise

    # Report which keys changed — names only, never values.
    print("Updated keys: " + (", ".join(sorted(updates)) or "(none)"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
