"""Verify that a project file matches the code block in a kit_v2 reference .md file.

Usage:
    python tools/check_ref.py <project_file> <reference_md>            exact match
    python tools/check_ref.py <project_file> <reference_md> --contains block must appear unchanged in the file
"""
import pathlib
import re
import sys


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    target, ref = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
    contains = "--contains" in sys.argv[3:]
    match = re.search(r"```[A-Za-z]*\n(.*?)\n```", ref.read_text(encoding="utf-8").replace("\r\n", "\n"), re.S)
    if not match:
        print("NO CODE BLOCK in", ref)
        return 2
    if not target.exists():
        print("MISSING", target)
        return 1
    want = match.group(1).strip()
    have = target.read_text(encoding="utf-8").replace("\r\n", "\n").strip()
    ok = (want in have) if contains else (have == want)
    print(("MATCH " if ok else "DIFFERENT ") + str(target))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
