"""Print one release's section of CHANGELOG.md, for the GitHub release the publish workflow makes.

    python tools/release_notes.py 0.1.0 [CHANGELOG.md]

The section is the one headed "## 0.1.0" (a date or more may follow the version on that line),
up to the next "## " heading. A leading "v" on the version is dropped, so the tag can be passed
as it is. Exits 1, saying so, when there is no such section or it is empty: a release needs its
notes written before the tag.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def section(changelog: str, version: str) -> str | None:
    version = version.removeprefix("v")
    heading = re.compile(rf"^## \[?{re.escape(version)}\]?(\s|$)")
    lines: list[str] = []
    inside = False
    for line in changelog.splitlines():
        if line.startswith("## "):
            if inside:
                break
            inside = bool(heading.match(line))
            continue
        if inside:
            lines.append(line)
    body = "\n".join(lines).strip()
    return body or None


def main(argv: list[str]) -> int:
    version = argv[0]
    path = Path(argv[1]) if len(argv) > 1 else Path("CHANGELOG.md")
    body = section(path.read_text(encoding="utf-8"), version)
    if body is None:
        print(f"{path} has no section for {version}", file=sys.stderr)
        return 1
    print(body)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
