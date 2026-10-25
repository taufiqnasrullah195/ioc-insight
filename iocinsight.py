#!/usr/bin/env python3
"""IOC Insight — quick run script.

Double-click / `python3 iocinsight.py` → interactive control panel.
Handles venv activation and .env loading automatically.

Examples:
    python3 iocinsight.py                  # interactive TUI menu
    python3 iocinsight.py 8.8.8.8          # one-shot lookup
    python3 iocinsight.py 8.8.8.8 --lang id
    ./iocinsight.py                        # same, if executable
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV_PY = ROOT / ".venv" / "bin" / "python"


def load_dotenv() -> None:
    """Load KEY=VALUE lines from .env next to this script (no dependency)."""
    env_file = ROOT / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip('"').strip("'")
        if value:
            os.environ.setdefault(key.strip(), value)


def main() -> None:
    load_dotenv()

    # re-exec with the project venv python if we aren't already in it
    if VENV_PY.exists() and Path(sys.executable) != VENV_PY:
        os.execv(str(VENV_PY), [str(VENV_PY), str(Path(__file__).resolve()), *sys.argv[1:]])

    sys.path.insert(0, str(ROOT))
    from ioc_insight.cli import app

    if len(sys.argv) == 1:
        # no args → interactive control panel
        from ioc_insight.tui import run_tui
        run_tui()
    else:
        app()


if __name__ == "__main__":
    main()
