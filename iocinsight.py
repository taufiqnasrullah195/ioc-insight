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

    if "--serve" in sys.argv:
        # web UI + API on one port
        port = 8000
        if "--port" in sys.argv:
            i = sys.argv.index("--port")
            try:
                port = int(sys.argv[i + 1])
            except (IndexError, ValueError):
                pass
        import uvicorn
        print(f"◉ IOC Insight web UI + API → http://localhost:{port}")
        uvicorn.run("ioc_insight.api:app", host="0.0.0.0", port=port, log_level="warning")
        return

    from ioc_insight.cli import app

    if len(sys.argv) == 1:
        # no args → interactive control panel + web dashboard in background
        _start_web_background()
        from ioc_insight.tui import run_tui
        run_tui()
    else:
        app()


def _start_web_background() -> None:
    """Serve web UI+API on :8000 alongside the TUI (daemon thread)."""
    import socket
    import threading

    import uvicorn

    # don't crash the TUI if the port is already taken (already serving)
    with socket.socket() as s:
        if s.connect_ex(("127.0.0.1", 8000)) == 0:
            print("◉ web dashboard already running → http://localhost:8000")
            return

    def serve() -> None:
        uvicorn.run("ioc_insight.api:app", host="0.0.0.0", port=8000,
                    log_level="error")

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    print("◉ web dashboard → http://localhost:8000  (berjalan bersama TUI)")


if __name__ == "__main__":
    main()
