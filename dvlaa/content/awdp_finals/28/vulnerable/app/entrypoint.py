from __future__ import annotations

import signal
import subprocess
import sys
import time


server_process: subprocess.Popen | None = None


def stop_server(signum: int, frame: object) -> None:
    if server_process is not None and server_process.poll() is None:
        server_process.terminate()
    raise SystemExit(0)


def main() -> None:
    global server_process

    signal.signal(signal.SIGTERM, stop_server)
    signal.signal(signal.SIGINT, stop_server)

    command = [
        sys.executable,
        "-m",
        "uvicorn",
        "app.main:app",
        "--host",
        "0.0.0.0",
        "--port",
        "80",
    ]
    while True:
        server_process = subprocess.Popen(command)
        return_code = server_process.wait()
        server_process = None
        if return_code == 0:
            return
        time.sleep(1)


if __name__ == "__main__":
    main()
