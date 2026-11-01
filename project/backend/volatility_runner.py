
import subprocess
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]

VOL_PATH = BASE_DIR / ".venv" / "Scripts" / "vol.exe"


def run_volatility(image_path):
    command = [
        str(VOL_PATH),
        "-q",
        "-r", "json",
        "-f", str(image_path),
        "windows.info"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Volatility failed: {result.stderr}"
        )

    return json.loads(result.stdout)
