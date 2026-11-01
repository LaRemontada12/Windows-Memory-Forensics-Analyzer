
import subprocess
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
VOL_PATH = BASE_DIR / ".venv" / "Scripts" / "vol.exe"

# Danh sach plugin duoc phep chay
ALLOWED_PLUGINS = {
    "windows.info",
    "windows.pslist",
    "windows.pstree",
    "windows.cmdline"
}


def run_volatility(image_path, plugin="windows.info"):

    # Kiem tra plugin
    if plugin not in ALLOWED_PLUGINS:
        raise ValueError(f"Unsupported plugin: {plugin}")

    # Tao lenh goi Volatility 3
    command = [
        str(VOL_PATH),
        "-q",
        "-r", "json",
        "-f", str(image_path),
        plugin
    ]

    # Thuc thi Volatility 3
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300
    )

    # Kiem tra loi khi chay
    if result.returncode != 0:
        raise RuntimeError(
            f"Volatility failed: {result.stderr}"
        )

    # Chuyen ket qua JSON sang Python
    return json.loads(result.stdout)
