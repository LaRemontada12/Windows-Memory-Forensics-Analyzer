
import subprocess
import json
from pathlib import Path

# ==========================================
# 1. CAU HINH VOLATILITY 3
# ==========================================

BASE_DIR = Path(__file__).resolve().parents[2]

VOL_PATH = BASE_DIR / ".venv" / "Scripts" / "vol.exe"

# Danh sach plugin duoc phep su dung
# Key: ten plugin hien thi trong API
# Value: ten plugin thuc thi trong Volatility 3

ALLOWED_PLUGINS = {
    "windows.info": "windows.info",
    "windows.pslist": "windows.pslist",
    "windows.pstree": "windows.pstree",
    "windows.cmdline": "windows.cmdline",
    "windows.malfind": "windows.malware.malfind.Malfind",
    "windows.netscan": "windows.netscan.NetScan"
}


# ==========================================
# 2. HAM THUC THI VOLATILITY 3
# ==========================================

def run_volatility(image_path, plugin="windows.info"):

    # Kiem tra plugin co duoc ho tro khong
    if plugin not in ALLOWED_PLUGINS:
        raise ValueError(
            f"Unsupported plugin: {plugin}"
        )

    # Lay ten plugin thuc thi
    volatility_plugin = ALLOWED_PLUGINS[plugin]

    # Tao lenh Volatility 3
    command = [
        str(VOL_PATH),
        "-q",
        "-r", "json",
        "-f", str(image_path),
        volatility_plugin
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

    # Kiem tra loi thuc thi
    if result.returncode != 0:
        raise RuntimeError(
            f"Volatility failed: {result.stderr}"
        )

    # Chuyen JSON thanh du lieu Python
    return json.loads(result.stdout)
