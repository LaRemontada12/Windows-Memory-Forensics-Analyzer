def normalize_pslist_record(record: dict) -> dict:
    """Chuan hoa mot ban ghi windows.pslist."""

    if not isinstance(record, dict):
        raise ValueError("A pslist record must be a dictionary")

    return {
        "pid": record.get("PID"),
        "ppid": record.get("PPID"),
        "process_name": record.get("ImageFileName"),
        "create_time": record.get("CreateTime"),
        "exit_time": record.get("ExitTime"),
        "session_id": record.get("SessionId"),
        "threads": record.get("Threads"),
    }

def normalize_cmdline_record(record: dict) -> dict:
    """Chuan hoa mot ban ghi windows.cmdline."""

    if not isinstance(record, dict):
        raise ValueError("A cmdline record must be a dictionary")

    return {
        "pid": record.get("PID"),
        "process_name": record.get("Process"),
        "command_line": record.get("Args"),
    }

def normalize_malfind_record(record: dict) -> dict:
    """Chuan hoa mot ban ghi windows.malfind."""

    if not isinstance(record, dict):
        raise ValueError("A malfind record must be a dictionary")

    return {
        "pid": record.get("PID"),
        "process_name": record.get("Process"),
        "start_address": record.get("Start VPN"),
        "end_address": record.get("End VPN"),
        "protection": record.get("Protection"),
        "private_memory": record.get("PrivateMemory"),
        "tag": record.get("Tag"),
        "notes": record.get("Notes"),
        "hexdump": record.get("Hexdump"),
    }

def normalize_netscan_record(record: dict) -> dict:
    """Chuan hoa mot ban ghi windows.netscan."""

    if not isinstance(record, dict):
        raise ValueError("A netscan record must be a dictionary")

    return {
        "pid": record.get("PID"),
        "process_name": record.get("Owner"),
        "protocol": record.get("Proto"),
        "local_address": record.get("LocalAddr"),
        "local_port": record.get("LocalPort"),
        "remote_address": record.get("ForeignAddr"),
        "remote_port": record.get("ForeignPort"),
        "state": record.get("State"),
        "create_time": record.get("Created"),
    }
