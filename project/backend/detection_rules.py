import re
from datetime import datetime


WINDOWS_PATH_SEPARATOR = chr(92)

OFFICE_PARENT_SUFFIXES = tuple(
    WINDOWS_PATH_SEPARATOR + name
    for name in (
        "eqnedt32.exe",
        "excel.exe",
        "msaccess.exe",
        "mspub.exe",
        "onenote.exe",
        "powerpnt.exe",
        "visio.exe",
        "winword.exe",
        "wordpad.exe",
        "wordview.exe",
    )
)

OFFICE_CHILD_SUFFIXES = tuple(
    WINDOWS_PATH_SEPARATOR + name
    for name in (
        "appvlp.exe",
        "bash.exe",
        "bitsadmin.exe",
        "certoc.exe",
        "certutil.exe",
        "cmd.exe",
        "cmstp.exe",
        "control.exe",
        "cscript.exe",
        "curl.exe",
        "forfiles.exe",
        "hh.exe",
        "ieexec.exe",
        "installutil.exe",
        "javaw.exe",
        "mftrace.exe",
        "microsoft.workflow.compiler.exe",
        "msbuild.exe",
        "msdt.exe",
        "mshta.exe",
        "msidb.exe",
        "msiexec.exe",
        "msxsl.exe",
        "odbcconf.exe",
        "pcalua.exe",
        "powershell.exe",
        "pwsh.exe",
        "regasm.exe",
        "regsvcs.exe",
        "regsvr32.exe",
        "rundll32.exe",
        "schtasks.exe",
        "scrcons.exe",
        "scriptrunner.exe",
        "sh.exe",
        "svchost.exe",
        "verclsid.exe",
        "wmic.exe",
        "workfolders.exe",
        "wscript.exe",
    )
)

OFFICE_CHILD_PATH_PARTS = tuple(
    part.replace("/", WINDOWS_PATH_SEPARATOR)
    for part in (
        "/appdata/",
        "/users/public/",
        "/programdata/",
        "/windows/tasks/",
        "/windows/temp/",
        "/windows/system32/tasks/",
    )
)


def matches_office_parent(image_path: str | None) -> bool:
    if not image_path:
        return False

    return image_path.casefold().endswith(OFFICE_PARENT_SUFFIXES)


def matches_suspicious_child(image_path: str | None) -> bool:
    if not image_path:
        return False

    path = image_path.casefold()
    return path.endswith(OFFICE_CHILD_SUFFIXES) or any(
        part in path for part in OFFICE_CHILD_PATH_PARTS
    )


def is_parent_child_pair(parent: dict, child: dict) -> bool:
    parent_pid = parent.get("PID")
    child_pid = child.get("PID")

    if parent_pid is None or child_pid is None or parent_pid == child_pid:
        return False

    if child.get("PPID") != parent_pid:
        return False

    try:
        parent_created = datetime.fromisoformat(parent.get("CreateTime"))
        child_created = datetime.fromisoformat(child.get("CreateTime"))

        if child_created < parent_created:
            return False

        parent_exit_time = parent.get("ExitTime")
        if parent_exit_time is None:
            return True

        parent_exited = datetime.fromisoformat(parent_exit_time)
        return child_created <= parent_exited
    except (TypeError, ValueError):
        return False


def detect_office_child_processes(analysis_evidence: dict) -> list[dict]:
    if analysis_evidence.get("plugin") != "windows.pstree":
        raise ValueError("Rule 1 requires windows.pstree evidence")

    run_id = analysis_evidence["run_id"]
    findings = []

    for record in analysis_evidence["evidence"]:
        pending = [record["data"]]

        while pending:
            parent = pending.pop()
            children = parent.get("__children") or []
            pending.extend(reversed(children))

            parent_path = parent.get("Path")
            if not matches_office_parent(parent_path):
                continue

            for child in children:
                child_path = child.get("Path")

                if not is_parent_child_pair(parent, child):
                    continue

                if not matches_suspicious_child(child_path):
                    continue

                findings.append({
                    "rule_name": "Suspicious Microsoft Office Child Process",
                    "description": (
                        "Office parent created a child whose executable name "
                        "or directory matches the rule."
                    ),
                    "run_id": run_id,
                    "record_index": record["record_index"],
                    "parent_pid": parent["PID"],
                    "parent_path": parent_path,
                    "child_pid": child["PID"],
                    "child_path": child_path,
                })

    return findings


# Rule 2: PowerShell voi tham so nhan lenh Base64.
# Tham chieu SigmaHQ: fb843269-508c-4b76-8b8d-88679db22ce7.
POWERSHELL_PROCESS_NAMES = {"powershell.exe", "pwsh.exe"}
ENCODED_COMMAND_SHORT_FLAGS = {"-e", "-ec", "-en", "-enc"}
COMMAND_LINE_ARGUMENTS = re.compile(r'(?:[^\s"]+|"[^"]*")+')


def find_encoded_command_flag(command_line: str) -> str | None:
    """Tra ve co khop dung nhu cach viet trong bang chung."""
    arguments = COMMAND_LINE_ARGUMENTS.findall(command_line)

    # Bo qua ten chuong trinh. Co can co mot doi so o phia sau.
    for index in range(1, len(arguments) - 1):
        flag = arguments[index].strip('"')
        option = flag.casefold()

        # Sau -File hoac -Command la ten script hoac noi dung lenh.
        if option in {"-f", "-file", "-c", "-command"}:
            break

        is_encoded_flag = option in ENCODED_COMMAND_SHORT_FLAGS or (
            option.startswith("-enco") and "-encodedcommand".startswith(option)
        )

        if is_encoded_flag and arguments[index + 1].strip('"'):
            return flag

    return None


def detect_encoded_powershell_commands(analysis_evidence: dict) -> list[dict]:
    """Tim dong lenh PowerShell co dau hieu su dung EncodedCommand."""
    if analysis_evidence.get("plugin") != "windows.cmdline":
        raise ValueError("Rule 2 requires windows.cmdline evidence")

    run_id = analysis_evidence["run_id"]
    findings = []

    for record in analysis_evidence["evidence"]:
        normalized = record.get("normalized")
        if not isinstance(normalized, dict):
            continue

        process_name = normalized.get("process_name")
        command_line = normalized.get("command_line")

        if not isinstance(process_name, str) or not isinstance(command_line, str):
            continue

        if process_name.casefold() not in POWERSHELL_PROCESS_NAMES:
            continue

        matched_flag = find_encoded_command_flag(command_line)
        if matched_flag is None:
            continue

        findings.append({
            "rule_name": "Suspicious PowerShell Encoded Command",
            "description": f"PowerShell command line contains {matched_flag}.",
            "run_id": run_id,
            "record_index": record["record_index"],
            "pid": normalized.get("pid"),
            "process_name": process_name,
            "command_line": command_line,
            "matched_flag": matched_flag,
        })

    return findings