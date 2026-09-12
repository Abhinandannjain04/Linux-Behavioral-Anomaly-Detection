import json
import os

INPUT_FILE = "/opt/audit-lab/parsed_events.json"
OUTPUT_FILE = "/opt/audit-lab/behavioral_events.json"

SENSITIVE_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers"
]

PRIVILEGE_COMMANDS = [
    "sudo",
    "su",
    "pkexec"
]

REMOTE_COMMANDS = [
    "ssh",
    "scp",
    "sftp"
]

NETWORK_TOOLS = [
    "curl",
    "wget",
    "nc",
    "netcat",
    "nmap",
    "telnet"
]

SHELLS = [
    "bash",
    "sh",
    "dash",
    "zsh",
    "fish"
]


def load_events():
    with open(INPUT_FILE, "r") as f:
        return json.load(f)


def get_command(event):
    command = event.get("command", {})

    if isinstance(command, str):
        return command

    if isinstance(command, dict):
        for key in ["command", "cmd", "text", "raw"]:
            value = command.get(key)

            if value:
                return str(value)

    process = event.get("process", {})

    comm = process.get("comm", "")
    exe = process.get("exe", "")

    return "{} {}".format(comm, exe).strip()


def get_paths(event):
    paths = event.get("paths", [])

    result = []

    if isinstance(paths, list):
        for item in paths:
            if isinstance(item, dict):
                path = item.get("path")

                if path:
                    result.append(str(path))

            elif isinstance(item, str):
                result.append(item)

    return result


def get_all_text(event):
    command = get_command(event)
    paths = get_paths(event)

    process = event.get("process", {})

    comm = process.get("comm", "")
    exe = process.get("exe", "")

    path_text = " ".join(paths)

    return "{} {} {} {}".format(
        command,
        comm,
        exe,
        path_text
    ).lower()


def classify_behavior(event):
    command = get_command(event).lower()
    text = get_all_text(event)

    user = event.get("user", {})

    uid = user.get("uid")
    euid = user.get("euid")

    syscall = event.get("syscall", {})
    syscall_name = str(syscall.get("name", "")).lower()

    process = event.get("process", {})

    process_name = str(
        process.get("comm", "")
    ).lower()

    behaviors = []

    if syscall_name in ["execve", "execveat"]:
        behaviors.append("PROCESS_EXECUTION")

    command_words = command.replace("/", " ").split()

    if any(
        privilege in command_words
        for privilege in PRIVILEGE_COMMANDS
    ):
        behaviors.append("PRIVILEGE_TOOL_USAGE")
        behaviors.append("PRIVILEGE_ESCALATION")

    if process_name in SHELLS:
        behaviors.append("SHELL_EXECUTION")

    if any(
        remote in command_words
        for remote in REMOTE_COMMANDS
    ):
        behaviors.append("REMOTE_ACCESS")

    if any(
        tool in command_words
        for tool in NETWORK_TOOLS
    ):
        behaviors.append("NETWORK_TOOL")

    if any(
        sensitive in text
        for sensitive in SENSITIVE_FILES
    ):
        behaviors.append("SENSITIVE_FILE_ACCESS")

    if uid == 0 or euid == 0:
        behaviors.append("ROOT_CONTEXT")

    if any(
        word in command
        for word in [
            "rm ",
            "unlink",
            "delete"
        ]
    ):
        behaviors.append("FILE_DELETE")

    if any(
        word in command
        for word in [
            "chmod",
            "chown",
            "setfacl"
        ]
    ):
        behaviors.append("PERMISSION_CHANGE")

    if any(
        word in command
        for word in [
            "touch ",
            "echo ",
            "printf ",
            "tee ",
            "cp ",
            "mv "
        ]
    ):
        behaviors.append("FILE_WRITE")

    if "find " in command or "locate " in command:
        behaviors.append("FILE_DISCOVERY")

    if any(
        command.startswith(prefix)
        for prefix in [
            "cat ",
            "less ",
            "more ",
            "head ",
            "tail "
        ]
    ):
        behaviors.append("FILE_READ")

    return sorted(set(behaviors))


def build_behavioral_events(events):
    results = []

    for event in events:
        behavioral_event = dict(event)

        behaviors = classify_behavior(event)

        behavioral_event["behaviors"] = behaviors
        behavioral_event["behavior_count"] = len(behaviors)

        results.append(behavioral_event)

    return results


def generate_summary(behavioral_events):
    counts = {}

    for event in behavioral_events:
        for behavior in event.get("behaviors", []):
            counts[behavior] = counts.get(behavior, 0) + 1

    return counts


def main():
    print("[+] Loading:", INPUT_FILE)

    if not os.path.exists(INPUT_FILE):
        print("[!] Input file not found")
        return

    events = load_events()

    print("[+] Events loaded:", len(events))

    behavioral_events = build_behavioral_events(events)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(
            behavioral_events,
            f,
            indent=4
        )

    print("[+] Behavioral events:", len(behavioral_events))
    print("[+] Output:", OUTPUT_FILE)

    counts = generate_summary(behavioral_events)

    print("\n[+] Behavioral summary")

    if not counts:
        print("    No behaviors detected")
        return

    for behavior, count in sorted(counts.items()):
        print(
            "    {:25} {}".format(
                behavior,
                count
            )
        )


if __name__ == "__main__":
    main()
