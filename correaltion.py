import json
from collections import Counter
from datetime import datetime

INPUT_FILE = "/opt/audit-lab/behavioral_events.json"
OUTPUT_FILE = "/opt/audit-lab/correlated_events_v2.json"

TIME_WINDOW = 60
MAX_ANCESTRY_DEPTH = 8

CORRELATION_RULES = {
    ("PRIVILEGE_TOOL_USAGE", "PRIVILEGE_ESCALATION"),

    ("PRIVILEGE_ESCALATION", "SHELL_EXECUTION"),
    ("PRIVILEGE_ESCALATION", "FILE_READ"),
    ("PRIVILEGE_ESCALATION", "FILE_WRITE"),
    ("PRIVILEGE_ESCALATION", "FILE_DELETE"),

    ("SHELL_EXECUTION", "FILE_READ"),
    ("SHELL_EXECUTION", "FILE_WRITE"),
    ("SHELL_EXECUTION", "FILE_DELETE"),
    ("SHELL_EXECUTION", "FILE_DISCOVERY"),

    ("FILE_DISCOVERY", "FILE_READ"),
    ("FILE_DISCOVERY", "FILE_WRITE"),
    ("FILE_DISCOVERY", "FILE_DELETE"),

    ("FILE_READ", "FILE_WRITE"),
    ("FILE_READ", "FILE_DELETE"),

    ("FILE_WRITE", "FILE_DELETE"),
}


def parse_time(event):
    timestamp = event.get("timestamp")

    if isinstance(timestamp, (int, float)):
        return float(timestamp)

    timestamp_iso = event.get("timestamp_iso")

    if timestamp_iso:
        try:
            return datetime.fromisoformat(timestamp_iso).timestamp()
        except Exception:
            pass

    return None


def get_pid(event):
    process = event.get("process", {})
    return process.get("pid")


def get_ppid(event):
    process = event.get("process", {})
    return process.get("ppid")


def get_user(event):
    user = event.get("user", {})

    auid = user.get("auid")

    if auid is not None:
        return auid

    uid = user.get("uid")

    return uid


def get_session(event):
    return event.get("session")


def get_behaviors(event):
    behaviors = event.get("behaviors", [])

    if isinstance(behaviors, str):
        return [behaviors]

    if isinstance(behaviors, list):
        return behaviors

    return []


def get_targets(event):
    targets = []

    paths = event.get("paths", [])

    if isinstance(paths, list):
        for path in paths:
            if isinstance(path, dict):
                name = path.get("name")

                if name and name not in targets:
                    targets.append(name)

    command = event.get("command", {})

    if isinstance(command, dict):
        for key in ["command", "args", "exe"]:
            value = command.get(key)

            if value:
                if isinstance(value, list):
                    for item in value:
                        if item not in targets:
                            targets.append(str(item))
                else:
                    value = str(value)

                    if value not in targets:
                        targets.append(value)

    return targets


def load_events(filepath):
    with open(filepath, "r") as file:
        data = json.load(file)

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        return data.get("events", [])

    return []


def build_process_index(events):
    process_index = {}

    for event in events:
        pid = get_pid(event)
        ppid = get_ppid(event)

        if pid is None:
            continue

        if pid not in process_index:
            process_index[pid] = {
                "pid": pid,
                "ppid": ppid
            }

        elif process_index[pid]["ppid"] is None and ppid is not None:
            process_index[pid]["ppid"] = ppid

    return process_index


def get_ancestry(pid, process_index):
    ancestry = []
    current_pid = pid
    visited = set()

    for _ in range(MAX_ANCESTRY_DEPTH):

        if current_pid is None:
            break

        if current_pid in visited:
            break

        visited.add(current_pid)
        ancestry.append(current_pid)

        node = process_index.get(current_pid)

        if not node:
            break

        parent_pid = node.get("ppid")

        if parent_pid is None:
            break

        if parent_pid == current_pid:
            break

        current_pid = parent_pid

    return ancestry


def process_relationship(pid1, pid2, process_index):

    if pid1 is None or pid2 is None:
        return None, None

    if pid1 == pid2:
        return "same_process", 0

    ancestry1 = get_ancestry(pid1, process_index)
    ancestry2 = get_ancestry(pid2, process_index)

    if pid2 in ancestry1:
        distance = ancestry1.index(pid2)

        return "ancestor_descendant", distance

    if pid1 in ancestry2:
        distance = ancestry2.index(pid1)

        return "ancestor_descendant", distance

    return None, None


def targets_overlap(targets1, targets2):

    if not targets1 or not targets2:
        return []

    set1 = set(targets1)
    set2 = set(targets2)

    return sorted(set1.intersection(set2))


def create_correlation(event1, event2, behavior1, behavior2,
                       relationship, ancestry_distance, shared_targets):

    time1 = parse_time(event1)
    time2 = parse_time(event2)

    return {
        "event1": event1.get("event_id"),
        "event2": event2.get("event_id"),

        "timestamp1": event1.get("timestamp"),
        "timestamp2": event2.get("timestamp"),

        "time_difference": round(time2 - time1, 6),

        "user": get_user(event1),
        "session": get_session(event1),

        "pid1": get_pid(event1),
        "pid2": get_pid(event2),

        "ppid1": get_ppid(event1),
        "ppid2": get_ppid(event2),

        "behavior1": behavior1,
        "behavior2": behavior2,

        "relationship": relationship,
        "ancestry_distance": ancestry_distance,

        "shared_targets": shared_targets,

        "process1": event1.get("process", {}),
        "process2": event2.get("process", {}),

        "targets1": get_targets(event1),
        "targets2": get_targets(event2)
    }


def main():

    print("[+] Loading:", INPUT_FILE)

    events = load_events(INPUT_FILE)

    print("[+] Events loaded:", len(events))

    behavioral_events = []

    for event in events:

        behaviors = get_behaviors(event)

        if behaviors:
            behavioral_events.append(event)

    print("[+] Behavioral events:", len(behavioral_events))

    behavioral_events.sort(
        key=lambda event: parse_time(event)
        if parse_time(event) is not None
        else float("inf")
    )

    process_index = build_process_index(events)

    print("[+] Processes indexed:", len(process_index))

    correlations = []

    for i in range(len(behavioral_events)):

        event1 = behavioral_events[i]

        time1 = parse_time(event1)

        if time1 is None:
            continue

        user1 = get_user(event1)

        pid1 = get_pid(event1)

        behaviors1 = get_behaviors(event1)

        for j in range(i + 1, len(behavioral_events)):

            event2 = behavioral_events[j]

            time2 = parse_time(event2)

            if time2 is None:
                continue

            time_difference = time2 - time1

            if time_difference < 0:
                continue

            if time_difference > TIME_WINDOW:
                break

            user2 = get_user(event2)

            if user1 != user2:
                continue

            pid2 = get_pid(event2)

            relationship, ancestry_distance = process_relationship(
                pid1,
                pid2,
                process_index
            )

            if relationship is None:
                continue

            behaviors2 = get_behaviors(event2)

            targets1 = get_targets(event1)
            targets2 = get_targets(event2)

            shared_targets = targets_overlap(
                targets1,
                targets2
            )

            for behavior1 in behaviors1:

                for behavior2 in behaviors2:

                    if behavior1 == behavior2:
                        continue

                    rule = (behavior1, behavior2)

                    if rule not in CORRELATION_RULES:
                        continue

                    correlation = create_correlation(
                        event1,
                        event2,
                        behavior1,
                        behavior2,
                        relationship,
                        ancestry_distance,
                        shared_targets
                    )

                    correlations.append(correlation)

    with open(OUTPUT_FILE, "w") as file:
        json.dump(
            correlations,
            file,
            indent=2
        )

    print()
    print("[+] Correlations found:", len(correlations))
    print("[+] Output:", OUTPUT_FILE)

    summary = Counter()

    for correlation in correlations:

        key = (
            correlation["behavior1"],
            correlation["behavior2"]
        )

        summary[key] += 1

    print()
    print("[+] Correlation summary")

    if not summary:
        print("    No correlations found.")

    else:
        for (behavior1, behavior2), count in summary.most_common():

            print(
                f"    {behavior1} -> {behavior2} : {count}"
            )

    relationship_summary = Counter()

    for correlation in correlations:

        relationship_summary[
            correlation["relationship"]
        ] += 1

    print()
    print("[+] Relationship summary")

    if not relationship_summary:
        print("    No relationships found.")

    else:
        for relationship, count in relationship_summary.most_common():

            print(
                f"    {relationship} : {count}"
            )


if __name__ == "__main__":
    main()
