import json
from collections import defaultdict
from datetime import datetime


INPUT_FILE = "parsed_events.json"


def parse_time(event):
    value = event.get("timestamp_iso")

    if not value:
        value = event.get("timestamp")

    if not value:
        return datetime.min

    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value)

        return datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

    except Exception:
        return datetime.min


def get_process(event):
    process = event.get("process")

    if isinstance(process, dict):
        return process

    return {}


def get_syscall(event):
    syscall = event.get("syscall")

    if isinstance(syscall, dict):
        return syscall

    return {}


def get_user(event):
    user = event.get("user")

    if isinstance(user, dict):
        return user

    return {}


def get_command_data(event):
    command = event.get("command")

    if isinstance(command, dict):
        return command

    return {}


def get_pid(event):
    process = get_process(event)

    value = process.get("pid")

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def get_ppid(event):
    process = get_process(event)

    value = process.get("ppid")

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def get_command(event):
    command = get_command_data(event)

    command_line = command.get("command_line")

    if command_line:
        return command_line

    process = get_process(event)

    comm = process.get("comm")

    if comm:
        return comm

    exe = process.get("exe")

    if exe:
        return exe

    return "unknown"


def get_exe(event):
    process = get_process(event)

    return process.get("exe")


def get_comm(event):
    process = get_process(event)

    return process.get("comm")


def get_uid(event):
    user = get_user(event)

    return user.get("uid")


def get_euid(event):
    user = get_user(event)

    return user.get("euid")


def get_auid(event):
    user = get_user(event)

    return user.get("auid")


def get_session(event):
    return event.get("session")


def get_tty(event):
    return event.get("tty")


def get_key(event):
    return event.get("audit_key")


def get_record_types(event):
    value = event.get("record_types", [])

    if isinstance(value, list):
        return value

    return []


def get_syscall_name(event):
    syscall = get_syscall(event)

    return syscall.get("name", "unknown")


def get_success(event):
    syscall = get_syscall(event)

    return syscall.get("success")


def load_events(filepath):
    print(f"[+] Reading: {filepath}")

    with open(filepath, "r") as file:
        data = json.load(file)

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        if isinstance(data.get("events"), list):
            return data["events"]

    return []


def get_usable_events(events):
    usable = []

    for event in events:
        record_types = get_record_types(event)

        if "SYSCALL" not in record_types:
            continue

        pid = get_pid(event)
        ppid = get_ppid(event)

        if pid is None or ppid is None:
            continue

        usable.append(event)

    return usable


def build_process_index(events):
    pid_map = defaultdict(list)

    for event in events:
        pid = get_pid(event)

        if pid is None:
            continue

        pid_map[pid].append(event)

    for pid in pid_map:
        pid_map[pid].sort(key=parse_time)

    return pid_map


def get_first_event(events):
    if not events:
        return None

    return min(events, key=parse_time)


def build_process_nodes(events):
    pid_map = build_process_index(events)

    nodes = {}

    for pid, pid_events in pid_map.items():
        first_event = get_first_event(pid_events)

        if first_event is None:
            continue

        nodes[pid] = {
            "pid": pid,
            "ppid": get_ppid(first_event),
            "timestamp": first_event.get(
                "timestamp_iso",
                str(first_event.get("timestamp", "unknown"))
            ),
            "command": get_command(first_event),
            "exe": get_exe(first_event),
            "comm": get_comm(first_event),
            "uid": get_uid(first_event),
            "euid": get_euid(first_event),
            "auid": get_auid(first_event),
            "session": get_session(first_event),
            "tty": get_tty(first_event),
            "key": get_key(first_event),
            "event_count": len(pid_events),
            "syscall_names": sorted(
                set(
                    get_syscall_name(event)
                    for event in pid_events
                )
            ),
        }

    return nodes


def build_parent_map(nodes):
    children_of = defaultdict(list)
    parent_of = {}

    for pid, node in nodes.items():
        ppid = node.get("ppid")

        if ppid is None:
            continue

        if ppid == pid:
            continue

        if ppid not in nodes:
            continue

        parent_of[pid] = ppid
        children_of[ppid].append(pid)

    for parent_pid in children_of:
        children_of[parent_pid].sort(
            key=lambda pid: parse_time_from_node(
                nodes[pid]
            )
        )

    return parent_of, children_of


def parse_time_from_node(node):
    value = node.get("timestamp")

    if not value:
        return datetime.min

    try:
        return datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )
    except Exception:
        return datetime.min


def find_roots(nodes, parent_of):
    roots = []

    for pid in nodes:
        if pid not in parent_of:
            roots.append(pid)

    roots.sort(
        key=lambda pid: parse_time_from_node(nodes[pid])
    )

    return roots


def calculate_depth(pid, tree, visited=None):
    if visited is None:
        visited = set()

    if pid in visited:
        return 0

    visited.add(pid)

    children = tree.get(pid, [])

    if not children:
        return 1

    depths = []

    for child_pid in children:
        depth = calculate_depth(
            child_pid,
            tree,
            visited.copy()
        )

        depths.append(depth)

    return 1 + max(depths)


def collect_leaf_chains(
    pid,
    nodes,
    tree,
    current=None,
    chains=None,
    visited=None
):
    if current is None:
        current = []

    if chains is None:
        chains = []

    if visited is None:
        visited = set()

    if pid in visited:
        return chains

    if pid not in nodes:
        return chains

    visited.add(pid)

    current = current + [pid]

    children = tree.get(pid, [])

    if not children:
        if len(current) >= 2:
            chains.append(current)

        return chains

    for child_pid in children:
        collect_leaf_chains(
            child_pid,
            nodes,
            tree,
            current,
            chains,
            visited.copy()
        )

    return chains


def build_chains(nodes, tree, parent_of):
    roots = find_roots(
        nodes,
        parent_of
    )

    chains = []

    for root_pid in roots:
        collect_leaf_chains(
            root_pid,
            nodes,
            tree,
            [],
            chains,
            set()
        )

    return chains


def print_statistics(
    events,
    usable_events,
    nodes,
    parent_of,
    tree,
    chains
):
    relationships = len(parent_of)

    roots = find_roots(
        nodes,
        parent_of
    )

    max_depth = 0

    for root_pid in roots:
        depth = calculate_depth(
            root_pid,
            tree
        )

        if depth > max_depth:
            max_depth = depth

    print()
    print("=" * 60)
    print("PROCESS TREE STATISTICS")
    print("=" * 60)

    print(
        f"Total structured events : {len(events)}"
    )

    print(
        f"Usable process events   : {len(usable_events)}"
    )

    print(
        f"Unique processes        : {len(nodes)}"
    )

    print(
        f"PID/PPID relationships  : {relationships}"
    )

    print(
        f"Process tree roots      : {len(roots)}"
    )

    print(
        f"Activity chains         : {len(chains)}"
    )

    print(
        f"Maximum tree depth      : {max_depth}"
    )

    if chains:
        lengths = [
            len(chain)
            for chain in chains
        ]

        print(
            f"Longest chain           : "
            f"{max(lengths)} events"
        )

        print(
            f"Shortest chain          : "
            f"{min(lengths)} events"
        )

        print(
            f"Average chain length    : "
            f"{sum(lengths) / len(lengths):.2f} events"
        )

        distribution = defaultdict(int)

        for length in lengths:
            distribution[length] += 1

        print()
        print("Chain length distribution:")

        for length in sorted(distribution):
            print(
                f"  {length} events : "
                f"{distribution[length]} chain(s)"
            )


def print_tree(
    pid,
    nodes,
    tree,
    prefix="",
    is_last=True,
    visited=None
):
    if visited is None:
        visited = set()

    if pid in visited:
        return

    if pid not in nodes:
        return

    visited.add(pid)

    node = nodes[pid]

    if prefix:
        branch = "└── " if is_last else "├── "
    else:
        branch = ""

    print(
        f"{prefix}{branch}"
        f"PID={node['pid']} | "
        f"PPID={node['ppid']} | "
        f"{node['command']}"
    )

    children = tree.get(pid, [])

    for index, child_pid in enumerate(children):

        child_is_last = (
            index == len(children) - 1
        )

        if prefix:
            if is_last:
                child_prefix = prefix + "    "
            else:
                child_prefix = prefix + "│   "
        else:
            child_prefix = ""

        print_tree(
            child_pid,
            nodes,
            tree,
            child_prefix,
            child_is_last,
            visited.copy()
        )


def print_process_trees(
    nodes,
    tree,
    parent_of
):
    print()
    print("=" * 60)
    print("PROCESS TREES")
    print("=" * 60)

    roots = find_roots(
        nodes,
        parent_of
    )

    shown = 0

    for root_pid in roots:

        children = tree.get(
            root_pid,
            []
        )

        if not children:
            continue

        root = nodes[root_pid]

        print()
        print(
            f"ROOT PID={root_pid} | "
            f"{root['command']}"
        )

        print_tree(
            root_pid,
            nodes,
            tree
        )

        shown += 1

        if shown >= 20:
            break

    if shown == 0:
        print("No process trees with children found.")


def print_chains(
    chains,
    nodes
):
    print()
    print("=" * 60)
    print("ACTIVITY CHAINS")
    print("=" * 60)

    if not chains:
        print("No chains found.")
        return

    chains = sorted(
        chains,
        key=lambda chain: (
            -len(chain),
            parse_time_from_node(
                nodes[chain[0]]
            )
        )
    )

    for index, chain in enumerate(
        chains[:20],
        1
    ):
        print()
        print(
            f"CHAIN {index}"
        )

        print(
            "-" * 60
        )

        for position, pid in enumerate(
            chain,
            1
        ):
            node = nodes[pid]

            print(
                f"{position}. "
                f"{node['timestamp']} | "
                f"PID={node['pid']} | "
                f"PPID={node['ppid']} | "
                f"{node['command']}"
            )


def main():

    events = load_events(
        INPUT_FILE
    )

    if not events:
        print(
            "[-] No events found."
        )
        return

    usable_events = get_usable_events(
        events
    )

    print(
        f"[+] Structured events loaded : "
        f"{len(events)}"
    )

    print(
        f"[+] Usable process events    : "
        f"{len(usable_events)}"
    )

    nodes = build_process_nodes(
        usable_events
    )

    parent_of, children_of = build_parent_map(
        nodes
    )

    chains = build_chains(
        nodes,
        children_of,
        parent_of
    )

    print_statistics(
        events,
        usable_events,
        nodes,
        parent_of,
        children_of,
        chains
    )

    print_process_trees(
        nodes,
        children_of,
        parent_of
    )

    print_chains(
        chains,
        nodes
    )


if __name__ == "__main__":
    main()
