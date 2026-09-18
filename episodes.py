import json
from collections import defaultdict

BEHAVIORAL_FILE = "/opt/audit-lab/behavioral_events.json"
CORRELATION_FILE = "/opt/audit-lab/correlated_events_v2.json"
OUTPUT_FILE = "/opt/audit-lab/episodes.json"

EPISODE_GAP = 30.0

print(f"[+] Loading behavioral events: {BEHAVIORAL_FILE}")

with open(BEHAVIORAL_FILE, "r") as f:
    behavioral_events = json.load(f)

print(f"[+] Behavioral events loaded: {len(behavioral_events)}")

print(f"[+] Loading correlations: {CORRELATION_FILE}")

with open(CORRELATION_FILE, "r") as f:
    correlations = json.load(f)

print(f"[+] Correlations loaded: {len(correlations)}")


# ---------------------------------------------------------
# BEHAVIOR PRIORITY
# ---------------------------------------------------------

BEHAVIOR_PRIORITY = [
    "PRIVILEGE_ESCALATION",
    "FILE_DELETE",
    "FILE_WRITE",
    "FILE_READ",
    "FILE_DISCOVERY",
    "SHELL_EXECUTION",
    "PRIVILEGE_TOOL_USAGE",
    "PROCESS_EXECUTION",
    "ROOT_CONTEXT",
    "PERMISSION_CHANGE"
]

PRIORITY = {
    behavior: index
    for index, behavior in enumerate(BEHAVIOR_PRIORITY)
}


def get_primary_behavior(behaviors):
    if not behaviors:
        return None

    valid = [
        behavior
        for behavior in behaviors
        if behavior in PRIORITY
    ]

    if not valid:
        return behaviors[0]

    return sorted(
        valid,
        key=lambda x: PRIORITY[x]
    )[0]


# ---------------------------------------------------------
# INDEX ALL BEHAVIORAL EVENTS
# ---------------------------------------------------------

behavior_index = {}

for event in behavioral_events:
    event_id = event.get("event_id")

    if not event_id:
        continue

    behavior_index[event_id] = event

print(f"[+] Behavioral event index: {len(behavior_index)}")


# ---------------------------------------------------------
# DEDUPLICATE CORRELATIONS
# ---------------------------------------------------------

seen = set()
edges = []

for correlation in correlations:

    key = (
        correlation.get("event1"),
        correlation.get("event2"),
        correlation.get("relationship"),
        correlation.get("pid1"),
        correlation.get("pid2")
    )

    if key in seen:
        continue

    seen.add(key)
    edges.append(correlation)

print(f"[+] Unique correlation relationships: {len(edges)}")


# ---------------------------------------------------------
# BUILD CORRELATION GRAPH
# ---------------------------------------------------------

graph = defaultdict(set)
correlated_ids = set()

for correlation in edges:

    event1 = correlation.get("event1")
    event2 = correlation.get("event2")

    if not event1 or not event2:
        continue

    if event1 not in behavior_index:
        continue

    if event2 not in behavior_index:
        continue

    graph[event1].add(event2)
    graph[event2].add(event1)

    correlated_ids.add(event1)
    correlated_ids.add(event2)

print(f"[+] Episode graph nodes: {len(correlated_ids)}")


# ---------------------------------------------------------
# FIND CONNECTED COMPONENTS
# ---------------------------------------------------------

visited = set()
components = []

for event_id in graph:

    if event_id in visited:
        continue

    stack = [event_id]
    component = []

    while stack:

        current = stack.pop()

        if current in visited:
            continue

        visited.add(current)
        component.append(current)

        for neighbor in graph[current]:

            if neighbor not in visited:
                stack.append(neighbor)

    components.append(component)

print(f"[+] Connected components: {len(components)}")


# ---------------------------------------------------------
# BUILD EVENT REPRESENTATIONS
# ---------------------------------------------------------

def build_event(event_id):

    event = behavior_index[event_id]

    user = event.get("user", {})
    process = event.get("process", {})
    behaviors = event.get("behaviors", [])

    if not isinstance(behaviors, list):
        behaviors = []

    primary_behavior = get_primary_behavior(behaviors)

    return {
        "event_id": event_id,
        "timestamp": float(event.get("timestamp", 0)),
        "timestamp_iso": event.get("timestamp_iso"),

        "user": user,
        "session": event.get("session"),

        "pid": process.get("pid"),
        "ppid": process.get("ppid"),
        "comm": process.get("comm"),
        "exe": process.get("exe"),

        "behaviors": behaviors,
        "primary_behavior": primary_behavior,

        "cwd": event.get("cwd"),

        "paths": event.get("paths", []),

        "command": event.get("command", {}),

        "syscall": event.get("syscall", {}),

        "tty": event.get("tty"),

        "audit_key": event.get("audit_key")
    }


# ---------------------------------------------------------
# BUILD EPISODES
# ---------------------------------------------------------

episodes = []

for component in components:

    component_events = []

    for event_id in component:

        if event_id in behavior_index:
            component_events.append(
                build_event(event_id)
            )

    if not component_events:
        continue

    component_events.sort(
        key=lambda x: x["timestamp"]
    )

    groups = []
    current_group = [component_events[0]]

    for event in component_events[1:]:

        previous = current_group[-1]

        time_gap = (
            event["timestamp"]
            - previous["timestamp"]
        )

        same_user = (
            event["user"].get("auid")
            == previous["user"].get("auid")
        )

        same_session = (
            event["session"]
            == previous["session"]
        )

        same_pid = (
            event["pid"] is not None
            and event["pid"] == previous["pid"]
        )

        parent_child = (
            event["ppid"] == previous["pid"]
            or
            previous["ppid"] == event["pid"]
        )

        connected_process = (
            same_pid
            or
            parent_child
        )

        if (
            same_user
            and same_session
            and time_gap <= EPISODE_GAP
            and connected_process
        ):
            current_group.append(event)

        else:
            groups.append(current_group)
            current_group = [event]

    groups.append(current_group)


    # -----------------------------------------------------
    # CREATE EPISODE FROM GROUP
    # -----------------------------------------------------

    for group in groups:

        group.sort(
            key=lambda x: x["timestamp"]
        )

        start_time = group[0]["timestamp"]
        end_time = group[-1]["timestamp"]

        event_ids = []
        correlated_event_ids = []

        behaviors = []
        processes = []
        targets = []
        commands = []
        syscalls = []

        behavior_sequence = []

        relationships = set()

        # -------------------------------------------------
        # EVENTS
        # -------------------------------------------------

        for event in group:

            event_id = event["event_id"]

            event_ids.append(event_id)

            if event_id in correlated_ids:
                correlated_event_ids.append(event_id)

            for behavior in event["behaviors"]:

                if behavior not in behaviors:
                    behaviors.append(behavior)

            if event["pid"] is not None:

                process = {
                    "pid": event["pid"],
                    "ppid": event["ppid"],
                    "comm": event["comm"],
                    "exe": event["exe"]
                }

                if process not in processes:
                    processes.append(process)

            for path in event["paths"]:

                if isinstance(path, dict):
                    path_value = path.get("path")
                else:
                    path_value = path

                if path_value and path_value not in targets:
                    targets.append(path_value)

            command = event["command"]

            if command:

                if command not in commands:
                    commands.append(command)

            syscall = event["syscall"]

            if isinstance(syscall, dict):

                syscall_name = syscall.get("name")

                if syscall_name and syscall_name != "unknown":

                    if syscall_name not in syscalls:
                        syscalls.append(syscall_name)

            behavior_sequence.append({
                "event_id": event_id,
                "timestamp": event["timestamp"],
                "behavior": event["primary_behavior"],
                "behaviors": event["behaviors"]
            })


        # -------------------------------------------------
        # RELATIONSHIPS
        # -------------------------------------------------

        group_ids = set(event_ids)

        for correlation in edges:

            event1 = correlation.get("event1")
            event2 = correlation.get("event2")

            if (
                event1 in group_ids
                and event2 in group_ids
            ):

                relationship = correlation.get(
                    "relationship"
                )

                if relationship:
                    relationships.add(
                        relationship
                    )


                # -------------------------------------------------
        # BEHAVIOR TRANSITIONS
        #
        # Use the actual correlated behavior pair.
        # Do not infer transitions from the primary behavior.
        # -------------------------------------------------

        transitions = []

        for correlation in edges:

            event1 = correlation.get("event1")
            event2 = correlation.get("event2")

            if (
                event1 not in group_ids
                or event2 not in group_ids
            ):
                continue

            b1 = correlation.get("behavior1")
            b2 = correlation.get("behavior2")

            if not b1 or not b2:
                continue

            transition = f"{b1} -> {b2}"

            if transition not in transitions:
                transitions.append(transition)

        # -------------------------------------------------
        # EPISODE USER
        # -------------------------------------------------

        episode_user = group[0]["user"]

        # -------------------------------------------------
        # CREATE EPISODE
        # -------------------------------------------------

        episode = {

            "episode_id":
                f"EP-{len(episodes) + 1:04d}",

            "start_time":
                start_time,

            "end_time":
                end_time,

            "duration":
                round(
                    end_time - start_time,
                    3
                ),

            "user":
                episode_user,

            "session":
                group[0]["session"],

            "processes":
                processes,

            "behaviors":
                behaviors,

            "events":
                event_ids,

            "correlated_events":
                correlated_event_ids,

            "targets":
                targets,

            "commands":
                commands,

            "syscalls":
                syscalls,

            "relationships":
                sorted(relationships),

            "behavior_sequence":
                behavior_sequence,

            "behavior_transitions":
                transitions
        }

        episodes.append(episode)


# ---------------------------------------------------------
# VALIDATION
# ---------------------------------------------------------

matched = len(correlated_ids)

total_correlated = len(
    set(
        event_id
        for event_id in correlated_ids
    )
)

print(
    f"[+] Correlated events matched behavioral events: "
    f"{matched}/{total_correlated}"
)

print(
    f"[+] Episodes created: {len(episodes)}"
)

if matched == total_correlated:
    print(
        "[+] All correlated events matched behavioral events"
    )
else:
    print(
        "[!] WARNING: Some correlated events "
        "were not found in behavioral events"
    )


# ---------------------------------------------------------
# WRITE OUTPUT
# ---------------------------------------------------------

with open(OUTPUT_FILE, "w") as f:

    json.dump(
        episodes,
        f,
        indent=2
    )

print(
    f"[+] Output: {OUTPUT_FILE}"
)

print()
print("[+] Episode summary")

for episode in episodes:

    print(
        f"    {episode['episode_id']} | "
        f"events={len(episode['events'])} | "
        f"correlated={len(episode['correlated_events'])} | "
        f"duration={episode['duration']}s | "
        f"behaviors={episode['behaviors']} | "
        f"transitions={episode['behavior_transitions']} | "
        f"relationships={episode['relationships']}"
    )
