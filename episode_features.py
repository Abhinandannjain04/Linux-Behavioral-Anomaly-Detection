import json
import math


INPUT_FILE = "episodes.json"
OUTPUT_FILE = "episode_features.json"


def safe_rate(count, duration):
    if duration <= 0:
        return 0.0

    return count / duration


def calculate_temporal_features(episode):
    timestamps = [
        event["timestamp"]
        for event in episode.get("behavior_sequence", [])
        if "timestamp" in event
    ]

    timestamps.sort()

    duration = episode.get("duration", 0.0)
    event_count = len(timestamps)

    intervals = []

    for i in range(1, len(timestamps)):
        intervals.append(timestamps[i] - timestamps[i - 1])

    if intervals:
        mean_interval = sum(intervals) / len(intervals)
        min_interval = min(intervals)
        max_interval = max(intervals)

        variance = sum(
            (interval - mean_interval) ** 2
            for interval in intervals
        ) / len(intervals)

        std_interval = math.sqrt(variance)

    else:
        mean_interval = 0.0
        min_interval = 0.0
        max_interval = 0.0
        std_interval = 0.0

    return {
        "start_time": episode.get("start_time"),
        "end_time": episode.get("end_time"),
        "duration": duration,
        "event_count": event_count,
        "event_rate": safe_rate(event_count, duration),
        "mean_inter_event_time": mean_interval,
        "min_inter_event_time": min_interval,
        "max_inter_event_time": max_interval,
        "std_inter_event_time": std_interval
    }


def calculate_behavioral_features(episode):
    behavior_sequence = episode.get("behavior_sequence", [])

    primary_behaviors = [
        event.get("behavior")
        for event in behavior_sequence
        if event.get("behavior")
    ]

    all_behaviors = set(episode.get("behaviors", []))

    behavior_counts = {}

    for behavior in primary_behaviors:
        behavior_counts[behavior] = (
            behavior_counts.get(behavior, 0) + 1
        )

    behavior_diversity = len(set(primary_behaviors))

    features = {
        "sequence_length": len(primary_behaviors),
        "behavior_diversity": behavior_diversity,
        "primary_behavior_counts": behavior_counts,
        "episode_behavior_diversity": len(all_behaviors),
        "episode_behaviors": sorted(all_behaviors)
    }

    behavior_types = [
        "PROCESS_EXECUTION",
        "ROOT_CONTEXT",
        "SHELL_EXECUTION",
        "FILE_READ",
        "FILE_WRITE",
        "FILE_DELETE",
        "FILE_DISCOVERY",
        "PRIVILEGE_ESCALATION",
        "PRIVILEGE_TOOL_USAGE",
        "PERMISSION_CHANGE"
    ]

    for behavior in behavior_types:
        features[f"has_{behavior.lower()}"] = (
            behavior in all_behaviors
        )

    return features


def calculate_sequence_features(episode):
    sequence = [
        event.get("behavior")
        for event in episode.get("behavior_sequence", [])
        if event.get("behavior")
    ]

    transitions = episode.get("behavior_transitions", [])

    parsed_transitions = []

    for transition in transitions:
        parts = transition.split(" -> ", 1)

        if len(parts) == 2:
            parsed_transitions.append({
                "from": parts[0],
                "to": parts[1]
            })

    repeated_behavior_count = 0
    max_consecutive_same_behavior = 0
    current_run = 0
    previous = None

    for behavior in sequence:
        if behavior == previous:
            current_run += 1
        else:
            current_run = 1

        max_consecutive_same_behavior = max(
            max_consecutive_same_behavior,
            current_run
        )

        if current_run > 1:
            repeated_behavior_count += 1

        previous = behavior

    return {
        "behavior_sequence": sequence,
        "transition_count": len(transitions),
        "unique_transition_count": len(set(transitions)),
        "transitions": transitions,
        "parsed_transitions": parsed_transitions,
        "repeated_behavior_count": repeated_behavior_count,
        "max_consecutive_same_behavior": max_consecutive_same_behavior
    }


def calculate_process_features(episode):
    processes = episode.get("processes", [])
    relationships = episode.get("relationships", [])

    pids = {
        process.get("pid")
        for process in processes
        if process.get("pid") is not None
    }

    return {
        "process_count": len(pids),
        "cross_process": len(pids) > 1,
        "relationship_count": len(relationships),
        "has_ancestor_descendant": (
            "ancestor_descendant" in relationships
        ),
        "has_same_process": (
            "same_process" in relationships
        )
    }


def calculate_identity_features(episode):
    user = episode.get("user", {})

    auid = user.get("auid")
    uid = user.get("uid")
    euid = user.get("euid")
    gid = user.get("gid")
    egid = user.get("egid")

    uid_euid_mismatch = (
        uid is not None
        and euid is not None
        and uid != euid
    )

    return {
        "auid": auid,
        "uid": uid,
        "euid": euid,
        "gid": gid,
        "egid": egid,
        "uid_euid_mismatch": uid_euid_mismatch,
        "privilege_transition": uid_euid_mismatch,
        "root_context": euid == 0,
        "session": episode.get("session")
    }


def calculate_context_features(episode):
    targets = episode.get("targets", [])
    commands = episode.get("commands", [])
    syscalls = episode.get("syscalls", [])

    return {
        "target_count": len(targets),
        "command_count": len(commands),
        "syscall_count": len(syscalls),
        "unique_target_count": len(set(targets)),
        "unique_syscall_count": len(set(syscalls)),
        "targets": targets,
        "commands": commands,
        "syscalls": syscalls
    }


def build_episode_features(episode):
    return {
        "episode_id": episode.get("episode_id"),
        "temporal": calculate_temporal_features(episode),
        "behavioral": calculate_behavioral_features(episode),
        "sequence": calculate_sequence_features(episode),
        "process": calculate_process_features(episode),
        "identity": calculate_identity_features(episode),
        "context": calculate_context_features(episode)
    }


def main():
    with open(INPUT_FILE, "r") as f:
        episodes = json.load(f)

    feature_records = []

    for episode in episodes:
        feature_records.append(
            build_episode_features(episode)
        )

    with open(OUTPUT_FILE, "w") as f:
        json.dump(
            feature_records,
            f,
            indent=4
        )

    print(f"Processed episodes: {len(episodes)}")
    print(f"Feature records: {len(feature_records)}")
    print(f"Output: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
