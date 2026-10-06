import json
import math
import ast


FEATURES_FILE = "episode_features.json"
PROFILES_FILE = "episode_profiles.json"
OUTPUT_FILE = "episode_deviations.json"


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)


def get_profile_key(identity):
    auid = identity.get("auid")
    uid = identity.get("uid")

    if auid is not None and auid != 4294967295:
        return f"AUID_{auid}"

    if uid is not None:
        return f"UID_{uid}"

    return None


def safe_z_score(value, stats):
    mean = stats.get("mean")
    std = stats.get("std")

    if mean is None or std is None:
        return None

    if std > 0:
        return abs(value - mean) / std

    return 0.0 if value == mean else None


def numeric_deviation(value, stats):
    result = {
        "value": value,
        "mean": stats.get("mean"),
        "median": stats.get("median"),
        "min": stats.get("min"),
        "max": stats.get("max"),
        "std": stats.get("std"),
        "z_score": None,
        "out_of_range": None
    }

    if value is None or not stats:
        return result

    result["z_score"] = safe_z_score(value, stats)

    minimum = stats.get("min")
    maximum = stats.get("max")

    if minimum is not None and maximum is not None:
        result["out_of_range"] = value < minimum or value > maximum

    return result


def analyze_behavior_deviation(episode, profile):
    current = episode.get("behavioral", {})
    profile_behavioral = profile.get("behavioral", {})

    episode_behaviors = current.get("episode_behaviors", [])

    frequency_map = profile_behavioral.get(
        "behavior_episode_frequency", {}
    )

    primary_rate_map = profile_behavioral.get(
        "behavior_primary_event_rate", {}
    )

    behavior_counts = current.get(
        "behavior_counts",
        current.get("primary_behavior_counts", {})
    )

    profile_available = bool(frequency_map)

    observed = {}

    novel_behaviors = []
    rare_candidates = []

    for behavior in episode_behaviors:
        frequency = frequency_map.get(behavior)

        record = {
            "profile_frequency": frequency,
            "novel": None if not profile_available else frequency is None
        }

        if profile_available:
            if frequency is None:
                frequency = 0.0
                record["profile_frequency"] = frequency
                record["novel"] = True
                novel_behaviors.append(behavior)
            else:
                if frequency <= 0.1:
                    rare_candidates.append(behavior)

        observed[behavior] = record

    primary_behaviors = {}

    for behavior, count in behavior_counts.items():
        primary_behaviors[behavior] = {
            "current_count": count,
            "profile_event_rate": primary_rate_map.get(behavior),
            "profile_available": bool(primary_rate_map)
        }

    return {
        "profile_available": profile_available,
        "observed_behaviors": observed,
        "novel_behaviors": novel_behaviors,
        "rare_behaviors": rare_candidates,
        "primary_behaviors": primary_behaviors
    }


def analyze_sequence_deviation(episode, profile):
    current_sequence = episode.get("sequence", {})
    profile_sequence = profile.get("sequence", {})

    transitions = current_sequence.get("transitions", [])

    transition_frequency = profile_sequence.get(
        "transition_frequency", {}
    )

    sequence_counts = profile_sequence.get(
        "sequence_counts", {}
    )

    transition_records = []
    novel_transitions = []

    transition_profile_available = bool(transition_frequency)

    for transition in transitions:
        frequency = transition_frequency.get(transition)

        record = {
            "profile_frequency": frequency,
            "novel": None if not transition_profile_available else frequency is None
        }

        if transition_profile_available and frequency is None:
            record["profile_frequency"] = 0.0
            record["novel"] = True
            novel_transitions.append(transition)

        transition_records.append({
            "transition": transition,
            **record
        })

    behavior_sequence = current_sequence.get(
        "behavior_sequence", []
    )

    full_sequence = " -> ".join(behavior_sequence)

    full_sequence_available = bool(sequence_counts)

    if full_sequence_available:
        sequence_count = sequence_counts.get(full_sequence, 0)

        full_sequence_record = {
            "sequence": full_sequence,
            "count": sequence_count,
            "observed": sequence_count > 0,
            "novel": sequence_count == 0
        }
    else:
        full_sequence_record = {
            "sequence": full_sequence,
            "count": None,
            "observed": None,
            "novel": None
        }

    return {
        "transition_profile_available": transition_profile_available,
        "transitions": transition_records,
        "novel_transitions": novel_transitions,
        "full_sequence_profile_available": full_sequence_available,
        "full_sequence": full_sequence_record
    }


def analyze_temporal_deviation(episode, profile):
    current = episode.get("temporal", {})
    profile_temporal = profile.get("temporal", {})

    metrics = [
        "duration",
        "event_count",
        "event_rate",
        "mean_inter_event_time",
        "min_inter_event_time",
        "max_inter_event_time",
        "std_inter_event_time"
    ]

    result = {}

    for metric in metrics:
        value = current.get(metric)
        stats = profile_temporal.get(metric, {})

        result[metric] = numeric_deviation(value, stats)

    return result


def analyze_process_deviation(episode, profile):
    current = episode.get("process", {})
    profile_process = profile.get("process", {})

    numerical = {}

    for metric in [
        "process_count",
        "relationship_count"
    ]:
        numerical[metric] = numeric_deviation(
            current.get(metric),
            profile_process.get(metric, {})
        )

    boolean_metrics = [
        ("cross_process", "cross_process_frequency"),
        ("has_ancestor_descendant", "ancestor_descendant_frequency"),
        ("has_same_process", "same_process_frequency")
    ]

    boolean_results = {}

    for current_key, profile_key in boolean_metrics:
        boolean_results[current_key] = {
            "value": current.get(current_key),
            "profile_frequency": profile_process.get(profile_key),
            "profile_available": profile_process.get(profile_key) is not None
        }

    return {
        "numerical": numerical,
        "boolean": boolean_results
    }

def extract_command_lines(command_frequency):
    return set(command_frequency.keys())


def analyze_context_deviation(episode, profile):
    current = episode.get("context", {})
    profile_context = profile.get("context", {})

    numerical = {}

    for metric in [
        "target_count",
        "command_count",
        "syscall_count"
    ]:
        numerical[metric] = numeric_deviation(
            current.get(metric),
            profile_context.get(metric, {})
        )

    profile_targets = profile_context.get(
        "target_frequency", {}
    )

    profile_commands = extract_command_lines(
        profile_context.get("command_frequency", {})
    )

    profile_syscalls = profile_context.get(
        "syscall_frequency", {}
    )

    current_targets = current.get("targets", [])
    current_commands = current.get("commands", [])
    current_syscalls = current.get("syscalls", [])

    novel_targets = []
    target_records = []

    for target in current_targets:
        count = profile_targets.get(target)

        target_records.append({
            "target": target,
            "profile_count": count,
            "novel": count is None
        })

        if count is None:
            novel_targets.append(target)

    novel_commands = []
    command_records = []

    for command in current_commands:
        command_line = command.get("command_line")

        if command_line is None:
            continue
       
        known = command_line in profile_commands
        
       

        command_records.append({
            "command_line": command_line,
            "known": known,
            "novel": not known
        })

        if not known:
            novel_commands.append(command_line)

    novel_syscalls = []
    syscall_records = []

    for syscall in current_syscalls:
        count = profile_syscalls.get(syscall)

        syscall_records.append({
            "syscall": syscall,
            "profile_count": count,
            "novel": count is None
        })

        if count is None:
            novel_syscalls.append(syscall)

    return {
        "numerical": numerical,
        "targets": target_records,
        "novel_targets": novel_targets,
        "commands": command_records,
        "novel_commands": novel_commands,
        "syscalls": syscall_records,
        "novel_syscalls": novel_syscalls
    }


def build_deviation_record(episode, profile_key, profile):
    identity = episode.get("identity", {})

    return {
        "episode_id": episode.get("episode_id"),
        "profile_used": profile_key,
        "profile_episode_count": profile.get("episode_count", 0),
        "behavioral": analyze_behavior_deviation(
            episode,
            profile
        ),
        "sequence": analyze_sequence_deviation(
            episode,
            profile
        ),
        "temporal": analyze_temporal_deviation(
            episode,
            profile
        ),
        "process": analyze_process_deviation(
            episode,
            profile
        ),
        "context": analyze_context_deviation(
            episode,
            profile
        )
    }


def main():
    episodes = load_json(FEATURES_FILE)
    profile_data = load_json(PROFILES_FILE)

    profiles = profile_data.get("profiles", {})

    deviation_records = []
    skipped = 0

    for episode in episodes:
        identity = episode.get("identity", {})

        profile_key = get_profile_key(identity)

        if profile_key is None:
            skipped += 1
            continue

        profile = profiles.get(profile_key)

        if profile is None:
            deviation_records.append({
                "episode_id": episode.get("episode_id"),
                "profile_used": None,
                "profile_available": False,
                "requested_profile": profile_key,
                "reason": "No matching profile exists"
            })
            continue

        record = build_deviation_record(
            episode,
            profile_key,
            profile
        )

        deviation_records.append(record)

    output = {
        "deviation_version": 1,
        "source_features": FEATURES_FILE,
        "source_profiles": PROFILES_FILE,
        "profile_version": profile_data.get(
            "profile_version"
        ),
        "episode_count": len(deviation_records),
        "skipped_count": skipped,
        "deviations": deviation_records
    }

    save_json(OUTPUT_FILE, output)

    print(f"Processed episodes: {len(deviation_records)}")
    print(f"Skipped episodes: {skipped}")
    print(f"Output: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
