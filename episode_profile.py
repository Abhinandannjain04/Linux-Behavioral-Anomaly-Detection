import json
import math
from collections import Counter, defaultdict


INPUT_FILE = "episode_features.json"
OUTPUT_FILE = "episode_profiles.json"


def clean_value(value):
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return 0.0
    return value


def statistics(values):
    if not values:
        return {
            "mean": 0.0,
            "median": 0.0,
            "min": 0.0,
            "max": 0.0,
            "std": 0.0
        }

    values = [clean_value(v) for v in values]

    n = len(values)
    mean = sum(values) / n

    sorted_values = sorted(values)

    if n % 2 == 1:
        median = sorted_values[n // 2]
    else:
        median = (
            sorted_values[n // 2 - 1] +
            sorted_values[n // 2]
        ) / 2

    variance = sum((x - mean) ** 2 for x in values) / n
    std = math.sqrt(variance)

    return {
        "mean": mean,
        "median": median,
        "min": min(values),
        "max": max(values),
        "std": std
    }


def get_profile_key(episode):
    identity = episode.get("identity", {})

    auid = identity.get("auid")

    if auid is None:
        return "AUID_UNKNOWN"

    if auid == 4294967295:
        return "AUID_UNSET"

    return f"AUID_{auid}"


def build_profile(episodes):
    episode_count = len(episodes)

    temporal_values = defaultdict(list)

    behavior_episode_counts = Counter()
    behavior_primary_counts = Counter()

    transition_counts = Counter()
    sequence_counts = Counter()

    process_counts = []
    relationship_counts = []

    cross_process_count = 0
    ancestor_descendant_count = 0
    same_process_count = 0

    target_counts = []
    command_counts = []
    syscall_counts = []

    target_frequency = Counter()
    command_frequency = Counter()
    syscall_frequency = Counter()

    for episode in episodes:

        temporal = episode.get("temporal", {})
        behavioral = episode.get("behavioral", {})
        sequence = episode.get("sequence", {})
        process = episode.get("process", {})
        context = episode.get("context", {})

        # ---------------------------------
        # TEMPORAL PROFILE
        # ---------------------------------

        for field in [
            "duration",
            "event_count",
            "event_rate",
            "mean_inter_event_time",
            "min_inter_event_time",
            "max_inter_event_time",
            "std_inter_event_time"
        ]:
            if field in temporal:
                temporal_values[field].append(temporal[field])

        # ---------------------------------
        # BEHAVIORAL PROFILE
        # ---------------------------------

        episode_behaviors = behavioral.get(
            "episode_behaviors", []
        )

        for behavior in set(episode_behaviors):
            behavior_episode_counts[behavior] += 1

        primary_counts = behavioral.get(
            "primary_behavior_counts", {}
        )

        for behavior, count in primary_counts.items():
            behavior_primary_counts[behavior] += count

        # ---------------------------------
        # SEQUENCE PROFILE
        # ---------------------------------

        for transition in sequence.get(
            "transitions", []
        ):
            transition_counts[transition] += 1

        behavior_sequence = sequence.get(
            "behavior_sequence", []
        )

        if behavior_sequence:
            sequence_key = " -> ".join(behavior_sequence)
            sequence_counts[sequence_key] += 1

        # ---------------------------------
        # PROCESS PROFILE
        # ---------------------------------

        process_counts.append(
            process.get("process_count", 0)
        )

        relationship_counts.append(
            process.get("relationship_count", 0)
        )

        if process.get("cross_process", False):
            cross_process_count += 1

        if process.get("has_ancestor_descendant", False):
            ancestor_descendant_count += 1

        if process.get("has_same_process", False):
            same_process_count += 1

        # ---------------------------------
        # CONTEXT PROFILE
        # ---------------------------------

        target_counts.append(
            context.get("target_count", 0)
        )

        command_counts.append(
            context.get("command_count", 0)
        )

        syscall_counts.append(
            context.get("syscall_count", 0)
        )

        for target in context.get("targets", []):
            target_frequency[target] += 1

        for command in context.get("commands", []):
            command_line = command.get("command_line")

            if command_line:
                command_frequency[command_line] += 1

        for syscall in context.get("syscalls", []):
            syscall_frequency[syscall] += 1

    # ---------------------------------
    # FREQUENCIES
    # ---------------------------------

    behavior_episode_frequency = {}

    for behavior, count in behavior_episode_counts.items():
        behavior_episode_frequency[behavior] = (
            count / episode_count
        )

    behavior_primary_event_rate = {}

    total_primary_events = sum(
        behavior_primary_counts.values()
    )

    if total_primary_events > 0:
        for behavior, count in behavior_primary_counts.items():
            behavior_primary_event_rate[behavior] = (
                count / total_primary_events
            )

    transition_frequency = {}

    for transition, count in transition_counts.items():
        transition_frequency[transition] = (
            count / episode_count
        )

    cross_process_frequency = (
        cross_process_count / episode_count
        if episode_count else 0.0
    )

    ancestor_descendant_frequency = (
        ancestor_descendant_count / episode_count
        if episode_count else 0.0
    )

    same_process_frequency = (
        same_process_count / episode_count
        if episode_count else 0.0
    )

    # ---------------------------------
    # PROFILE
    # ---------------------------------

    profile = {
        "episode_count": episode_count,

        "temporal": {},

        "behavioral": {
            "behavior_episode_counts":
                dict(behavior_episode_counts),

            "behavior_primary_counts":
                dict(behavior_primary_counts),

            "behavior_episode_frequency":
                behavior_episode_frequency,

            "behavior_primary_event_rate":
                behavior_primary_event_rate
        },

        "sequence": {
            "transition_counts":
                dict(transition_counts),

            "sequence_counts":
                dict(sequence_counts),

            "transition_frequency":
                transition_frequency
        },

        "process": {
            "process_count":
                statistics(process_counts),

            "relationship_count":
                statistics(relationship_counts),

            "cross_process_frequency":
                cross_process_frequency,

            "ancestor_descendant_frequency":
                ancestor_descendant_frequency,

            "same_process_frequency":
                same_process_frequency
        },

        "context": {
            "target_count":
                statistics(target_counts),

            "command_count":
                statistics(command_counts),

            "syscall_count":
                statistics(syscall_counts),

            "target_frequency":
                dict(target_frequency),

            "command_frequency":
                dict(command_frequency),

            "syscall_frequency":
                dict(syscall_frequency)
        }
    }

    for field, values in temporal_values.items():
        profile["temporal"][field] = statistics(values)

    return profile


def main():

    with open(INPUT_FILE, "r") as f:
        episodes = json.load(f)

    profiles = defaultdict(list)

    for episode in episodes:
        profile_key = get_profile_key(episode)
        profiles[profile_key].append(episode)

    output_profiles = {}

    for profile_key, profile_episodes in profiles.items():
        output_profiles[profile_key] = build_profile(
            profile_episodes
        )

    output = {
        "profile_version": 2,
        "source": INPUT_FILE,
        "profile_count": len(output_profiles),
        "profiles": dict(output_profiles)
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(
            output,
            f,
            indent=4
        )

    print(f"Processed episodes: {len(episodes)}")
    print(f"Profiles created: {len(output_profiles)}")
    print(f"Output: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
