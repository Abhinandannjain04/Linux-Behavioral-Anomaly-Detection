import re
import sys
import json
from datetime import datetime, timezone


SYSCALL_MAP = {
    59: "execve",
    322: "execveat"
}


class AuditRecord:
    def __init__(self, record_type, timestamp, serial, fields, raw):
        self.record_type = record_type
        self.timestamp = timestamp
        self.serial = serial
        self.fields = fields
        self.raw = raw

    @property
    def event_id(self):
        return f"{self.timestamp}:{self.serial}"


def parse_audit_header(line):
    match = re.search(
        r'type=(\S+).*msg=audit\((\d+\.\d+):(\d+)\)',
        line
    )

    if not match:
        return None

    record_type = match.group(1)
    timestamp = float(match.group(2))
    serial = int(match.group(3))

    return record_type, timestamp, serial


def parse_fields(line):
    fields = {}

    pattern = r'(\w+)=(".*?"|\S+)'

    for match in re.finditer(pattern, line):
        key = match.group(1)
        value = match.group(2)

        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]

        fields[key] = value

    return fields


def parse_line(line):
    header = parse_audit_header(line)

    if header is None:
        return None

    record_type, timestamp, serial = header
    fields = parse_fields(line)

    return AuditRecord(
        record_type,
        timestamp,
        serial,
        fields,
        line
    )


def to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize_success(value):
    if value == "yes":
        return True

    if value == "no":
        return False

    return None


def decode_hex(value):
    if not value:
        return value

    try:
        if re.fullmatch(r'[0-9a-fA-F]+', value) and len(value) % 2 == 0:
            decoded = bytes.fromhex(value)

            if all(
                byte in range(32, 127) or byte in (0, 9, 10)
                for byte in decoded
            ):
                return decoded.decode("utf-8", errors="replace")
    except Exception:
        pass

    return value


def decode_execve(fields):
    argc = to_int(fields.get("argc"))

    if argc is None:
        return {
            "argc": None,
            "args": [],
            "command_line": ""
        }

    args = []

    for i in range(argc):
        key = f"a{i}"

        if key in fields:
            value = fields[key]
            value = decode_hex(value)
            args.append(value)

    command_line = " ".join(args)

    return {
        "argc": argc,
        "args": args,
        "command_line": command_line
    }


def decode_proctitle(value):
    if not value:
        return None

    try:
        decoded = bytes.fromhex(value)
        decoded = decoded.replace(b"\x00", b" ")

        return decoded.decode(
            "utf-8",
            errors="replace"
        )
    except Exception:
        return value


def timestamp_to_iso(timestamp):
    try:
        return datetime.fromtimestamp(
            timestamp,
            timezone.utc
        ).isoformat()
    except Exception:
        return None


class EventBuffer:

    def __init__(self):
        self.events = {}

    def add(self, record):
        event_id = record.event_id

        if event_id not in self.events:
            self.events[event_id] = []

        self.events[event_id].append(record)

    def get_events(self):
        return self.events.values()


def build_structured_event(records):

    records = sorted(
        records,
        key=lambda r: r.record_type
    )

    first = records[0]

    event = {
        "event_id": first.event_id,
        "timestamp": first.timestamp,
        "timestamp_iso": timestamp_to_iso(first.timestamp),
        "record_types": [],
        "user": {},
        "process": {},
        "syscall": {},
        "command": {},
        "cwd": None,
        "paths": [],
        "session": None,
        "tty": None,
        "audit_key": None
    }

    for record in records:

        if record.record_type not in event["record_types"]:
            event["record_types"].append(
                record.record_type
            )

        fields = record.fields

        if record.record_type == "SYSCALL":

            event["user"] = {
                "auid": to_int(fields.get("auid")),
                "uid": to_int(fields.get("uid")),
                "euid": to_int(fields.get("euid")),
                "gid": to_int(fields.get("gid")),
                "egid": to_int(fields.get("egid"))
            }

            event["process"] = {
                "pid": to_int(fields.get("pid")),
                "ppid": to_int(fields.get("ppid")),
                "comm": fields.get("comm"),
                "exe": fields.get("exe")
            }

            syscall_number = to_int(
                fields.get("syscall")
            )

            event["syscall"] = {
                "number": syscall_number,
                "name": SYSCALL_MAP.get(
                    syscall_number,
                    "unknown"
                ),
                "success": normalize_success(
                    fields.get("success")
                ),
                "exit": to_int(
                    fields.get("exit")
                )
            }

            event["session"] = to_int(
                fields.get("ses")
            )

            event["tty"] = fields.get(
                "tty"
            )

            event["audit_key"] = fields.get(
                "key"
            )

        elif record.record_type == "EXECVE":

            event["command"] = decode_execve(
                fields
            )

        elif record.record_type == "PROCTITLE":

            event["process"]["proctitle"] = (
                decode_proctitle(
                    fields.get("proctitle")
                )
            )

        elif record.record_type == "CWD":

            event["cwd"] = fields.get(
                "cwd"
            )

        elif record.record_type == "PATH":

            path_info = {
                "path": fields.get("name"),
                "inode": to_int(
                    fields.get("inode")
                ),
                "dev": fields.get("dev"),
                "mode": fields.get("mode"),
                "uid": to_int(
                    fields.get("ouid")
                ),
                "gid": to_int(
                    fields.get("ogid")
                ),
                "nametype": fields.get(
                    "nametype"
                )
            }

            event["paths"].append(
                path_info
            )

    return event


def parse_file(filepath):

    buffer = EventBuffer()

    lines_processed = 0
    records_parsed = 0
    ignored_lines = 0
    failed_lines = 0

    with open(
        filepath,
        "r",
        encoding="utf-8",
        errors="replace"
    ) as file:

        for line in file:

            lines_processed += 1

            line = line.strip()

            if not line:
                ignored_lines += 1
                continue

            if line == "----":
                ignored_lines += 1
                continue

            if line.startswith("time->"):
                ignored_lines += 1
                continue

            record = parse_line(line)

            if record is None:
                failed_lines += 1
                continue

            records_parsed += 1
            buffer.add(record)

    structured_events = []

    for records in buffer.get_events():

        event = build_structured_event(
            records
        )

        structured_events.append(
            event
        )

    structured_events.sort(
        key=lambda event: event["timestamp"]
    )

    return (
        structured_events,
        lines_processed,
        records_parsed,
        ignored_lines,
        failed_lines
    )


def main():

    if len(sys.argv) > 1:
        filepath = sys.argv[1]
    else:
        filepath = "/var/log/audit/audit.log"

    print(f"[+] Reading: {filepath}")

    (
        events,
        lines_processed,
        records_parsed,
        ignored_lines,
        failed_lines
    ) = parse_file(filepath)

    output_file = "parsed_events.json"

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            events,
            file,
            indent=2
        )

    print(
        f"[+] Lines processed: {lines_processed}"
    )

    print(
        f"[+] Audit records parsed: {records_parsed}"
    )

    print(
        f"[+] Ausearch formatting lines ignored: {ignored_lines}"
    )

    print(
        f"[+] Malformed/failed lines: {failed_lines}"
    )

    print(
        f"[+] Events created: {len(events)}"
    )

    print(
        f"[+] Output written to: {output_file}"
    )


if __name__ == "__main__":
    main()
