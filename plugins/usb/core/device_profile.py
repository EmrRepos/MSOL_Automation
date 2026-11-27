"""
Device profile loading and matching.

A device profile is a JSON file that describes how to talk to a specific
device: the serial port settings plus an ordered list of command/response
exchanges. This keeps device-specific protocol knowledge out of the test
plugins so the same plugin works for any device.

Profiles live in the `device_profiles/` directory. A profile matches a device
by VID/PID (wildcards allowed); a profile marked `"default": true` is used
when nothing else matches.
"""

import json
import os

PROFILE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "device_profiles"
)

DEFAULT_SERIAL = {
    "baudrate": 115200,
    "timeout": 2,
    "read_size": 256,
    "settle": 0.2
}

DEFAULT_COMMAND = {
    "name": "Unnamed Command",
    "payload": "",
    "expect": None,
    "append_crc": False,
    "append_newline": False,
    "verify_crc": False,
    "required": True
}


def _normalise_id(value):
    """Normalise a VID/PID to bare uppercase hex for comparison."""
    if value is None:
        return ""
    text = str(value).strip().upper()
    if text.startswith("0X"):
        text = text[2:]
    return text.lstrip("0") or "0"


def _matches(pattern, value):
    if pattern is None or pattern == "*":
        return True
    return _normalise_id(pattern) == _normalise_id(value)


def load_profiles(directory=None, logger=None):
    """Load every valid profile from the profile directory."""
    directory = directory or PROFILE_DIR
    profiles = []

    if not os.path.isdir(directory):
        return profiles

    for filename in sorted(os.listdir(directory)):
        if not filename.lower().endswith(".json"):
            continue
        path = os.path.join(directory, filename)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            data["_source"] = filename
            profiles.append(data)
        except Exception as ex:
            if logger:
                logger(f"[WARN] Invalid device profile {filename}: {ex}")

    return profiles


def find_profile(device, directory=None, logger=None):
    """
    Return the best matching profile for a device, or None.

    Specific VID/PID matches win over wildcard matches, which win over the
    profile flagged as default.
    """
    profiles = load_profiles(directory, logger)
    if not profiles:
        return None

    vid = device.get("vid")
    pid = device.get("pid")

    best = None
    best_score = -1

    for profile in profiles:
        match = profile.get("match") or {}
        vid_pattern = match.get("vid")
        pid_pattern = match.get("pid")

        if profile.get("default") and best_score < 0:
            best = profile
            best_score = 0

        if not match:
            continue

        if not (_matches(vid_pattern, vid) and _matches(pid_pattern, pid)):
            continue

        score = 1
        if vid_pattern not in (None, "*"):
            score += 1
        if pid_pattern not in (None, "*"):
            score += 1

        if score > best_score:
            best = profile
            best_score = score

    return best


def serial_settings(profile):
    """Merge a profile's serial settings over the defaults."""
    settings = dict(DEFAULT_SERIAL)
    if profile:
        settings.update(profile.get("serial") or {})
    return settings


def commands(profile):
    """Return the profile's commands with defaults applied."""
    if not profile:
        return []

    result = []
    for entry in profile.get("commands") or []:
        command = dict(DEFAULT_COMMAND)
        command.update(entry)
        result.append(command)
    return result
