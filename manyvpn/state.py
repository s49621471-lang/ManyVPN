import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

DECAY = 0.7
START = 0.5
KEEP_DAYS = 14


def digest(key):
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]


def empty():
    return {"updated": "", "nodes": {}}


def load(path):
    target = Path(path)
    if not target.exists():
        return empty()
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return empty()
    if not isinstance(data, dict) or not isinstance(data.get("nodes"), dict):
        return empty()
    return data


def reliability(history, key):
    entry = history["nodes"].get(digest(key))
    if not entry:
        return START
    try:
        return float(entry.get("score", START))
    except (TypeError, ValueError):
        return START


def record(history, tested, working):
    now = datetime.now(timezone.utc)
    stamp = now.isoformat(timespec="seconds")
    good = {node.key for node in working}
    for node in tested:
        code = digest(node.key)
        entry = history["nodes"].get(code) or {"score": START, "ok": 0, "fail": 0}
        success = 1.0 if node.key in good else 0.0
        entry["score"] = round(float(entry.get("score", START)) * DECAY + success * (1 - DECAY), 4)
        entry["ok"] = int(entry.get("ok", 0)) + (1 if success else 0)
        entry["fail"] = int(entry.get("fail", 0)) + (0 if success else 1)
        entry["last"] = stamp
        if success:
            entry["seen"] = stamp
        history["nodes"][code] = entry
    cutoff = now - timedelta(days=KEEP_DAYS)
    for code in list(history["nodes"].keys()):
        last = history["nodes"][code].get("last", "")
        try:
            when = datetime.fromisoformat(last)
        except ValueError:
            continue
        if when < cutoff:
            del history["nodes"][code]
    history["updated"] = stamp
    return history


def save(history, path):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(history, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
