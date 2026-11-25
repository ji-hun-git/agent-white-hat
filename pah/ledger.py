"""The protection log: every change to what the guard allows, in order, each entry chained to the one before.

Shirudo (OpenAI and Cisco, 2026) keeps a hardware-backed record of every protection loaded or removed, so nobody can
quietly switch one off and pretend it was never there. pah has no TPM to lean on, so it does the part a file can do:
`protection-log.jsonl` in the guard's folder holds one entry per change (a shield added, enforced or removed, a project
trusted, a configuration baseline accepted, hooks installed, a file restored from quarantine), each carrying the
SHA-256 of the entry before it, and `protection-log.head` holds the newest hash.

`pah log verify` recomputes the chain. An edited entry, a deleted or reordered one, a cut-off tail and a deleted log
all show. What a chain alone cannot show is someone with your file permissions rewriting the whole history and its
head consistently; for that, note the head somewhere else (`pah log` prints it) and check against it later with
`pah log verify --anchor HASH`: an anchor noted earlier must still be in the chain.

The agent cannot write here: the guard denies edits to its own folder and asks before commands that touch it.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁠-⁤﻿]")
_DETAIL_LIMIT = 500


def _home() -> Path:
    from . import guard  # read at call time: tests and PAH_HOME move it

    return guard.HOME


def path() -> Path:
    return _home() / "protection-log.jsonl"


def head_path() -> Path:
    return _home() / "protection-log.head"


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def clean(value, limit: int = _DETAIL_LIMIT):
    """What goes into the log: no control or invisible characters, no unbounded strings."""
    if isinstance(value, str):
        text = _CONTROL.sub("", value)
        return text if len(text) <= limit else text[: limit - 1] + "…"
    if isinstance(value, dict):
        return {str(k)[:64]: clean(v, limit) for k, v in list(value.items())[:50]}
    if isinstance(value, (list, tuple)):
        return [clean(v, limit) for v in list(value)[:50]]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return clean(str(value), limit)


def _digest(entry: dict) -> str:
    body = {k: entry[k] for k in ("n", "t", "action", "detail", "prev") if k in entry}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                          .encode("utf-8")).hexdigest()


class _Lock:
    """One writer at a time: two agents' hooks or two terminals must not fork the chain."""

    def __init__(self, target: Path, wait: float = 5.0, stale: float = 30.0):
        self.file = target.with_suffix(".lock")
        self.wait, self.stale = wait, stale

    def __enter__(self):
        deadline = time.monotonic() + self.wait
        while True:
            try:
                fd = os.open(self.file, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.close(fd)
                return self
            except FileExistsError:
                try:
                    if time.time() - self.file.stat().st_mtime > self.stale:
                        self.file.unlink()
                        continue
                except OSError:
                    pass
                if time.monotonic() > deadline:
                    raise RuntimeError(f"the protection log is locked ({self.file}); try again")
                time.sleep(0.05)

    def __exit__(self, *exc):
        try:
            self.file.unlink()
        except OSError:
            pass


def _read_lines() -> list[str]:
    try:
        return [line for line in path().read_text(encoding="utf-8").splitlines() if line.strip()]
    except FileNotFoundError:
        return []


def _last() -> dict | None:
    lines = _read_lines()
    if not lines:
        return None
    try:
        return json.loads(lines[-1])
    except ValueError:
        return None


def record(action: str, /, **detail) -> dict:
    """Append one change to the log and move the head. Returns the entry written."""
    home = _home()
    home.mkdir(parents=True, exist_ok=True)
    with _Lock(path()):
        last = _last()
        if last is None and _read_lines():
            raise RuntimeError(f"the protection log's last line is unreadable; run `pah log verify` ({path()})")
        entry = {"n": (last or {}).get("n", 0) + 1, "t": now(), "action": clean(action, 64), "detail": clean(detail),
                 "prev": (last or {}).get("hash", GENESIS)}
        entry["hash"] = _digest(entry)
        with path().open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        tmp = head_path().with_suffix(".tmp")
        tmp.write_text(f"{entry['n']} {entry['hash']}\n", encoding="utf-8")
        os.replace(tmp, head_path())
    return entry


def entries() -> list[dict]:
    """The entries that parse, in file order (verify says whether they hold together)."""
    out = []
    for line in _read_lines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def _head() -> tuple[int, str] | None:
    try:
        n, h = head_path().read_text(encoding="utf-8").split()
        return int(n), h
    except (OSError, ValueError):
        return None


def verify(anchor: str | None = None) -> dict:
    """Recompute the chain. ok is False when an entry was edited, removed, reordered or cut off, or when an anchor
    noted earlier is no longer in it."""
    problems: list[str] = []
    prev, expected_n, hashes = GENESIS, 1, []
    lines = _read_lines()
    for i, line in enumerate(lines, 1):
        try:
            entry = json.loads(line)
            if not isinstance(entry, dict):
                raise ValueError
        except ValueError:
            problems.append(f"line {i} is not a log entry")
            continue
        n = entry.get("n")
        if n != expected_n:
            problems.append(f"entry {expected_n} is missing or out of order (found entry {n} on line {i})")
        if entry.get("prev") != prev:
            problems.append(f"entry {n} does not follow the entry before it: something before it was changed or removed")
        if entry.get("hash") != _digest(entry):
            problems.append(f"entry {n} was edited after it was written")
        prev = entry.get("hash", "")
        hashes.append(prev)
        expected_n = (n if isinstance(n, int) else expected_n) + 1
    head = _head()
    if head is None:
        if lines:
            problems.append(f"the head file is missing ({head_path()}), so a cut-off tail would not show")
    else:
        n, h = head
        if not lines:
            problems.append(f"the log is empty or deleted, but its head says it had {n} entries")
        elif h != prev:
            problems.append(f"the newest entry is not the head ({n} {h[:16]}…): entries after it were removed, or the "
                            "head was changed")
    if anchor:
        anchor = anchor.strip().lower()
        if len(anchor) < 12 or not any(h.startswith(anchor) for h in hashes):
            problems.append(f"the anchor {anchor[:16]} is not in the chain: the history before it was rewritten")
    return {"ok": not problems, "count": len(lines), "head": prev if lines else "", "problems": problems,
            "path": str(path())}
