"""Shields: narrow guard rules that bridge the days between an attack becoming known and the fix reaching you.

The idea comes from Shirudo (OpenAI and Cisco, 2026), which shields a running Linux service from one exploit path
until a patch ships: the protection is temporary, scoped to the one path, watched before it is enforced, approved by
the operator, signed, and its loading and removal are recorded. pah's guard sits in front of an AI agent's actions
rather than in the kernel, so here a shield is a rule for those actions:

  match      package versions an agent would install (npm:@ctrl/tinycolor@4.1.1, pypi:name@1.2.3), command patterns,
             hosts (and their subdomains) a command or fetch reaches, and paths a write or read touches
  action     deny or ask; a shield can only make the guard stricter, never allow anything
  mode       monitor (report-only: record what it would have stopped, change nothing) or enforce
  expires    always; at most MAX_DAYS ahead. A shield is a bridge to the real fix, not a permanent rule

`pah shield add` starts a shield in monitor mode; `pah shield report` shows what it caught and how much of that the
guard would otherwise have let through; `pah shield enforce` makes it act. Bundles of shields from a publisher are
signed with Ed25519 and refused unless the user trusts the key. Every change goes into the protection log
(pah/ledger.py), and `pah log verify` compares the shields on disk with what the log says they should be.

The guard reads shields.json on each check; nothing here runs a command, and a broken shields file never stops the
rest of the guard from working.
"""
from __future__ import annotations

import base64
import fnmatch
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import ledger

MAX_DAYS = 90
DEFAULT_DAYS = 14
REASON_LIMIT = 400
TITLE_LIMIT = 120
BUNDLE_FORMAT = "pah-shields/1"
MATCH_KINDS = ("package", "command", "host", "path")
ACTIONS = ("deny", "ask")
MODES = ("monitor", "enforce")
SHA_FIELDS = ("id", "title", "reason", "ref", "match", "action", "expires", "source", "created")
BUILTIN_KEYS = Path(__file__).resolve().parent / "data" / "shield-keys.json"
HITS_LIMIT = 1_000_000

ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}")
HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")
EXACT = re.compile(r"v?=*\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?")


class ShieldError(ValueError):
    """A shield, bundle or key that cannot be used, with the reason in words."""


# ------------------------------------------------------------------------------------------- time and storage

def _now() -> datetime:
    return datetime.now(timezone.utc)


def fmt_time(when: datetime) -> str:
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(text: str) -> datetime:
    try:
        text = str(text).strip()
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
            text += "T00:00:00Z"
        when = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise ShieldError(f"not a date and time: {str(text)[:40]!r} (use 2026-12-01T00:00:00Z)") from None
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


def _home() -> Path:
    from . import guard

    return guard.HOME


def path() -> Path:
    return _home() / "shields.json"


def hits_path() -> Path:
    return _home() / "shield-hits.jsonl"


def keys_path() -> Path:
    return _home() / "shield-keys.json"


def _write_json(target: Path, data) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, target)


def load() -> list[dict]:
    try:
        data = json.loads(path().read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as err:
        raise ShieldError(f"{path()} is unreadable ({err}); `pah log verify` shows what changed it") from None
    items = data.get("shields") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise ShieldError(f"{path()} has no list of shields")
    return [s for s in items if isinstance(s, dict)]


def _save(items: list[dict]) -> None:
    _write_json(path(), {"shields": items})


def get(shield_id: str) -> dict | None:
    return next((s for s in load() if s.get("id") == shield_id), None)


def expired(shield: dict, now: datetime | None = None) -> bool:
    try:
        return parse_time(shield.get("expires", "")) <= (now or _now())
    except ShieldError:
        return True


def active() -> list[dict]:
    now = _now()
    return [s for s in load() if s.get("mode") in MODES and s.get("action") in ACTIONS and not expired(s, now)]


def sha(shield: dict) -> str:
    body = {k: shield.get(k) for k in SHA_FIELDS}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                          .encode("utf-8")).hexdigest()


# ------------------------------------------------------------------------------------------- validation

def _package_spec(spec: str) -> tuple[str, str, str | None]:
    m = re.fullmatch(r"(npm|pypi):(.+)", str(spec).strip())
    if not m:
        raise ShieldError(f"a package is written npm:name@version or pypi:name@version, not {str(spec)[:60]!r}")
    eco, rest = m.groups()
    if eco == "npm":
        name, version = _npm_token(rest)
    else:
        name, version = _py_token(rest.replace("@", "==", 1) if "@" in rest and "==" not in rest else rest)
    if not name:
        raise ShieldError(f"no package name in {spec!r}")
    if version is not None and not EXACT.fullmatch(version):
        raise ShieldError(f"a shield names one exact version or none, not {version!r} ({spec})")
    return eco, name, version


def _broad_path(pattern: str) -> bool:
    return re.fullmatch(r"[*?/\\\[\]!.~]*", pattern) is not None


def validate(raw: dict, *, source: str, clamp: bool = False) -> dict:
    """A clean shield from user or bundle input, or ShieldError. With clamp, an expiry beyond MAX_DAYS is cut back
    instead of refused (bundles)."""
    if not isinstance(raw, dict):
        raise ShieldError("a shield is an object")
    sid = str(raw.get("id", ""))
    if not ID.fullmatch(sid):
        raise ShieldError(f"shield id {sid[:40]!r}: use 3 to 64 letters, digits, dots, dashes or underscores")
    reason = ledger.clean(str(raw.get("reason") or ""), REASON_LIMIT).strip()
    if not reason:
        raise ShieldError(f"shield {sid}: say why it exists (--reason); the agent and the user see it")
    title = ledger.clean(str(raw.get("title") or ""), TITLE_LIMIT).strip() or sid
    ref = str(raw.get("ref") or "").strip()
    if ref and (not re.fullmatch(r"https://[^\s<>\"']{3,300}", ref)):
        raise ShieldError(f"shield {sid}: the reference must be an https:// link")
    action = raw.get("action", "deny")
    if action not in ACTIONS:
        raise ShieldError(f"shield {sid}: the action is deny or ask (a shield cannot allow anything)")
    mode = raw.get("mode", "monitor")
    if mode not in MODES:
        raise ShieldError(f"shield {sid}: the mode is monitor or enforce")
    match = raw.get("match")
    if not isinstance(match, dict) or not match:
        raise ShieldError(f"shield {sid}: say what it matches (package, command, host or path)")
    clean_match: dict[str, list[str]] = {}
    for kind, values in match.items():
        if kind not in MATCH_KINDS:
            raise ShieldError(f"shield {sid}: unknown match {kind!r}; use {', '.join(MATCH_KINDS)}")
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list) or not values or len(values) > 50:
            raise ShieldError(f"shield {sid}: {kind} takes a list of 1 to 50 entries")
        out = []
        for v in values:
            v = str(v).strip()
            if not v or len(v) > 300:
                raise ShieldError(f"shield {sid}: empty or overlong {kind} entry")
            if kind == "package":
                _package_spec(v)
            elif kind == "command":
                try:
                    rx = re.compile(v, re.I)
                except re.error as err:
                    raise ShieldError(f"shield {sid}: command pattern {v!r} is not a regular expression ({err})") from None
                if rx.search("") is not None:
                    raise ShieldError(f"shield {sid}: command pattern {v!r} matches every command")
            elif kind == "host":
                v = v.lower().rstrip(".")
                if not HOST.fullmatch(v):
                    raise ShieldError(f"shield {sid}: {v!r} is not a host name (subdomains are matched without a *)")
            elif kind == "path" and _broad_path(v):
                raise ShieldError(f"shield {sid}: path pattern {v!r} matches every file")
            out.append(v)
        clean_match[kind] = out
    now = _now()
    expires = parse_time(raw.get("expires") or "")
    if expires <= now:
        raise ShieldError(f"shield {sid}: it has already expired ({fmt_time(expires)})")
    limit = now + timedelta(days=MAX_DAYS)
    if expires > limit + timedelta(minutes=5):
        if not clamp:
            raise ShieldError(f"shield {sid}: a shield lasts at most {MAX_DAYS} days; it bridges to a fix, it is not one")
        expires = limit
    created = raw.get("created")
    try:
        created = fmt_time(parse_time(created)) if created else fmt_time(now)
    except ShieldError:
        created = fmt_time(now)
    return {"id": sid, "title": title, "reason": reason, "ref": ref, "match": clean_match, "action": action,
            "mode": mode, "expires": fmt_time(expires), "created": created,
            "source": ledger.clean(str(source), 160)}


# ------------------------------------------------------------------------------------------- changes (logged)

def add(raw: dict, *, source: str = "local", clamp: bool = False) -> dict:
    shield = validate(raw, source=raw.get("source") or source, clamp=clamp)
    existing = load()
    items = [s for s in existing if s.get("id") != shield["id"]]
    replaced = len(items) != len(existing)
    items.append(shield)
    _save(items)
    ledger.record("shield-add", id=shield["id"], sha=sha(shield), mode=shield["mode"], action=shield["action"],
                  expires=shield["expires"], source=shield["source"], replaced=replaced)
    return shield


def set_mode(shield_id: str, mode: str) -> dict:
    if mode not in MODES:
        raise ShieldError("the mode is monitor or enforce")
    items = load()
    shield = next((s for s in items if s.get("id") == shield_id), None)
    if shield is None:
        raise ShieldError(f"no shield {shield_id!r}; `pah shield list` shows them")
    if expired(shield):
        raise ShieldError(f"shield {shield_id} has expired; add it again if it is still needed")
    shield["mode"] = mode
    _save(items)
    ledger.record("shield-mode", id=shield_id, mode=mode)
    return shield


def remove(shield_id: str) -> dict:
    items = load()
    shield = next((s for s in items if s.get("id") == shield_id), None)
    if shield is None:
        raise ShieldError(f"no shield {shield_id!r}; `pah shield list` shows them")
    _save([s for s in items if s is not shield])
    ledger.record("shield-remove", id=shield_id)
    return shield


def remove_expired() -> list[str]:
    note_expired()
    gone = [s["id"] for s in load() if expired(s)]
    for sid in gone:
        remove(sid)
    return gone


def note_expired() -> list[str]:
    """Record each shield's expiry in the protection log once (shields stop acting on their own; this keeps the
    record complete)."""
    items = load()
    noted = []
    for s in items:
        if expired(s) and not s.get("expired_logged"):
            ledger.record("shield-expired", id=s.get("id"), expires=s.get("expires"))
            s["expired_logged"] = True
            noted.append(s.get("id"))
    if noted:
        _save(items)
    return noted


def drift() -> list[str]:
    """Differences between the shields and keys on disk and what the protection log says they should be."""
    expected: dict[str, dict] = {}
    keys: dict[str, str] = {}
    for e in ledger.entries():
        d, act = e.get("detail") or {}, e.get("action")
        if act == "shield-add":
            expected[d.get("id")] = {"sha": d.get("sha"), "mode": d.get("mode")}
        elif act == "shield-mode" and d.get("id") in expected:
            expected[d["id"]]["mode"] = d.get("mode")
        elif act == "shield-remove":
            expected.pop(d.get("id"), None)
        elif act == "key-trust":
            keys[d.get("id")] = d.get("public")
        elif act == "key-untrust":
            keys.pop(d.get("id"), None)
    problems = []
    try:
        stored = {s.get("id"): s for s in load()}
    except ShieldError as err:
        return [str(err)]
    for sid, s in stored.items():
        want = expected.get(sid)
        if want is None:
            problems.append(f"shield {sid} is in {path().name} but the protection log never added it")
        elif want["sha"] != sha(s):
            problems.append(f"shield {sid} was changed outside pah (its content no longer matches the log)")
        elif want["mode"] != s.get("mode"):
            problems.append(f"shield {sid} is in {s.get('mode')} mode, but the log last set it to {want['mode']}")
    for sid in expected:
        if sid not in stored:
            problems.append(f"shield {sid} was removed without an entry in the protection log")
    user_keys = {k.get("id"): k.get("public") for k in _user_keys()}
    for kid, pub in user_keys.items():
        if keys.get(kid) != pub:
            problems.append(f"signing key {kid} is trusted in {keys_path().name} but the protection log never trusted it")
    for kid in keys:
        if kid not in user_keys:
            problems.append(f"signing key {kid} was untrusted without an entry in the protection log")
    return problems


# ------------------------------------------------------------------------------------------- matching

def _tokens(args: str):
    from .names import _FLAGS_WITH_VALUE

    skip = False
    for tok in args.split():
        tok = tok.strip("\"'`,")
        if skip:
            skip = False
            continue
        if not tok or tok in ("&&", "||"):
            break
        if tok.startswith("-"):
            skip = tok in _FLAGS_WITH_VALUE
            continue
        if re.match(r"(?:https?:|git\+|file:|\.|/|~|[A-Za-z]:\\)", tok) or tok.endswith((".tgz", ".whl", ".txt", ".tar.gz")):
            continue
        yield tok


def _npm_token(tok: str) -> tuple[str, str | None]:
    if tok.startswith("@"):
        body, _, version = tok[1:].partition("@")
        name = "@" + body
    else:
        name, _, version = tok.partition("@")
    if not re.fullmatch(r"@?[A-Za-z0-9][\w.\-]*(?:/[\w.\-]+)?", name):
        return "", None
    return name, (version or None)


def _py_token(tok: str) -> tuple[str, str | None]:
    m = re.match(r"([A-Za-z0-9][\w.\-]*)(?:\[[^\]]*\])?\s*(.*)", tok.split(";")[0].strip())
    if not m:
        return "", None
    name, rest = m.group(1), m.group(2).strip()
    if rest.startswith("==") and not rest.startswith("==="):
        rest = rest[2:].strip()
    elif rest.startswith("==="):
        rest = rest[3:].strip()
    return name, (rest or None)


def installs(text: str) -> list[tuple[str, str, str | None]]:
    """(ecosystem, name, version as written or None) for each package a command installs or runs."""
    from .names import NPM_INSTALL, PY_INSTALL

    out = []
    for m in NPM_INSTALL.finditer(text):
        args = next((g for g in m.groups() if g is not None), "")
        found = [x for x in (_npm_token(t) for t in _tokens(args)) if x[0]]
        out += [("npm", n, v) for n, v in (found[:1] if m.group(2) is not None or m.group(3) is not None else found)]
    for m in PY_INSTALL.finditer(text):
        args = next((g for g in m.groups() if g is not None), "")
        found = [x for x in (_py_token(t) for t in _tokens(args)) if x[0]]
        out += [("pypi", n, v) for n, v in (found[:1] if m.group(3) is not None else found)]
    return out


def manifest_packages(file_path: str, content: str) -> list[tuple[str, str, str | None]]:
    name = Path(file_path.replace("\\", "/")).name.lower()
    out: list[tuple[str, str, str | None]] = []
    if name == "package.json":
        try:
            data = json.loads(content)
        except ValueError:
            return []
        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            deps = data.get(section) if isinstance(data, dict) else None
            if isinstance(deps, dict):
                out += [("npm", str(k), str(v)) for k, v in deps.items()]
    elif re.fullmatch(r"(?:.*[-_.])?requirements(?:[-_.].*)?\.(?:txt|in)", name):
        for line in content.splitlines():
            line = line.split("#", 1)[0].strip()
            if line and not line.startswith("-"):
                pkg, version = _py_token(line)
                if pkg:
                    out.append(("pypi", pkg, version))
    return out


def _same_version(a: str, b: str) -> bool:
    return a.lstrip("v=").strip() == b.lstrip("v=").strip()


def _package_hit(spec: str, found: list[tuple[str, str, str | None]]) -> str | None:
    from .names import normalize

    eco, name, version = _package_spec(spec)
    for f_eco, f_name, f_version in found:
        if f_eco != eco or normalize(f_name, eco) != normalize(name, eco):
            continue
        if version is None:
            return f"{f_name} ({eco})"
        if f_version and EXACT.fullmatch(f_version):
            if _same_version(f_version, version):
                return f"{f_name}@{f_version} ({eco})"
            continue
        return f"{f_name} ({eco}) without an exact version, which may resolve to {version}"
    return None


def _host_rx(host: str) -> re.Pattern:
    return re.compile(r"(?<![\w.-])(?:[a-z0-9-]+\.)*" + re.escape(host) + r"(?!\.?[a-z0-9-])", re.I)


def _path_hit(pattern: str, file_path: str) -> bool:
    norm = str(Path(file_path).expanduser()).replace("\\", "/").lower()
    pat = os.path.expanduser(pattern).replace("\\", "/").lower()
    if "/" not in pat:
        return fnmatch.fnmatchcase(norm.rsplit("/", 1)[-1], pat)
    return fnmatch.fnmatchcase(norm, pat) or fnmatch.fnmatchcase(norm, "*/" + pat.lstrip("/"))


def match(shield: dict, kind: str, *, texts=(), path: str = "", content: str = "", url: str = "") -> str | None:
    """Why this shield applies to the step, or None."""
    m = shield.get("match") or {}
    texts = [t[:20_000] for t in texts if t]
    if kind == "command":
        found = [p for t in texts for p in installs(t)]
        for spec in m.get("package", ()):
            hit = _package_hit(spec, found)
            if hit:
                return f"installs {hit}"
        for pattern in m.get("command", ()):
            if any(re.search(pattern, t, re.I) for t in texts):
                return f"the command matches {pattern!r}"
        for host in m.get("host", ()):
            if any(_host_rx(host).search(t) for t in texts):
                return f"the command reaches {host}"
    elif kind in ("write", "read"):
        for pattern in m.get("path", ()):
            if path and _path_hit(pattern, path):
                return f"{'writes' if kind == 'write' else 'reads'} {path} ({pattern})"
        if kind == "write" and content and m.get("package"):
            found = manifest_packages(path, content[:2_000_000])
            for spec in m.get("package", ()):
                hit = _package_hit(spec, found)
                if hit:
                    return f"the manifest adds {hit}"
    elif kind == "fetch" and url:
        from .hosts import host_of

        target = host_of(url)
        for host in m.get("host", ()):
            if target == host or target.endswith("." + host):
                return f"the fetch reaches {host}"
    return None


def _record_hit(shield: dict, kind: str, subject: str, before: str, why: str) -> None:
    try:
        target = hits_path()
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.stat().st_size > HITS_LIMIT:
            lines = target.read_text(encoding="utf-8").splitlines()[-2000:]
            target.write_text("\n".join(lines) + "\n", encoding="utf-8")
        row = {"t": fmt_time(_now()), "shield": shield.get("id"), "mode": shield.get("mode"),
               "action": shield.get("action"), "kind": kind, "before": before, "why": ledger.clean(why, 240),
               "subject": ledger.clean(subject, 240)}
        with target.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    except OSError:
        pass


def apply(decision, kind: str, *, record: bool = True, texts=(), path: str = "", content: str = "", url: str = "",
          **_ignored):
    """Let active shields judge one step. Enforced shields make the decision stricter; monitor shields only note
    themselves on decision.shields and, when record is set, in the hits log."""
    items = active()
    if not items:
        return decision
    before = decision.action
    subject = (texts[0] if texts else "") or path or url
    for s in items:
        why = match(s, kind, texts=texts, path=path, content=content, url=url)
        if not why:
            continue
        decision.shields.append({"id": s["id"], "mode": s["mode"], "action": s["action"], "why": why,
                                 "title": s.get("title", ""), "expires": s.get("expires", "")})
        if record:
            _record_hit(s, kind, subject, before, why)
        if s["mode"] == "enforce":
            until = s.get("expires", "")[:10]
            ref = f" ({s['ref']})" if s.get("ref") else ""
            decision.stricter(s["action"], f"agent-white-hat shield {s['id']} ({s.get('title', '')}): {why}. "
                                           f"{s.get('reason', '')}{ref} [in force until {until}]")
    return decision


def hits(shield_id: str | None = None) -> list[dict]:
    try:
        lines = hits_path().read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    out = []
    for line in lines:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict) and (shield_id is None or row.get("shield") == shield_id):
            out.append(row)
    return out


def report(shield_id: str | None = None) -> list[dict]:
    """For each shield: how often it matched, and how many of those steps the guard alone would have let through
    (what enforcing it adds)."""
    rows = []
    every = hits(shield_id)
    for s in load():
        if shield_id and s.get("id") != shield_id:
            continue
        mine = [h for h in every if h.get("shield") == s.get("id")]
        rows.append({"id": s.get("id"), "title": s.get("title"), "mode": s.get("mode"), "action": s.get("action"),
                     "expires": s.get("expires"), "expired": expired(s), "hits": len(mine),
                     "new": sum(1 for h in mine if h.get("before") == "defer"),
                     "last": mine[-1]["t"] if mine else "",
                     "examples": [{"t": h.get("t"), "kind": h.get("kind"), "subject": h.get("subject"),
                                   "before": h.get("before")} for h in mine[-5:]]})
    return rows


# ------------------------------------------------------------------------------------------- keys and bundles

def key_id(public: bytes) -> str:
    return hashlib.sha256(bytes(public)).hexdigest()[:16]


def public_hex(secret: bytes) -> str:
    from . import ed25519

    return ed25519.public_key(secret).hex()


def _parse_key_text(text: str, kind: str) -> bytes:
    text = text.strip()
    m = re.fullmatch(rf"(?:pah-ed25519-{kind}\s+)?([0-9a-fA-F]{{64}})(?:\s+.*)?", text, re.S)
    if not m:
        raise ShieldError(f"not an Ed25519 {kind} key (pah-ed25519-{kind} followed by 64 hex digits)")
    return bytes.fromhex(m.group(1))


def read_secret(file: Path | str) -> bytes:
    return _parse_key_text(Path(file).read_text(encoding="utf-8"), "secret")


def read_public(value: str) -> bytes:
    """A public key from a .pub file or as 64 hex digits."""
    candidate = Path(value)
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value) and candidate.exists():
        value = candidate.read_text(encoding="utf-8")
    return _parse_key_text(value, "public")


def keygen(out: Path | str) -> dict:
    """A new signing key pair: OUT (secret, keep it to yourself) and OUT.pub (give it to the people who import your
    bundles)."""
    out = Path(out)
    pub_file = Path(str(out) + ".pub")
    if out.exists() or pub_file.exists():
        raise ShieldError(f"{out} or {pub_file} already exists; pick another name (keys are never overwritten)")
    out.parent.mkdir(parents=True, exist_ok=True)
    secret = os.urandom(32)
    pub = bytes.fromhex(public_hex(secret))
    fd = os.open(out, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(f"pah-ed25519-secret {secret.hex()}\n")
    pub_file.write_text(f"pah-ed25519-public {pub.hex()}\n", encoding="utf-8")
    return {"id": key_id(pub), "public": pub.hex(), "secret_file": str(out), "public_file": str(pub_file)}


def _builtin_keys() -> list[dict]:
    try:
        data = json.loads(BUILTIN_KEYS.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [dict(k, builtin=True) for k in data.get("keys", []) if isinstance(k, dict)]


def _user_keys() -> list[dict]:
    try:
        data = json.loads(keys_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [k for k in data.get("keys", []) if isinstance(k, dict)]


def trusted_keys() -> list[dict]:
    return _builtin_keys() + _user_keys()


def trust_key(public: str, name: str) -> dict:
    from . import ed25519

    pub = read_public(public)
    if ed25519._decompress(pub) is None:
        raise ShieldError("that public key is not a point on the curve")
    name = ledger.clean(str(name), 80).strip()
    if not name:
        raise ShieldError("name the key's owner (--name), so you know whose bundles it signs")
    kid = key_id(pub)
    keys = [k for k in _user_keys() if k.get("id") != kid]
    entry = {"id": kid, "name": name, "public": pub.hex(), "added": fmt_time(_now())}
    keys.append(entry)
    _write_json(keys_path(), {"keys": keys})
    ledger.record("key-trust", id=kid, name=name, public=pub.hex())
    return entry


def untrust_key(kid: str) -> None:
    keys = _user_keys()
    if not any(k.get("id") == kid for k in keys):
        raise ShieldError(f"no key {kid!r} that you trusted; `pah shield keys` lists them (built-in keys stay)")
    _write_json(keys_path(), {"keys": [k for k in keys if k.get("id") != kid]})
    ledger.record("key-untrust", id=kid)


def bundle_bytes(bundle: dict) -> bytes:
    """What a signature covers: the bundle without its signature, as canonical JSON."""
    body = {k: v for k, v in bundle.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _check_format(bundle) -> None:
    if not isinstance(bundle, dict) or bundle.get("format") != BUNDLE_FORMAT:
        raise ShieldError(f"not a shield bundle (its format must be {BUNDLE_FORMAT!r})")
    if not isinstance(bundle.get("shields"), list) or not bundle["shields"]:
        raise ShieldError("the bundle holds no shields")
    if not str(bundle.get("publisher") or "").strip():
        raise ShieldError("the bundle does not say who published it")


def sign_bundle(bundle: dict, secret: bytes) -> dict:
    from . import ed25519

    _check_format(bundle)
    for raw in bundle["shields"]:
        validate(raw, source="bundle", clamp=True)
    body = {k: v for k, v in bundle.items() if k != "signature"}
    pub = bytes.fromhex(public_hex(secret))
    sig = ed25519.sign(secret, bundle_bytes(body))
    return dict(body, signature={"alg": "ed25519", "key": key_id(pub), "sig": base64.b64encode(sig).decode("ascii")})


def verify_bundle(bundle: dict) -> dict:
    """The trusted key that signed the bundle, or ShieldError saying why it cannot be trusted."""
    from . import ed25519

    _check_format(bundle)
    sig = bundle.get("signature")
    if not isinstance(sig, dict):
        raise ShieldError("the bundle is not signed")
    if sig.get("alg") != "ed25519":
        raise ShieldError(f"the bundle is signed with {str(sig.get('alg'))[:20]!r}; only ed25519 is accepted")
    key = next((k for k in trusted_keys() if k.get("id") == sig.get("key")), None)
    if key is None:
        raise ShieldError(f"the bundle is signed by key {str(sig.get('key'))[:16]}, which you have not trusted. If you "
                          "know whose key it is, add it with `pah shield trust-key <file.pub> --name <owner>`")
    try:
        raw_sig = base64.b64decode(str(sig.get("sig", "")), validate=True)
    except ValueError:
        raise ShieldError("the signature is not base64") from None
    if not ed25519.verify(bytes.fromhex(key["public"]), bundle_bytes(bundle), raw_sig):
        raise ShieldError(f"the signature does not match key {key['id']} ({key.get('name')}): the bundle was changed "
                          "after it was signed")
    return key


def import_bundle(bundle: dict, *, allow_unsigned: bool = False, enforce: bool = False) -> list[dict]:
    """Add a bundle's shields, all or none. They start in monitor mode unless the user says enforce; the publisher
    cannot decide that for them."""
    _check_format(bundle)
    publisher = ledger.clean(str(bundle.get("publisher")), 80)
    if "signature" in bundle:
        key = verify_bundle(bundle)
        source, key_ref = f"bundle: {publisher} (key {key['id']})", key["id"]
    elif allow_unsigned:
        source, key_ref = f"unsigned bundle: {publisher}", ""
    else:
        raise ShieldError("the bundle is not signed; import it with --unsigned only if you wrote it or read every shield")
    mode = "enforce" if enforce else "monitor"
    now = _now()
    prepared = []
    for raw in bundle["shields"]:
        if isinstance(raw, dict) and raw.get("expires") and parse_time(raw["expires"]) <= now:
            continue
        prepared.append(validate(dict(raw, mode=mode), source=source, clamp=True))
    if not prepared:
        return []
    ledger.record("shield-import", publisher=publisher, key=key_ref, ids=[s["id"] for s in prepared], mode=mode,
                  bundle=hashlib.sha256(bundle_bytes(bundle)).hexdigest())
    return [add(s, source=source) for s in prepared]
