"""Command line: pah scan | audit | appsec | diff | sweep | protect | quarantine | check-command | hook | watch | checkup |
incident | install | shield | log | mcp | rules."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .agents import AGENTS as AGENT_CHOICES
from .model import EXIT_CODES

FAIL_ORDER = {"block": 2, "warn": 1, "incomplete": 1, "pass": 0}


def _stdio() -> None:
    """Consoles get Unicode through the console API; pipes and files get UTF-8, whatever the locale's code page."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            if hasattr(stream, "isatty") and not stream.isatty():
                stream.reconfigure(encoding="utf-8", errors="replace")
            else:
                stream.reconfigure(errors="replace")


def cmd_scan(args) -> int:
    from . import report as render
    from .scan import scan

    if args.deep and not Path(args.target).exists():
        raise RuntimeError("--deep reviews files on disk: clone the repository first (`git clone --no-recurse-submodules "
                           "<url>`), then run `pah scan <folder> --deep`")
    rep = scan(args.target, max_seconds=args.max_seconds, online=args.online, av=getattr(args, "av", False))
    if args.deep:
        from .review import review

        rep.review = review(rep, args.target, provider=args.provider, model=args.model)
    if args.format == "json":
        out = render.as_json(rep)
    elif args.format == "sarif":
        out = render.sarif(rep)
    else:
        out = render.text(rep, lang=args.lang, verbose=args.verbose)
        if getattr(args, "audit", False):
            out += "\n\n" + render.next_steps(rep, lang=args.lang)
    if args.output:
        Path(args.output).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)
    prefix = None
    if getattr(args, "github", False):
        from .ci import github, workspace_prefix

        prefix = workspace_prefix(args.target)
        github(rep, prefix=prefix)
    if getattr(args, "sarif_out", None):
        Path(args.sarif_out).write_text(render.sarif(rep, base=prefix or "") + "\n", encoding="utf-8")
    verdict = rep.verdict
    if args.fail_on:
        return EXIT_CODES[verdict] if FAIL_ORDER[verdict] >= FAIL_ORDER[args.fail_on] else 0
    return EXIT_CODES[verdict]


def cmd_appsec(args) -> int:
    """The user's own web app: the fourteen holes attackers try first, read from the code."""
    from . import report as render
    from .appsec import check

    rep = check(args.target, max_seconds=args.max_seconds)
    if args.format == "json":
        out = render.as_json(rep)
    elif args.format == "sarif":
        out = render.sarif(rep)
    else:
        out = render.text(rep, lang=args.lang, verbose=args.verbose, subject="app")
        out += "\n\n" + render.APP_NEXT.get(args.lang, render.APP_NEXT["en"])
    if args.output:
        Path(args.output).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)
    prefix = None
    if getattr(args, "github", False):
        from .ci import github, workspace_prefix

        prefix = workspace_prefix(args.target)
        github(rep, prefix=prefix)
    if getattr(args, "sarif_out", None):
        Path(args.sarif_out).write_text(render.sarif(rep, base=prefix or "") + "\n", encoding="utf-8")
    verdict = rep.verdict
    if args.fail_on:
        return EXIT_CODES[verdict] if FAIL_ORDER[verdict] >= FAIL_ORDER[args.fail_on] else 0
    return EXIT_CODES[verdict]


def cmd_diff(args) -> int:
    from . import report as render
    from .diff import diff, summary

    rep = diff(args.old, args.new, source=args.source, max_seconds=args.max_seconds)
    if args.format == "json":
        out = render.as_json(rep)
    elif args.format == "sarif":
        out = render.sarif(rep)
    else:
        out = render.text(rep, lang=args.lang, verbose=args.verbose) + "\n\n" + summary(rep)
    if args.output:
        Path(args.output).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)
    verdict = rep.verdict
    if args.fail_on:
        return EXIT_CODES[verdict] if FAIL_ORDER[verdict] >= FAIL_ORDER[args.fail_on] else 0
    return EXIT_CODES[verdict]


def cmd_check_command(args) -> int:
    from .guard import check_command

    d = check_command(args.command, args.cwd or os.getcwd(), scan_repos=not args.no_scan, record=False)
    if args.json:
        print(json.dumps({"action": d.action, "reason": d.reason, "findings": [f.to_dict() for f in d.findings],
                          "shields": d.shields}, indent=2, ensure_ascii=False))
    else:
        print(f"{d.action.upper()}: {d.reason or 'no objection from agent-white-hat'}")
        for s in d.shields:
            if s["mode"] == "monitor":
                print(f"MONITOR: shield {s['id']} would {s['action']} this once enforced ({s['why']})")
    return {"defer": 0, "ask": 1, "deny": 2}[d.action]


def cmd_hook(args) -> int:
    from .hooks import main as hook_main

    return hook_main(args.event, args.agent)


def cmd_watch(args) -> int:
    from . import watch

    if args.action in ("init", "accept"):
        snap = watch.init()
        n = sum(1 for e in snap["files"].values() if e.get("exists"))
        _log(f"watch-{args.action}", files=n, folders=len(snap["dirs"]))
        print(f"Baseline saved to {watch.BASELINE}: {n} agent and shell configuration files, "
              f"{len(snap['dirs'])} folders, {len(snap.get('run_keys', {}))} Run keys.")
        return 0
    if not watch.BASELINE.exists():
        print("No baseline yet. Run `pah watch init` once your agent setup is the way you want it.")
        return 3
    changes = watch.check()
    if args.json:
        print(json.dumps(changes, indent=2, ensure_ascii=False))
    elif not changes:
        print("No changes to agent or shell configuration since the baseline.")
    else:
        for c in changes:
            print(f"{c['severity'].upper():8} {c['label']}  ({c['path']})\n         {c['change']}")
        print("\nIf you made these changes, run `pah watch accept`. If not, find out what did before using your agents.")
    return 2 if any(c["severity"] in ("high", "critical") for c in changes) else (1 if changes else 0)


def cmd_checkup(args) -> int:
    from . import report as render
    from .checkup import run

    rep = run()
    if args.format == "json":
        print(render.as_json(rep))
    else:
        print(render.text(rep, lang=args.lang, subject="computer"))
        if any(f.rule == "PAH-H001" for f in rep.findings):
            print("\nKeys in plain files: revoke and recreate them in each provider's console, then store the new ones "
                  "in your OS credential store or password manager. Changing a password does not cancel stolen tokens.")
    return EXIT_CODES[rep.verdict]


SWEEP_WORDS = {
    "en": {"title": "agent-white-hat sweep", "items": "items", "places": "places", "cached": "unchanged since the last "
           "sweep", "engine": "Antivirus engine", "none": "none found", "computer": "This computer (pah checkup)",
           "quarantined": "Quarantined", "verdict": "Verdict", "next_block": "Blocked items stay where they are unless you "
           "add --quarantine; `pah quarantine list` shows what was moved and `pah quarantine restore ID` puts it back.",
           "no_engine": "none on this computer, so binaries were not checked against signatures"},
    "ko": {"title": "agent-white-hat 전체 검사", "items": "개 항목", "places": "곳", "cached": "지난 검사 이후 바뀌지 않음",
           "engine": "백신 엔진", "none": "발견 없음", "computer": "이 컴퓨터 (pah checkup)", "quarantined": "격리됨",
           "verdict": "판정", "next_block": "--quarantine을 붙이지 않으면 차단 항목은 그대로 둡니다. 옮긴 항목은 "
           "`pah quarantine list`로 보고 `pah quarantine restore ID`로 되돌립니다.", "no_engine": "이 컴퓨터에 없어서 실행 파일은 시그니처로 검사하지 못했습니다"},
}


def render_sweep(rep: dict, lang: str = "en") -> str:
    w = SWEEP_WORDS.get(lang, SWEEP_WORDS["en"])
    items = rep["items"]
    places = sum(len(v) for v in rep["places"].values())
    out = [f"{w['title']}  ·  {len(items)} {w['items']}, {places} {w['places']}  ·  {rep['seconds']}s", ""]
    for it in items:
        if it["verdict"] == "pass":
            continue
        out.append(f" {it['verdict'].upper():10} {it['kind']:10} {it['path']}")
        for f in it["findings"][:3]:
            where = f"{f['path']}:{f['line']}" if f.get("line") else f["path"]
            out.append(f"            {f['severity']:8} {f['rule']}  {where}  {f['message'][:110]}")
        if it.get("note"):
            out.append(f"            {it['note'][:140]}")
        if it.get("quarantined"):
            out.append(f"            {w['quarantined']}: {', '.join(it['quarantined'])}")
    passed = [it for it in items if it["verdict"] == "pass"]
    cached = sum(1 for it in passed if it.get("cached"))
    out.append(f" {'PASS':10} {len(passed)} {w['items']}" + (f" ({cached} {w['cached']})" if cached else ""))
    engine = rep.get("engine") or {}
    if engine and not engine.get("engines"):
        out += ["", f"{w['engine']}: {w['no_engine']}"]
    elif engine:
        hits = engine.get("detections") or []
        out += ["", f"{w['engine']} ({', '.join(engine['engines'])}): " + (w["none"] if not hits else "")]
        out += [f"   {h['severity']:8} {h['path']}  {h['message'][:110]}" for h in hits[:20]]
    host = rep.get("computer")
    if host:
        out += ["", f"{w['computer']}: {host['verdict'].upper()}"]
        out += [f"   {f['severity']:8} {f['rule']}  {f['message'][:120]}" for f in host["findings"][:10]]
    out += ["", f"{w['verdict']}: {rep['verdict'].upper()}"]
    if rep["verdict"] == "block":
        out.append(w["next_block"])
    return "\n".join(out)


def cmd_sweep(args) -> int:
    from . import protect

    def progress(i, n, item):
        if item.verdict in ("block", "warn"):
            print(f"[{i}/{n}] {item.verdict.upper():5} {item.path}", file=sys.stderr, flush=True)

    rep = protect.sweep(tuple(args.only) if args.only else None, engine=not args.no_engine, checkup=not args.no_checkup,
                        fresh=args.fresh, quarantine=args.quarantine, max_seconds=args.max_seconds,
                        progress=None if args.format == "json" else progress)
    print(json.dumps(rep, indent=2, ensure_ascii=False) if args.format == "json" else render_sweep(rep, args.lang))
    return {"block": 2, "warn": 1, "incomplete": 3, "pass": 0}[rep["verdict"]]


def cmd_protect(args) -> int:
    from . import protect

    if args.install or args.uninstall:
        from .install import _base_args

        command = _base_args() + ["protect"] + (["--quarantine"] if args.quarantine else [])
        plan = protect.login_plan(command, remove=args.uninstall)
        print("Real-time protection " + ("will stop starting at login:" if args.uninstall else "will start at login:"))
        for step in plan:
            print("  " + (f"write {step['write']}" if "write" in step else f"delete {step['delete']}" if "delete" in step
                          else "run " + subprocess_line(step["run"])))
        if not args.yes:
            print("Nothing changed. Run the same command with --yes to apply it.")
            return 0
        for line in protect.apply_plan(plan):
            print("  " + line)
        _log("protect-login-remove" if args.uninstall else "protect-login-add", quarantine=bool(args.quarantine))
        return 0
    try:
        protect.protect(args.interval, do_quarantine=args.quarantine)
    except KeyboardInterrupt:
        print("Real-time protection stopped.")
    return 0


def subprocess_line(argv: list[str]) -> str:
    import subprocess

    return subprocess.list2cmdline(argv)


def cmd_quarantine(args) -> int:
    from . import protect

    if args.action == "list":
        entries = protect.quarantined()
        if not entries:
            print("Quarantine is empty.")
        for m in entries:
            print(f"{m['id']}  {m['when']}  {m['kind']:6} {m['original']}\n              {m['reason'][:140]}")
        return 0
    if not args.target:
        print(f"pah quarantine {args.action} needs {'a path' if args.action == 'add' else 'an ID from `pah quarantine list`'}.")
        return 3
    try:
        if args.action == "add":
            m = protect.quarantine(args.target, "moved by hand")
            print(f"Quarantined {m['original']} as {m['id']}.")
            _log("quarantine-add", id=m["id"], path=m["original"])
        elif args.action == "restore":
            m = protect.restore(args.target)
            print(f"Restored {m['original']}.")
            _log("quarantine-restore", id=m["id"], path=m["original"])
        else:
            if not args.yes:
                print("Deleting cannot be undone. Run the same command with --yes to delete it.")
                return 0
            m = protect.delete(args.target)
            print(f"Deleted {m['original']} from quarantine for good.")
            _log("quarantine-delete", id=m["id"], path=m["original"])
    except (OSError, ValueError, KeyError) as e:
        print(f"Could not {args.action}: {e}")
        return 3
    return 0


def cmd_trust(args) -> int:
    from .guard import is_trusted, set_trust, trusted_projects

    if args.list:
        for p in sorted(trusted_projects()):
            print(p)
        return 0
    path = Path(args.path or ".")
    if not path.is_dir():
        print(f"pah: not a folder: {path}", file=sys.stderr)
        return 64
    if args.remove:
        print(f"No longer trusted: {set_trust(path, False)}")
        _log("trust-remove", path=str(path.resolve()))
        return 0
    if is_trusted(path):
        print(f"Already trusted: {path.resolve()}")
        return 0
    print(f"Trusted: {set_trust(path, True)}\nThe guard still judges commands here but no longer scans this project before "
          "setup. Trust only projects you wrote or have reviewed; undo with `pah trust --remove`.")
    _log("trust-add", path=str(path.resolve()))
    return 0


def cmd_install(args) -> int:
    from .install import AGENT_NAMES, apply, build, detected

    names = ["claude-code" if a == "claude" else a for a in args.agents]
    if args.all:
        names = list(AGENT_NAMES)
    elif args.detected or not names:
        names = detected()
        print("Agents found on this computer: " + (", ".join(names) or "none"))
    unknown = [a for a in names if a not in AGENT_NAMES]
    if unknown:
        print(f"Unknown agent(s): {', '.join(unknown)}. Choose from: {', '.join(AGENT_NAMES)}", file=sys.stderr)
        return 64
    plans = build(names, skills=args.skills, mcp=args.mcp, hooks=not args.no_hooks)
    changed = [str(c.path) for plan in plans for c in plan.changes]
    code = apply(plans, write=args.yes)
    if args.yes and changed and code == 0:
        _log("install", agents=names, skills=bool(args.skills), mcp=bool(args.mcp), hooks=not args.no_hooks,
             files=changed)
    return code


def cmd_mcp(args) -> int:
    from .mcp_server import serve

    return serve()


def cmd_rules(args) -> int:
    from . import appsec, av, behavior, checkup, diff, guard, intel, models, outputs, packages, review, scan, surfaces, watch  # noqa: F401  (registers every rule)
    from .model import RULES
    from .report import rules_markdown

    if args.markdown:
        print(rules_markdown())
    else:
        for rid in sorted(RULES):
            print(f"{rid}  {RULES[rid].title}")
    return 0


def cmd_session(args) -> int:
    """What agents did, step by step, as the hooks recorded it: the chain behind each alert."""
    import time

    from . import behavior, outputs  # noqa: F401  (rule titles)
    from . import session as sessions
    from .model import RULES

    if args.action == "clear":
        n = sessions.clear(args.id)
        print(f"Removed {n} session record(s).")
        return 0
    if args.action == "list":
        rows = sessions.sessions(args.limit)
        if args.json:
            print(json.dumps(rows, indent=1, ensure_ascii=False))
            return 0
        if not rows:
            print("No sessions recorded yet. The hooks record each agent step once agent-white-hat is installed.")
            return 0
        for r in rows:
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(r["last"]))
            alerts = ", ".join(sorted(set(r["alerts"]))) or "-"
            print(f"{r['id'][:12]}  {when}  {r['agent']:<11} {r['steps']:>4} steps  {r['denied']:>3} denied  alerts: {alerts}"
                  f"\n              {r['cwd']}")
        print("\npah session show <id> (or latest) for the steps.")
        return 0
    events = sessions.events_of(args.id or "latest")
    if args.json:
        print(json.dumps(events, indent=1, ensure_ascii=False))
        return 0
    if not events:
        print("No such session; pah session list shows them.")
        return 64
    first = events[0]
    print(f"Session of {first.get('agent', '?')} in {first.get('cwd', '?')}, {len(events)} steps\n")
    for i, e in enumerate(events, 1):
        when = time.strftime("%H:%M:%S", time.localtime(e.get("t", 0)))
        mark = {"deny": "DENIED", "ask": "ASKED"}.get(e.get("action", ""), "")
        print(f"{i:>4}  {when}  {e.get('tool', '')[:22]:<22} {e.get('text', '')[:90]}  {mark}")
        tags = e.get("tags") or {}
        if tags:
            print("      " + "; ".join(f"{k}: {', '.join(v)[:80]}" for k, v in tags.items()))
        for rid in e.get("alerts", []):
            print(f"      ! {rid} {RULES[rid].title if rid in RULES else ''}")
    return 0


def _incidents_for(arg: str | None):
    from . import incidents

    if not arg:
        return list(incidents.catalog())
    one = incidents.get(arg)
    return [one] if one else incidents.search(arg)


def cmd_incident(args) -> int:
    from . import av, behavior, checkup, diff, guard, incidents, intel, models, outputs, packages, review, scan, surfaces, watch  # noqa: F401  (rule titles)

    if args.action == "list":
        if args.markdown:
            print(incidents.markdown(), end="")
        elif args.json:
            print(json.dumps([i.to_dict() for i in incidents.catalog()], indent=1, ensure_ascii=False))
        else:
            print(incidents.table())
            print("\npah incident show <id> for what happened and what to do; pah incident check looks for their traces.")
        return 0
    chosen = _incidents_for(args.id)
    if not chosen:
        print(f"pah: no incident matches {args.id!r}; pah incident list shows them all", file=sys.stderr)
        return 64
    if args.action == "show":
        if args.json:
            print(json.dumps([i.to_dict() for i in chosen], indent=1, ensure_ascii=False))
        else:
            print("\n\n".join(incidents.text(i) for i in chosen))
        return 0
    hits = incidents.found(chosen)  # check
    if args.json:
        print(json.dumps([{"incident": i.id, "path": str(p), "what": t.what, "severity": t.severity} for i, t, p in hits],
                         indent=1, ensure_ascii=False))
        return 2 if hits else 0
    if not hits:
        traced = sum(1 for i in chosen if i.traces)
        print(f"No traces of {traced} incident(s) on this computer. This covers only the files they are known to leave; "
              "pah checkup and pah sweep look further.")
        return 0
    for inc in [i for i in chosen if any(h[0] is i for h in hits)]:
        print(incidents.text(inc, located=[(t, p) for i, t, p in hits if i is inc]))
        print()
    return 2


def _log(action: str, **detail) -> None:
    """Record a change to the user's protection in the protection log (pah/ledger.py)."""
    from . import ledger

    try:
        ledger.record(action, **detail)
    except (OSError, RuntimeError) as err:
        print(f"pah: the change was made, but the protection log could not record it: {err}", file=sys.stderr)


def _when(text: str) -> str:
    return str(text).replace("T", " ").replace("Z", " UTC")


def _read_bundle(file: str) -> dict:
    from .shields import ShieldError

    try:
        return json.loads(Path(file).read_text(encoding="utf-8"))
    except ValueError as err:
        raise ShieldError(f"{file} is not JSON ({err})") from None


def _shield_add(args, shields) -> int:
    from datetime import timedelta

    match = {kind: values for kind, values in (("package", args.package), ("command", args.command),
                                                ("host", args.host), ("path", args.path)) if values}
    if not 1 <= args.days <= shields.MAX_DAYS:
        raise shields.ShieldError(f"--days is 1 to {shields.MAX_DAYS}: a shield bridges to a fix, it is not one")
    sid = args.id or f"local-{shields._now():%Y%m%d}-{os.urandom(2).hex()}"
    title = args.title or ", ".join(v for values in match.values() for v in values)[:120]
    s = shields.add({"id": sid, "title": title, "reason": args.reason, "ref": args.ref or "", "match": match,
                     "action": args.effect, "mode": "enforce" if args.enforce else "monitor",
                     "expires": shields.fmt_time(shields._now() + timedelta(days=args.days))})
    if s["mode"] == "monitor":
        print(f"Added shield {s['id']} in monitor mode until {_when(s['expires'])}. It records what it would "
              f"{s['action']} and changes nothing yet: `pah shield report {s['id']}` shows what it caught, and "
              f"`pah shield enforce {s['id']}` makes it {s['action']}.")
    else:
        print(f"Added shield {s['id']}, enforced until {_when(s['expires'])}: the guard will {s['action']} what it "
              f"matches. `pah shield monitor {s['id']}` switches it back to report-only.")
    return 0


def _shield_list(args, shields) -> int:
    from collections import Counter

    shields.note_expired()
    items = shields.load()
    counts = Counter(h.get("shield") for h in shields.hits())
    problems = shields.drift()
    if args.json:
        print(json.dumps({"shields": [dict(s, expired=shields.expired(s), hits=counts.get(s["id"], 0)) for s in items],
                          "problems": problems}, indent=1, ensure_ascii=False))
        return 2 if problems else 0
    if not items:
        print("No shields. `pah shield add` adds one for an incident happening now; `pah shield import` adds a "
              "signed bundle.")
    for s in items:
        state = "expired" if shields.expired(s) else s.get("mode", "?")
        print(f"{s.get('id', '?'):<30} {state:<8} {s.get('action', '?'):<5} until {_when(s.get('expires', ''))}  "
              f"{counts.get(s.get('id'), 0)} matches")
        print(f"    {s.get('title', '')}  [{s.get('source', '')}]")
        for kind, values in (s.get("match") or {}).items():
            print(f"    {kind}: {', '.join(values)[:150]}")
    if problems:
        print("\nThe protection log disagrees with the shields on disk:")
        for line in problems:
            print("  - " + line)
        return 2
    return 0


def _shield_report(args, shields) -> int:
    rows = shields.report(args.id)
    if args.json:
        print(json.dumps(rows, indent=1, ensure_ascii=False))
        return 0
    if not rows:
        print("No such shield." if args.id else "No shields yet.")
        return 64 if args.id else 0
    for r in rows:
        state = "expired" if r["expired"] else r["mode"]
        print(f"{r['id']} ({state}, {r['action']}): {r['hits']} matches; {r['new']} of them the guard alone would "
              f"have let through" + (f"; last {_when(r['last'])}" if r["last"] else ""))
        for e in r["examples"]:
            print(f"    {_when(e['t'])}  {e['kind']:<7} guard alone: {e['before']:<5}  {e['subject'][:110]}")
    print("\nRead each match before enforcing: a legitimate step among them means the shield is too broad.")
    return 0


def _shield_import(args, shields) -> int:
    imported = shields.import_bundle(_read_bundle(args.file), allow_unsigned=args.unsigned, enforce=args.enforce)
    if not imported:
        print("Nothing imported: every shield in the bundle has expired.")
        return 0
    for s in imported:
        print(f"Imported shield {s['id']} ({s['mode']}, {s['action']}) until {_when(s['expires'])}: {s['title']}")
    if not args.enforce:
        print("They record what they would stop and change nothing yet; `pah shield report` shows what they caught "
              "and `pah shield enforce <id>` turns one on.")
    return 0


def _shield_verify(args, shields) -> int:
    bundle = _read_bundle(args.file)
    key = shields.verify_bundle(bundle)
    print(f"Signed by key {key['id']} ({key.get('name', '')}{', built in' if key.get('builtin') else ''}); "
          f"{len(bundle['shields'])} shield(s) from {bundle.get('publisher')}, issued {bundle.get('issued', '?')}.")
    return 0


def _shield_sign(args, shields) -> int:
    signed = shields.sign_bundle(_read_bundle(args.file), shields.read_secret(args.key))
    out = Path(args.output or args.file)
    out.write_text(json.dumps(signed, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Signed {len(signed['shields'])} shield(s) with key {signed['signature']['key']}: {out}")
    return 0


def _shield_keygen(args, shields) -> int:
    info = shields.keygen(args.out)
    print(f"Key {info['id']}\n  secret: {info['secret_file']} (keep it to yourself; it signs your bundles)\n"
          f"  public: {info['public_file']} (give it to people who import your bundles)")
    return 0


def _shield_keys(args, shields) -> int:
    keys = shields.trusted_keys()
    if not keys:
        print("No trusted signing keys. `pah shield trust-key <file.pub> --name <owner>` adds one.")
    for k in keys:
        print(f"{k.get('id')}  {k.get('name', '')}{'  (built in)' if k.get('builtin') else ''}")
    return 0


def _shield_trust_key(args, shields) -> int:
    k = shields.trust_key(args.key, args.name)
    print(f"Trusted key {k['id']} ({k['name']}): bundles it signs can be imported. Undo with "
          f"`pah shield untrust-key {k['id']}`.")
    return 0


def _shield_untrust_key(args, shields) -> int:
    shields.untrust_key(args.id)
    print(f"No longer trusted: {args.id}. Shields already imported stay until you remove them.")
    return 0


def _shield_mode(args, shields) -> int:
    s = shields.set_mode(args.id, "enforce" if args.action == "enforce" else "monitor")
    print(f"Shield {s['id']} is now " + ("enforced: the guard will " + s["action"] + " what it matches."
                                          if s["mode"] == "enforce" else "report-only: it records what it would stop."))
    return 0


def _shield_remove(args, shields) -> int:
    if args.expired:
        gone = shields.remove_expired()
        print(f"Removed {len(gone)} expired shield(s)" + (": " + ", ".join(gone) if gone else "."))
        return 0
    if not args.id:
        print("pah shield remove needs a shield id, or --expired", file=sys.stderr)
        return 64
    shields.remove(args.id)
    print(f"Removed shield {args.id}.")
    return 0


SHIELD_ACTIONS = {"add": _shield_add, "list": _shield_list, "report": _shield_report, "import": _shield_import,
                  "verify": _shield_verify, "sign": _shield_sign, "keygen": _shield_keygen, "keys": _shield_keys,
                  "trust-key": _shield_trust_key, "untrust-key": _shield_untrust_key, "enforce": _shield_mode,
                  "monitor": _shield_mode, "remove": _shield_remove}


def cmd_shield(args) -> int:
    from . import shields

    try:
        return SHIELD_ACTIONS[args.action](args, shields)
    except shields.ShieldError as err:
        print(f"pah: {err}", file=sys.stderr)
        return 2 if args.action == "verify" else 64


def cmd_log(args) -> int:
    from . import ledger, shields

    result = ledger.verify(anchor=args.anchor)
    problems = result["problems"] + shields.drift()
    shown = ledger.entries()[-args.limit:] if args.action == "show" else []
    if args.json:
        print(json.dumps(dict(result, ok=not problems, problems=problems, entries=shown), indent=1, ensure_ascii=False))
        return 2 if problems else 0
    for e in shown:
        detail = ", ".join(f"{k}={v}" for k, v in (e.get("detail") or {}).items() if k not in ("sha", "public"))
        print(f"{e.get('n', '?'):>5}  {_when(e.get('t', ''))}  {str(e.get('action', '')):<20} {detail[:120]}")
    if shown:
        print()
    if not problems:
        print(f"Protection log OK: {result['count']} entries, head {result['head'] or '(empty)'}")
        if args.action == "show" and result["head"]:
            print("Note the head somewhere off this computer; `pah log verify --anchor <head>` later shows whether the "
                  "history before it was rewritten.")
        return 0
    print("The protection log does not hold together:")
    for line in problems:
        print("  - " + line)
    print("Something other than pah changed the guard's state. Treat the shields, trusted projects and configuration "
          "baseline as suspect: review them (pah shield list, pah trust --list, pah watch check) and run pah checkup.")
    return 2


def _ci_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--sarif-out", metavar="FILE", help="also write a SARIF report to FILE (for GitHub code scanning), "
                   "whatever --format prints")
    p.add_argument("--github", action="store_true", help="GitHub Actions: annotate findings on their lines, set the "
                   "verdict as a step output and write a job summary")


def main(argv: list[str] | None = None) -> int:
    _stdio()
    parser = argparse.ArgumentParser(prog="pah", description="A local shield for people who let AI agents open, install and "
                                     "run code. Nothing is executed and nothing leaves your machine unless you ask.")
    parser.add_argument("--version", action="version", version=f"agent-white-hat {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scan", help="scan a repository, skill, MCP server, package, archive or git URL before using it")
    p.add_argument("target")
    p.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    p.add_argument("--json", dest="format", action="store_const", const="json")
    p.add_argument("--sarif", dest="format", action="store_const", const="sarif")
    p.add_argument("-o", "--output", help="write the report to a file")
    p.add_argument("--fail-on", choices=("block", "warn", "incomplete"), help="exit non-zero only at or above this verdict")
    p.add_argument("--max-seconds", type=float, default=None)
    p.add_argument("--online", action="store_true", help="also check that packages exist, are not brand new and are not "
                   "listed as malicious (sends package names only, to registry.npmjs.org, pypi.org and api.osv.dev)")
    p.add_argument("--deep", action="store_true", help="add a model review of the evidence (needs a provider key)")
    p.add_argument("--provider", choices=("anthropic", "openai", "meta", "ollama"), default=None)
    p.add_argument("--model", default=None)
    p.add_argument("--lang", choices=("en", "ko"), default=os.environ.get("PAH_LANG", "en"))
    p.add_argument("-v", "--verbose", action="store_true", help="also show info-level findings")
    p.add_argument("--av", action="store_true", help="also scan with the antivirus engine on this computer "
                   "(Microsoft Defender or ClamAV; local only)")
    _ci_options(p)
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("audit", help="everything for one target: the scan, the local antivirus engine, and (with "
                       "--online) malicious-package and known-vulnerability checks; ends with next steps")
    p.add_argument("target")
    p.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    p.add_argument("--json", dest="format", action="store_const", const="json")
    p.add_argument("-o", "--output", help="write the report to a file")
    p.add_argument("--fail-on", choices=("block", "warn", "incomplete"))
    p.add_argument("--max-seconds", type=float, default=None)
    p.add_argument("--online", action="store_true", help="send package names and versions to the public registries "
                   "and OSV (malicious packages, brand-new packages, known vulnerabilities)")
    p.add_argument("--no-av", dest="av", action="store_false", help="skip the antivirus engine")
    p.add_argument("--deep", action="store_true", help="add a model review of the evidence (needs a provider key)")
    p.add_argument("--provider", choices=("anthropic", "openai", "meta", "ollama"), default=None)
    p.add_argument("--model", default=None)
    p.add_argument("--lang", choices=("en", "ko"), default=os.environ.get("PAH_LANG", "en"))
    p.add_argument("-v", "--verbose", action="store_true")
    _ci_options(p)
    p.set_defaults(func=cmd_scan, av=True, audit=True)

    p = sub.add_parser("diff", help="what a new version of a package, repository, extension or skill does that the old "
                       "one did not; with --source, what a published package has that its source does not")
    p.add_argument("old", help="folder or archive: the version you have, or with --source the source checkout")
    p.add_argument("new", help="folder or archive: the update, or with --source the published package")
    p.add_argument("--source", action="store_true", help="OLD is the source at the release's tag and NEW the package "
                   "built from it: code that runs on its own and is only in the package blocks")
    p.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    p.add_argument("--json", dest="format", action="store_const", const="json")
    p.add_argument("-o", "--output", help="write the report to a file")
    p.add_argument("--fail-on", choices=("block", "warn", "incomplete"))
    p.add_argument("--max-seconds", type=float, default=None)
    p.add_argument("--lang", choices=("en", "ko"), default=os.environ.get("PAH_LANG", "en"))
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("check-command", help="judge a shell command an agent (or you) is about to run")
    p.add_argument("command")
    p.add_argument("--cwd")
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-scan", action="store_true", help="do not scan the project the command would set up")
    p.set_defaults(func=cmd_check_command)

    p = sub.add_parser("hook", help="agent hook entry point (reads the agent's JSON on stdin)")
    p.add_argument("event", choices=("pre", "post", "session-start"))
    p.add_argument("--agent", default="claude", choices=AGENT_CHOICES,
                   help="which agent's hook protocol to speak (default: claude)")
    p.set_defaults(func=cmd_hook)

    p = sub.add_parser("watch", help="baseline and diff of AI-agent and shell configuration")
    p.add_argument("action", choices=("init", "check", "accept"))
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("checkup", help="check this computer for exposed keys, risky agent settings and known traces")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument("--json", dest="format", action="store_const", const="json")
    p.add_argument("--lang", choices=("en", "ko"), default=os.environ.get("PAH_LANG", "en"))
    p.set_defaults(func=cmd_checkup)

    p = sub.add_parser("sweep", help="full scan of this computer: downloads, code folders, agent skills and plugins, "
                       "editor extensions, the checkup and the built-in antivirus engine")
    p.add_argument("--only", nargs="*", choices=("downloads", "code", "agent", "extensions"), help="scan only these places")
    p.add_argument("--quarantine", action="store_true", help="move blocked items into quarantine (restorable)")
    p.add_argument("--fresh", action="store_true", help="ignore the results remembered from the last sweep")
    p.add_argument("--no-engine", action="store_true", help="skip the antivirus engine (Microsoft Defender or ClamAV)")
    p.add_argument("--no-checkup", action="store_true", help="skip the checks of this computer's settings and traces")
    p.add_argument("--max-seconds", type=float, default=60.0, help="time limit per item")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument("--json", dest="format", action="store_const", const="json")
    p.add_argument("--lang", choices=("en", "ko"), default=os.environ.get("PAH_LANG", "en"))
    p.set_defaults(func=cmd_sweep)

    p = sub.add_parser("protect", help="real-time protection: scan new downloads, clones, extensions, skills and startup "
                       "items as they arrive")
    p.add_argument("--interval", type=float, default=5.0, help="seconds between checks")
    p.add_argument("--quarantine", action="store_true", help="move blocked items into quarantine (restorable)")
    p.add_argument("--install", action="store_true", help="start real-time protection at login (shows the change first)")
    p.add_argument("--uninstall", action="store_true", help="stop starting it at login")
    p.add_argument("--yes", action="store_true", help="apply --install or --uninstall")
    p.set_defaults(func=cmd_protect)

    p = sub.add_parser("quarantine", help="list, restore, delete or add quarantined files and folders")
    p.add_argument("action", choices=("list", "restore", "delete", "add"))
    p.add_argument("target", nargs="?", help="an ID from `pah quarantine list`, or a path for `add`")
    p.add_argument("--yes", action="store_true", help="confirm delete")
    p.set_defaults(func=cmd_quarantine)

    p = sub.add_parser("trust", help="mark a project you wrote or reviewed as trusted, so the guard stops scanning it "
                       "before setup")
    p.add_argument("path", nargs="?")
    p.add_argument("--remove", action="store_true")
    p.add_argument("--list", action="store_true")
    p.set_defaults(func=cmd_trust)

    p = sub.add_parser("install", help="add the guard to AI agents: hooks, skills, MCP server (shows changes first)")
    p.add_argument("agents", nargs="*", help="claude-code codex gemini antigravity cursor copilot devin kiro cline "
                   "(default: the agents found on this computer)")
    p.add_argument("--all", action="store_true", help="every supported agent")
    p.add_argument("--detected", action="store_true", help="the agents whose settings folders exist")
    p.add_argument("--skills", action="store_true", help="also copy the security skills to ~/.agents/skills and "
                   "~/.claude/skills")
    p.add_argument("--mcp", action="store_true", help="also register the MCP server where the agent has a config file")
    p.add_argument("--no-hooks", action="store_true", help="skip the hooks (for example with --skills only)")
    p.add_argument("--yes", action="store_true", help="write the changes (default: only show them)")
    p.set_defaults(func=cmd_install)

    p = sub.add_parser("incident", help="real incidents: what happened, the traces they leave and what to do, in order")
    p.add_argument("action", nargs="?", choices=("list", "show", "check"), default="list")
    p.add_argument("id", nargs="?", help="incident id or words to search for (check: all incidents when omitted)")
    p.add_argument("--json", action="store_true")
    p.add_argument("--markdown", action="store_true", help="list: write docs/incidents.md")
    p.set_defaults(func=cmd_incident)

    p = sub.add_parser("session", help="what agents did, step by step, and the chains the guard stopped")
    p.add_argument("action", nargs="?", choices=("list", "show", "clear"), default="list")
    p.add_argument("id", nargs="?", help="session id from `pah session list`, or latest (show); omit to clear all")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_session)

    p = sub.add_parser("shield", help="narrow, expiring guard rules for an incident happening now: report-only first, "
                       "then enforced; signed bundles")
    ss = p.add_subparsers(dest="action", required=True)
    q = ss.add_parser("add", help="add a shield (report-only unless --enforce)")
    q.add_argument("--package", action="append", help="npm:name@version or pypi:name@version (no version: any)")
    q.add_argument("--command", action="append", help="regular expression for commands the agent runs")
    q.add_argument("--host", action="append", help="host name a command or fetch reaches; its subdomains match too")
    q.add_argument("--path", action="append", help="glob for files the agent writes or reads (*/.vscode/tasks.json)")
    q.add_argument("--reason", required=True, help="why: shown to the agent and to you")
    q.add_argument("--title")
    q.add_argument("--ref", help="https:// link to the advisory")
    q.add_argument("--id")
    q.add_argument("--action", dest="effect", choices=("deny", "ask"), default="deny")
    q.add_argument("--days", type=int, default=14, help="how long it lasts (at most 90)")
    q.add_argument("--enforce", action="store_true", help="act at once instead of recording first")
    q = ss.add_parser("list", help="the shields, their mode, expiry and matches")
    q.add_argument("--json", action="store_true")
    q = ss.add_parser("report", help="what each shield caught, and how much of it the guard alone would have allowed")
    q.add_argument("id", nargs="?")
    q.add_argument("--json", action="store_true")
    for name, text in (("enforce", "make a shield act"), ("monitor", "make a shield report-only again")):
        q = ss.add_parser(name, help=text)
        q.add_argument("id")
    q = ss.add_parser("remove", help="remove a shield, or every expired one")
    q.add_argument("id", nargs="?")
    q.add_argument("--expired", action="store_true")
    q = ss.add_parser("import", help="add a signed bundle of shields (report-only unless --enforce)")
    q.add_argument("file")
    q.add_argument("--unsigned", action="store_true", help="accept a bundle without a signature (only one you wrote)")
    q.add_argument("--enforce", action="store_true")
    q = ss.add_parser("verify", help="check a bundle's signature against the keys you trust")
    q.add_argument("file")
    q = ss.add_parser("sign", help="sign a bundle with your secret key (publishers)")
    q.add_argument("file")
    q.add_argument("--key", required=True, help="secret key file from `pah shield keygen`")
    q.add_argument("-o", "--output", help="write the signed bundle here (default: in place)")
    q = ss.add_parser("keygen", help="make a signing key pair: OUT and OUT.pub (publishers)")
    q.add_argument("out")
    ss.add_parser("keys", help="the signing keys whose bundles you accept")
    q = ss.add_parser("trust-key", help="accept bundles signed by this public key")
    q.add_argument("key", help="a .pub file or 64 hex digits")
    q.add_argument("--name", required=True, help="whose key it is")
    q = ss.add_parser("untrust-key", help="stop accepting bundles signed by this key")
    q.add_argument("id")
    p.set_defaults(func=cmd_shield)

    p = sub.add_parser("log", help="the protection log: every change to what the guard allows, hash-chained")
    p.add_argument("action", nargs="?", choices=("show", "verify"), default="show")
    p.add_argument("--anchor", help="a head noted earlier: it must still be in the chain")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_log)

    p = sub.add_parser("mcp", help="run as an MCP server over stdio (scan, check_app, check_command, checkup, watch_check, incident)")
    p.set_defaults(func=cmd_mcp)

    p = sub.add_parser("appsec", help="check your own web app for the 14 holes attackers try first: script in a "
                       "username, another user's ID, open /admin, keys in the browser, prompt injection, admin at "
                       "signup, client-set prices, fake payments, races, -1 items, guessable codes, open databases, "
                       ".env in git, unchecked uploads")
    p.add_argument("target", nargs="?", default=".", help="the app's folder (default: this folder)")
    p.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    p.add_argument("--json", dest="format", action="store_const", const="json")
    p.add_argument("--sarif", dest="format", action="store_const", const="sarif")
    p.add_argument("-o", "--output", help="write the report to a file")
    p.add_argument("--fail-on", choices=("block", "warn", "incomplete"), help="exit non-zero only at or above this verdict")
    p.add_argument("--max-seconds", type=float, default=None)
    p.add_argument("--lang", choices=("en", "ko"), default=os.environ.get("PAH_LANG", "en"))
    p.add_argument("-v", "--verbose", action="store_true", help="also show info-level findings")
    _ci_options(p)
    p.set_defaults(func=cmd_appsec)

    p = sub.add_parser("rules", help="list every rule")
    p.add_argument("--markdown", action="store_true")
    p.set_defaults(func=cmd_rules)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as err:
        print(f"pah: not found: {err}", file=sys.stderr)
        return 64
    except RuntimeError as err:
        print(f"pah: {err}", file=sys.stderr)
        return 65
