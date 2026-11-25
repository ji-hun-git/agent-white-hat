#!/usr/bin/env python3
"""A held-out evaluation of `pah appsec`: public apps the rules were never tuned on, pinned before the first run.

    python bench/appsec_eval.py plan --frame FILE   # pin the sample: names and commits only, nothing is scanned
    python bench/appsec_eval.py fetch --cache DIR   # fetch each app at its pinned commit (depth 1, never run)
    python bench/appsec_eval.py run --cache DIR     # pah appsec on each app, once; findings to bench/results
    python bench/appsec_eval.py score RESULTS       # with the labels: precision, recall, per stratum and rule

The protocol, fixed in bench/fixtures/appsec-heldout-round1.json before the first run:

- Three strata, none of them used while the rules were written or tuned (the twelve apps of 2026-11-25 are the
  development set and are listed there as excluded):
  - vulnerable: apps built to be attacked, in the languages appsec reads (JavaScript, TypeScript, Python). The
    vulnerabilities their own documentation lists are written into the fixture before the run, each mapped to one of
    the fourteen classes or marked out of scope, which gives recall.
  - well_built: maintained, widely used open-source apps in the frameworks appsec reads. Every finding is a candidate
    false alarm, and also a chance at a real bug.
  - ai_built: apps generated with Lovable that have a Supabase backend, the population appsec is for. The frame is a
    GitHub code search for the sentence Lovable writes into every README (the 300 results are saved in the fixture);
    candidates are taken in an order seeded by SEED, each kept if it is not a fork, can still be read and has a
    supabase/ folder, until 15 are kept.
- Each app is pinned at its default branch's commit when the sample was drawn, fetched at that commit with depth 1
  and no submodules, and never installed, built or run.
- One run, with the code of the commit that pre-registered the sample (its code hash is recorded). It is reported
  whatever it shows. Rules changed afterwards are measured on a fresh draw, and these apps join the development set.
- Every finding at medium or above is labeled by reviewers that did not write the rules, reading the code in the
  fetched app: true (an attacker can do what the finding says, and nothing elsewhere in the repository stops it),
  false, or uncertain, each with a reason. In vulnerable apps the reviewers also note which documented
  vulnerability a true finding points at.
- Precision is true / (true + false), per stratum, severity and rule, with Wilson 95% intervals; uncertain findings
  are counted apart and shown as bounds (all true, all false). Recall is the share of documented in-scope
  vulnerabilities with at least one true finding on them. Also: findings per app and seconds per app.

Results go to bench/results/<date>-appsec-heldout.json: per app its commit, verdict, files, seconds and per finding
the rule, severity, file, line and message. Never the evidence lines: AI-built apps commit real keys.

Round two (--round 2, fixture bench/fixtures/appsec-heldout-round2.json) is the fresh draw that measures the fixes
round one led to, under the same protocol. Round one's 34 apps join the development set. Its vulnerable and
well-built apps are the first candidates of the ranked lists VULNERABLE_2 and WELL_BUILT_2 that can be read, are not
forks and are written in a language appsec reads (well-built ones also pushed in the last year); its apps built with
AI are drawn with its own seed from round one's saved search results, without every repository round one examined.
Results go to bench/results/<date>-appsec-heldout-round2.json.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import random
import shutil
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "bench"))

from run import code_hash  # noqa: E402

FIXTURE = ROOT / "bench" / "fixtures" / "appsec-heldout-round1.json"
LABELS = ROOT / "bench" / "fixtures" / "appsec-heldout-round1-labels.json"
SEED = "pah-appsec-heldout-round1-2026-11-25"
QUERY = '"Welcome to your Lovable project" filename:README.md'
AI_BUILT = 15

DEVELOPMENT = [
    "nextjs/saas-starter", "vercel/ai-chatbot", "mckaywrigley/chatbot-ui", "shadcn-ui/taxonomy",
    "vercel/nextjs-subscription-payments", "fastapi/full-stack-fastapi-template",
    "gothinkster/node-express-realworld-example-app", "gothinkster/django-realworld-example-app",
    "juice-shop/juice-shop", "OWASP/NodeGoat", "appsecco/dvna", "adeyosemanputra/pygoat",
]
VULNERABLE = [
    "erev0s/VAmPI", "snoopysecurity/dvws-node", "cr0hn/vulnerable-node", "we45/Vulnerable-Flask-App",
    "anxolerd/dvpwa", "payatu/Tiredful-API", "stamparm/DSVW", "dolevf/Damn-Vulnerable-GraphQL-Application",
    "OWASP/crAPI",
]
WELL_BUILT = [
    "umami-software/umami", "boxyhq/saas-starter-kit", "ixartz/SaaS-Boilerplate", "sahat/hackathon-starter",
    "hagopj13/node-express-boilerplate", "danielfsousa/express-rest-boilerplate", "miguelgrinberg/microblog",
    "nsidnev/fastapi-realworld-example-app", "HackSoftware/Django-Styleguide-Example",
    "Razikus/supabase-nextjs-template",
]
GIT = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull, "-c", "core.longpaths=true",
       "-c", "core.symlinks=false", "-c", "protocol.file.allow=never"]

# Round two (2026-11-25): a fresh draw after the fixes round one led to. Round one's 34 apps are development data now.
# The apps are the first candidates of these ranked lists that qualify (see _qualifies), in this order; the lists were
# written before any candidate was checked, and the fixture records why each skipped one was skipped.
VULNERABLE_2 = [
    "snyk-labs/nodejs-goof", "fportantier/vulpy", "Checkmarx/capital", "payatu/vuln-nodejs-app",
    "WithSecureLabs/damn-vulnerable-llm-agent", "SirAppSec/vuln-node.js-express.js-app", "nVisium/django.nV",
    "OWASP/DVSA", "trottomv/python-insecure-app", "jorritfolmer/vulnerable-api", "carvesystems/vulnerable-graphql-api",
    "harishsg993010/DamnVulnerableLLMProject", "Contrast-Security-OSS/vulnpy",
]
WELL_BUILT_2 = [
    "lukevella/rallly", "documenso/documenso", "mfts/papermark", "linkwarden/linkwarden", "elie222/inbox-zero",
    "mealie-recipes/mealie", "healthchecks/healthchecks", "wger-project/wger", "formbricks/formbricks", "dubinc/dub",
    "openstatusHQ/openstatus", "outline/outline", "langfuse/langfuse", "calcom/cal.com",
]
LANGUAGES = {"JavaScript", "TypeScript", "Python", "HTML", "EJS", "Pug", "Handlebars", "Vue", "Svelte", "Jinja"}
ROUNDS = {
    1: {"fixture": "appsec-heldout-round1.json", "labels": "appsec-heldout-round1-labels.json",
        "seed": SEED, "results": "{date}-appsec-heldout.json"},
    2: {"fixture": "appsec-heldout-round2.json", "labels": "appsec-heldout-round2-labels.json",
        "seed": "pah-appsec-heldout-round2-2026-11-25", "results": "{date}-appsec-heldout-round2.json"},
}


def _paths(n: int) -> tuple[Path, Path, str, str]:
    r = ROUNDS[n]
    fixtures = ROOT / "bench" / "fixtures"
    return fixtures / r["fixture"], fixtures / r["labels"], r["seed"], r["results"]


def _gh(path: str) -> dict | None:
    res = subprocess.run(["gh", "api", path], capture_output=True, timeout=60, check=False)
    if res.returncode != 0:
        return None
    try:
        return json.loads(res.stdout)
    except ValueError:
        return None


def head(repo: str) -> str | None:
    res = subprocess.run(GIT + ["ls-remote", f"https://github.com/{repo}.git", "HEAD"], capture_output=True,
                         timeout=120, check=False, env=dict(os.environ, GIT_TERMINAL_PROMPT="0"))
    out = res.stdout.decode("utf-8", "replace").split()
    return out[0] if res.returncode == 0 and out else None


def draw_ai_built(frame: list[str], seed: str = SEED, want: int = AI_BUILT) -> tuple[list[dict], list[dict]]:
    order = sorted(set(frame))
    random.Random(seed).shuffle(order)
    kept, skipped = [], []
    for repo in order:
        if len(kept) >= want:
            break
        meta = _gh(f"repos/{repo}")
        if meta is None:
            skipped.append({"repo": repo, "why": "cannot be read"})
            continue
        if meta.get("fork"):
            skipped.append({"repo": repo, "why": "fork"})
            continue
        if not isinstance(_gh(f"repos/{repo}/contents/supabase"), list):
            skipped.append({"repo": repo, "why": "no supabase/ folder"})
            continue
        commit = head(repo)
        if not commit:
            skipped.append({"repo": repo, "why": "no commit"})
            continue
        kept.append({"repo": repo, "commit": commit})
    return kept, skipped


def _qualifies(repo: str, stratum: str, year_ago: str) -> str:
    """"" when the candidate can be used, else why not. Fixed before any candidate was checked."""
    meta = _gh(f"repos/{repo}")
    if meta is None:
        return "cannot be read"
    if meta.get("fork"):
        return "fork"
    if (meta.get("language") or "") not in LANGUAGES:
        return f"written in {meta.get('language')}"
    if stratum == "well_built" and (meta.get("pushed_at") or "") < year_ago:
        return "no push in the last year"
    if (meta.get("size") or 0) > 400_000:
        return "larger than 400 MB"
    return ""


def _plan_round2(args) -> int:
    fixture, _, seed, _ = _paths(2)
    if fixture.exists() and not args.force:
        print(f"{fixture} exists: the sample is already drawn", file=sys.stderr)
        return 2
    first = json.loads(FIXTURE.read_text(encoding="utf-8"))
    used = set(DEVELOPMENT) | {a["repo"] for apps in first["strata"].values() for a in apps}
    examined = used | {s["repo"] for s in first["frame"]["ai_built"]["skipped_in_order"]}
    year_ago = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 365 * 86400))
    strata, candidates = {}, {}
    for name, ranked, want in (("vulnerable", VULNERABLE_2, 9), ("well_built", WELL_BUILT_2, 10)):
        strata[name], candidates[name] = [], []
        for repo in ranked:
            if len(strata[name]) >= want:
                break
            why = "in the development set" if repo in used else _qualifies(repo, name, year_ago)
            commit = None if why else head(repo)
            if not why and not commit:
                why = "no commit"
            candidates[name].append({"repo": repo, "used": not why, **({"why": why} if why else {})})
            if not why:
                strata[name].append({"repo": repo, "commit": commit})
    frame = [r for r in first["frame"]["ai_built"]["results"] if r not in examined]
    strata["ai_built"], skipped = draw_ai_built(frame, seed=seed)
    rev = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
    doc = {"kind": "appsec-heldout-round2", "drawn": time.strftime("%Y-%m-%d"), "seed": seed,
           "code_at_draw": rev.stdout.strip(), "code_hash_at_draw": code_hash(),
           "development_set": sorted(used), "strata": strata, "candidates": candidates,
           "frame": {"ai_built": {"query": QUERY, "from": "round one's saved search results, without every repository "
                                                       "round one examined", "results": sorted(frame),
                                  "skipped_in_order": skipped}},
           "expected": {}, "out_of_scope": {}}
    fixture.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"pinned {sum(len(v) for v in strata.values())} apps -> {fixture}")
    return 0


def cmd_plan(args) -> int:
    if args.round == 2:
        return _plan_round2(args)
    if FIXTURE.exists() and not args.force:
        print(f"{FIXTURE} exists: the sample is already drawn", file=sys.stderr)
        return 2
    if not args.frame:
        raise SystemExit("round one needs --frame")
    frame = [ln.strip() for ln in Path(args.frame).read_text(encoding="utf-8").splitlines() if ln.strip()]
    frame = [r for r in frame if r not in DEVELOPMENT]
    strata = {}
    for name, repos in (("vulnerable", VULNERABLE), ("well_built", WELL_BUILT)):
        strata[name] = []
        for repo in repos:
            commit = head(repo)
            if not commit:
                raise SystemExit(f"cannot pin {repo}")
            strata[name].append({"repo": repo, "commit": commit})
    strata["ai_built"], skipped = draw_ai_built(frame)
    rev = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
    doc = {"kind": "appsec-heldout-round1", "drawn": time.strftime("%Y-%m-%d"), "seed": SEED,
           "code_at_draw": rev.stdout.strip(), "code_hash_at_draw": code_hash(), "development_set": DEVELOPMENT,
           "strata": strata,
           "frame": {"ai_built": {"query": QUERY, "searched": time.strftime("%Y-%m-%d"), "results": sorted(set(frame)),
                                  "skipped_in_order": skipped}},
           "expected": {}, "out_of_scope": {}}
    FIXTURE.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"pinned {sum(len(v) for v in strata.values())} apps -> {FIXTURE}")
    return 0


def _dir(cache: Path, repo: str) -> Path:
    return cache / repo.replace("/", "__")


def cmd_fetch(args) -> int:
    doc = json.loads(_paths(args.round)[0].read_text(encoding="utf-8"))
    cache = Path(args.cache)
    cache.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1")
    for stratum, apps in doc["strata"].items():
        for app in apps:
            dest = _dir(cache, app["repo"])
            if (dest / ".git").is_dir():
                continue
            dest.mkdir(parents=True, exist_ok=True)
            steps = [["init", "-q"], ["remote", "add", "origin", f"https://github.com/{app['repo']}.git"],
                     ["fetch", "-q", "--depth", "1", "--no-recurse-submodules", "origin", app["commit"]],
                     ["checkout", "-q", "FETCH_HEAD"]]
            for step in steps:
                res = subprocess.run(GIT + ["-C", str(dest)] + step, capture_output=True, timeout=900, check=False,
                                     env=env)
                if res.returncode != 0:
                    print(f"{app['repo']}: git {step[0]} failed: {res.stderr.decode('utf-8', 'replace')[:200]}")
                    break
            print(f"{stratum:10} {app['repo']}")
    return 0


def cmd_run(args) -> int:
    from pah.appsec import check

    fixture, _, _, results_name = _paths(args.round)
    doc = json.loads(fixture.read_text(encoding="utf-8"))
    cache = Path(args.cache)
    rev = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
    out = {"name": f"appsec-heldout-round{args.round}", "date": time.strftime("%Y-%m-%d"), "platform": sys.platform,
           "code": code_hash(), "commit": rev.stdout.strip(), "apps": []}
    for stratum, apps in doc["strata"].items():
        for app in apps:
            path = _dir(cache, app["repo"])
            started = time.monotonic()
            rep = check(path, max_seconds=600)
            seconds = round(time.monotonic() - started, 2)
            out["apps"].append({
                "stratum": stratum, "repo": app["repo"], "commit": app["commit"], "verdict": rep.verdict,
                "files": rep.stats.get("files", 0), "seconds": seconds, "incomplete": rep.incomplete,
                "findings": [{"rule": f.rule, "severity": f.severity, "path": f.path, "line": f.line,
                              "message": f.message} for f in rep.sorted_findings()]})
            top = Counter(f.severity for f in rep.findings)
            print(f"{stratum:10} {app['repo'][:44]:44} {rep.verdict:5} {seconds:6}s  "
                  f"{top.get('critical', 0) + top.get('high', 0)} high+, {top.get('medium', 0)} medium")
    dest = ROOT / "bench" / "results" / results_name.format(date=out["date"])
    if dest.exists():
        raise SystemExit(f"{dest} exists: the run is made once")
    dest.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"-> {dest}")
    return 0


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, (c - r) / d), min(1.0, (c + r) / d))


def _key(app: str, f: dict) -> tuple:
    return (app, f["rule"], f["path"], f["line"])


def publish(results: dict, labels: dict) -> tuple[dict, dict]:
    """The files safe to publish. Apps built with AI are real people's projects, and a true label says where one can be
    attacked: they are published under pseudonyms (in an order that is not kept), with each finding's rule, severity
    and label only. Apps built to be attacked and the well-built apps stay as they are."""
    marks = {(x["app"], x["rule"], x["path"], x["line"]): x for x in labels["labels"]}
    ai = [a["repo"] for a in results["apps"] if a["stratum"] == "ai_built"]
    random.SystemRandom().shuffle(ai)
    alias = {repo: f"ai-{i:02d}" for i, repo in enumerate(ai, 1)}
    apps = []
    for app in results["apps"]:
        if app["repo"] not in alias:
            apps.append(app)
            continue
        name = alias[app["repo"]]
        found = []
        for i, f in enumerate(app["findings"], 1):
            mark = marks.get(_key(app["repo"], f))
            row = {"id": f"{name}-{i:03d}", "rule": f["rule"], "severity": f["severity"]}
            if f["severity"] in ("medium", "high", "critical"):
                row["label"] = mark["label"] if mark else "unlabeled"
            found.append(row)
        apps.append({"stratum": app["stratum"], "repo": name, "verdict": app["verdict"], "files": app["files"],
                     "seconds": app["seconds"], "findings": found})
    pub_results = {k: v for k, v in results.items() if k != "apps"}
    pub_results["apps"] = apps
    pub_results["published"] = ("apps built with AI appear under pseudonyms, with rule, severity and label only; the "
                                "full results are kept locally")
    from pah.appsec import _mask  # a reviewer's note can quote a key it read: cut every key-shaped value

    pub_labels = {k: v for k, v in labels.items() if k != "labels"}
    pub_labels["labels"] = [dict(x, why=_mask(x.get("why", ""))) for x in labels["labels"] if x["app"] not in alias]
    return pub_results, pub_labels


def score(results: dict, labels: dict, fixture: dict) -> dict:
    """Join each medium-or-above finding with its label; precision per stratum, severity and rule; recall on the
    documented vulnerabilities."""
    marks = {(x["app"], x["rule"], x["path"], x["line"]): x for x in labels["labels"]}
    groups: dict[tuple, Counter] = defaultdict(Counter)
    unlabeled = []
    per_app = {}
    for app in results["apps"]:
        counted = Counter()
        for f in app["findings"]:
            if f["severity"] not in ("medium", "high", "critical"):
                continue
            if "label" in f:  # a published file carries the label inline
                label = f["label"]
            else:
                mark = marks.get(_key(app["repo"], f))
                label = mark["label"] if mark else "unlabeled"
            if label == "unlabeled":
                unlabeled.append((app["repo"], f["rule"], f.get("path", f.get("id")), f.get("line", 0)))
            sev = "high" if f["severity"] in ("high", "critical") else "medium"
            for g in (("all",), ("stratum", app["stratum"]), ("stratum-severity", app["stratum"], sev),
                      ("rule", f["rule"]), ("severity", sev)):
                groups[g][label] += 1
            counted[label] += 1
        per_app[app["repo"]] = {"stratum": app["stratum"], "seconds": app["seconds"], "files": app["files"],
                                **dict(counted)}
    table = {}
    for g, c in sorted(groups.items()):
        t, fl, u = c["true"], c["false"], c["uncertain"]
        lo, hi = wilson(t, t + fl)
        table["/".join(g)] = {"true": t, "false": fl, "uncertain": u, "unlabeled": c["unlabeled"],
                              "precision": round(t / (t + fl), 3) if t + fl else None,
                              "ci95": [round(lo, 3), round(hi, 3)],
                              "bounds": [round(t / (t + fl + u), 3) if t + fl + u else None,
                                         round((t + u) / (t + fl + u), 3) if t + fl + u else None]}
    caught = labels.get("caught", {})
    recall = {}
    total_k = total_n = 0
    for repo, vulns in fixture.get("expected", {}).items():
        ids = [v["id"] for v in vulns]
        got = sorted(set(caught.get(repo, [])) & set(ids))
        recall[repo] = {"documented": len(ids), "caught": len(got), "missed": sorted(set(ids) - set(got))}
        total_k += len(got)
        total_n += len(ids)
    lo, hi = wilson(total_k, total_n)
    by_class = defaultdict(lambda: [0, 0])
    for repo, vulns in fixture.get("expected", {}).items():
        for v in vulns:
            by_class[v["class"]][1] += 1
            by_class[v["class"]][0] += v["id"] in caught.get(repo, [])
    return {"precision": table, "recall": {"caught": total_k, "documented": total_n,
                                           "recall": round(total_k / total_n, 3) if total_n else None,
                                           "ci95": [round(lo, 3), round(hi, 3)], "per_app": recall,
                                           "per_class": {k: {"caught": v[0], "documented": v[1]}
                                                         for k, v in sorted(by_class.items())}},
            "per_app": per_app, "unlabeled": unlabeled}


def cmd_publish(args) -> int:
    results = json.loads(Path(args.results).read_text(encoding="utf-8"))
    labels = json.loads(Path(args.labels).read_text(encoding="utf-8"))
    pub_results, pub_labels = publish(results, labels)
    labels_out = _paths(args.round)[1]
    Path(args.out_results).write_text(json.dumps(pub_results, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    labels_out.write_text(json.dumps(pub_labels, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"-> {args.out_results}\n-> {labels_out}")
    return 0


def cmd_score(args) -> int:
    fixture_path, labels_path, _, _ = _paths(args.round)
    results = json.loads(Path(args.results).read_text(encoding="utf-8"))
    labels = json.loads(Path(args.labels or labels_path).read_text(encoding="utf-8"))
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    out = score(results, labels, fixture)
    if args.json:
        print(json.dumps(out, indent=1))
        return 0
    print("precision (true / (true + false)), Wilson 95% interval, bounds with uncertain as false..true")
    for g, row in out["precision"].items():
        print(f"  {g:32} {row['true']:4} true {row['false']:4} false {row['uncertain']:3} uncertain  "
              f"precision {row['precision']}  ci {row['ci95']}  bounds {row['bounds']}")
    r = out["recall"]
    print(f"recall on documented vulnerabilities: {r['caught']}/{r['documented']} = {r['recall']}  ci {r['ci95']}")
    for k, v in r["per_class"].items():
        print(f"  {k}: {v['caught']}/{v['documented']}")
    if out["unlabeled"]:
        print(f"{len(out['unlabeled'])} findings have no label")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    def add(name: str, func, help_: str):
        p = sub.add_parser(name, help=help_)
        p.add_argument("--round", type=int, choices=sorted(ROUNDS), default=1)
        p.set_defaults(func=func)
        return p

    p = add("plan", cmd_plan, "pin the sample (names and commits only)")
    p.add_argument("--frame", help="round one: file with the code search results, one owner/name per line")
    p.add_argument("--force", action="store_true")
    add("fetch", cmd_fetch, "fetch each app at its pinned commit").add_argument("--cache", required=True)
    add("run", cmd_run, "pah appsec on each app, once").add_argument("--cache", required=True)
    p = add("publish", cmd_publish, "write the results and labels safe to publish (AI-built apps pseudonymized)")
    p.add_argument("results", help="the full results (kept outside git)")
    p.add_argument("labels", help="the full labels (kept outside git)")
    p.add_argument("out_results", help="where the published results go")
    p = add("score", cmd_score, "precision and recall from the labels")
    p.add_argument("results")
    p.add_argument("--labels", help="default: the round's published labels")
    p.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
