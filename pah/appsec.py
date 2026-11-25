"""pah appsec: the holes attackers try first in a web app an AI agent built, found by reading the code.

Fourteen checks, one for each way people break into such apps: a script in a username (PAH-W001), another user's ID
in the URL (W002), /admin typed by hand (W003), an API key in the browser (W004), prompt injection (W005), admin at
signup (W006), an edited price (W007), a faked payment (W008), a code redeemed a hundred times (W009), -1 items
(W010), a guessed login code (W011), a database anyone can query (W012), .env in git (W013) and a "photo" that is
not a photo (W014).

Like scan, nothing in the target is run (git is asked which files it tracks, with hooks and fsmonitor off). Unlike
scan, the target is the user's own app and a finding is a bug to fix. The checks read one route handler or one file
at a time, so a clean result is not a security review: skills/app-security covers what reading cannot.
"""
from __future__ import annotations

import base64
import bisect
import fnmatch
import json
import math
import os
import posixpath
import re
import shutil
import subprocess
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .model import RULES, Finding, Report, clip, rank, rule

CWE = "https://cwe.mitre.org/data/definitions/{}.html"

R_XSS = rule(
    "PAH-W001", "Text from users rendered as raw HTML (script in your username)",
    "Anything a visitor can type (a username, bio, comment or search term) that reaches the page as HTML runs as script "
    "in every other visitor's browser: it can read their session, act as them or rewrite the page.",
    "Render it as text (React {value}, Jinja {{ value }}, textContent). If it must be HTML, pass it through a sanitizer "
    "such as DOMPurify or bleach first.", owasp=("A03:2021",), refs=(CWE.format(79),))
R_IDOR = rule(
    "PAH-W002", "Record looked up by an ID from the request without checking its owner (change the ID in the URL)",
    "Signed in is not the same as allowed: changing /orders/123 to /orders/124 shows, edits or deletes another "
    "customer's record when the lookup uses the ID alone.",
    "Look records up by ID and owner together (where: { id, userId: session.user.id }), or compare the record's owner "
    "with the signed-in user before returning or changing it; in Django REST Framework, filter in get_queryset.",
    owasp=("A01:2021",), refs=(CWE.format(639),))
R_ADMIN = rule(
    "PAH-W003", "Admin page or endpoint without a server-side role check (type /admin)",
    "Hiding the admin link does not hide the route. Anyone who types /admin, or calls the admin API directly, gets in "
    "unless the server checks the role on every request.",
    "Check the role on the server for every admin route: a middleware or decorator on the route or its router "
    "(requireAdmin, @admin_required, IsAdminUser) or a Next.js middleware that matches /admin. A check in a client "
    "component only hides the page.", owasp=("A01:2021",), refs=(CWE.format(862), CWE.format(602)))
R_BROWSER_KEY = rule(
    "PAH-W004", "Secret key shipped to the browser (API key in the browser)",
    "Front-end code, NEXT_PUBLIC_, VITE_ and REACT_APP_ variables and mobile bundles are public: anyone can open the "
    "developer tools, copy the key and run up your AI bill or read your whole database with a service-role key.",
    "Keep secret keys on the server (a route handler, server action or edge function calls the provider), drop the "
    "public prefix, rotate the exposed key, and use only keys meant to be public in the browser (Supabase anon, Stripe "
    "publishable).", owasp=("A05:2021",), refs=(CWE.format(200), CWE.format(798)))
R_PROMPT = rule(
    "PAH-W005", "Model output trusted, or user text in the system prompt (prompt-inject your AI)",
    "Anyone who can put text in front of your model can steer it. Its answer then runs as code, SQL or HTML with your "
    "app's power, or the system prompt's rules give way to the user's text.",
    "Treat model output as untrusted input: never pass it to eval, exec, a shell or raw SQL; render it as text; check "
    "structured output against a schema and an allowlist. Keep user text in the user message, not the system prompt.",
    owasp=("LLM01", "LLM05"), refs=("https://genai.owasp.org/llmrisk/llm01-prompt-injection/", CWE.format(94)))
R_MASS = rule(
    "PAH-W006", "Request body saved straight into a record (admin at signup)",
    "When the server saves whatever fields arrive, a signup with \"role\": \"admin\", \"isPro\": true or \"credits\": "
    "99999 is saved too. Supabase user_metadata can be changed by the user, so it cannot decide roles.",
    "Copy only the fields a user may set (const { email, password } = body), or validate with a schema that drops "
    "unknown keys. Set roles and plans only on the server; in Supabase keep them in app_metadata or a table users "
    "cannot write.", owasp=("A01:2021",), refs=(CWE.format(915),))
R_PRICE = rule(
    "PAH-W007", "Price or amount taken from the request (edit the price)",
    "The browser can send any number. A checkout that charges the price the client sent sells everything for a cent.",
    "Send product IDs and quantities only, and look prices up on the server (your catalog, or Stripe Price IDs).",
    owasp=("A04:2021",), refs=(CWE.format(472), CWE.format(602)))
R_PAYMENT = rule(
    "PAH-W008", "Payment trusted without proof from the payment provider (fake a payment)",
    "Anyone can POST a made-up \"payment succeeded\" event to a webhook that does not check signatures, open the "
    "success page without paying, or run the browser's own \"mark as paid\" update from the console.",
    "Fulfil orders only in a webhook that verifies the provider's signature (stripe.webhooks.constructEvent, "
    "Webhook.construct_event, svix), or after retrieving the payment from the provider on the server. Never let the "
    "browser mark anything paid.", owasp=("A08:2021",), refs=(CWE.format(345),))
R_RACE = rule(
    "PAH-W009", "Read, check, then update without a lock (redeem it 100 times)",
    "Send the same redeem request 100 times at once and each one reads \"not used yet\" before any of them writes "
    "\"used\": the coupon, gift card or balance pays out 100 times.",
    "Make the check and the write one atomic step: a conditional update (updateMany({ where: { code, used: false } }) "
    "and check the count; filter(...).update(...) in Django), SELECT ... FOR UPDATE, or a unique constraint on "
    "redemptions. A transaction alone does not stop it at the default isolation level.",
    owasp=("A04:2021",), refs=(CWE.format(362),))
R_QUANTITY = rule(
    "PAH-W010", "Quantity from the request not checked (order -1 items)",
    "A quantity of -1 turns a charge into a credit, makes a cart total negative or puts stock back; 0 and huge numbers "
    "break the arithmetic in other ways.",
    "Accept only whole numbers in a sensible range, on the server: zod .int().positive().max(100), pydantic "
    "Field(gt=0, le=100), or an explicit check that rejects anything below 1.",
    owasp=("A04:2021",), refs=(CWE.format(1284),))
R_CODE = rule(
    "PAH-W011", "Login or reset code that can be guessed (guess the login code)",
    "A six-digit code has a million values: with no limit on attempts a script tries them all in minutes. Codes made "
    "with Math.random() or Python's random module can be predicted outright.",
    "Limit attempts per account and per address and void the code after a few wrong tries; make codes with "
    "crypto.randomInt or the secrets module.", owasp=("A07:2021",), refs=(CWE.format(307), CWE.format(338)))
R_DB = rule(
    "PAH-W012", "Database answers queries it should not (query your database)",
    "SQL built from strings lets a visitor rewrite the query. Supabase tables without row level security, policies "
    "that say using (true) and Firebase rules in test mode let anyone with the public key, which is in your web page, "
    "read and change every row.",
    "Use parameters ($1, %s, ?) or a tagged sql`` template. In Supabase, enable row level security on every table, "
    "with policies that check auth.uid(); in Firebase, replace test-mode rules with rules that check "
    "request.auth.uid.", owasp=("A03:2021", "A01:2021"), refs=(CWE.format(89), CWE.format(284)))
R_SECRET = rule(
    "PAH-W013", "Secret committed to the repository (.env in Git)",
    "A .env file or key in a commit can be read by everyone with the repository, for good: deleting it later leaves it "
    "in history, and bots scan public repositories for keys within minutes.",
    "Add .env* to .gitignore (keep a .env.example with placeholders), remove the file from git (git rm --cached .env), "
    "rotate every key it held, and read secrets from the environment or a secret manager.",
    owasp=("A05:2021",), refs=(CWE.format(540), CWE.format(798)))
R_UPLOAD = rule(
    "PAH-W014", "Uploaded file stored without checking what it is (upload a non-photo)",
    "An \"avatar\" that is really an HTML or SVG file runs script when someone opens its link on your domain, and a "
    "name like ../../server.js can overwrite your code. Unchecked sizes fill the disk.",
    "Check the type by content (file-type, Pillow) against an allowlist without SVG, cap the size, store under a name "
    "you generate, and serve uploads from another domain or as attachments.",
    owasp=("A04:2021",), refs=(CWE.format(434),))

RULE_IDS = (R_XSS, R_IDOR, R_ADMIN, R_BROWSER_KEY, R_PROMPT, R_MASS, R_PRICE, R_PAYMENT, R_RACE, R_QUANTITY, R_CODE,
            R_DB, R_SECRET, R_UPLOAD)
# What a single file can show on its own: the note an agent gets right after writing one. Ownership, admin routes,
# races, rate limits and row level security depend on other files, so only the whole-app check reports them.
LOCAL_RULES = frozenset((R_XSS, R_BROWSER_KEY, R_PROMPT, R_MASS, R_PRICE, R_PAYMENT, R_CODE, R_DB, R_SECRET, R_UPLOAD))

# ------------------------------------------------------------------------------------------------ files

SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", ".nuxt", ".output", ".svelte-kit", ".vercel", ".netlify",
             "out", "coverage", "vendor", "venv", ".venv", "__pycache__", "site-packages", "bower_components", ".turbo",
             ".cache", ".parcel-cache", ".expo", "Pods", "target", ".gradle", ".idea", "storybook-static", ".tox",
             ".mypy_cache", ".pytest_cache", ".ruff_cache", ".wrangler", ".angular", "public/build"}
JS_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte", ".astro"}
PY_EXT = {".py"}
TEMPLATE_EXT = {".html", ".htm", ".jinja", ".jinja2", ".j2", ".ejs", ".hbs", ".handlebars", ".njk", ".liquid", ".twig",
                ".php", ".erb"}
TEXT_EXT = JS_EXT | PY_EXT | TEMPLATE_EXT | {".sql", ".rules", ".json", ".yaml", ".yml", ".toml", ".env", ".txt", ".cfg",
                                             ".ini", ".conf", ".properties", ".sh", ".rb", ".go", ".java", ".kt", ".cs",
                                             ".swift", ".dart", ".xml", ".plist", ".gradle", ""}
LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "poetry.lock", "uv.lock", "composer.lock",
             "gemfile.lock", "cargo.lock", "go.sum", "pipfile.lock"}
MAX_BYTES = 600_000
MAX_FILES = 60_000
ENV_NAME = re.compile(r"^\.env(?:\.[\w.-]+)?$|^[\w.-]+\.env$", re.I)
ENV_EXAMPLE = re.compile(r"example|sample|template|\.dist$|defaults?$|\.tpl$|schema", re.I)
TEST_PATH = re.compile(
    r"(?:^|/)(?:tests?|__tests__|__mocks__|specs?|fixtures?|e2e|cypress|playwright|mocks?|examples?|samples?|demos?|"
    r"docs?|stories|seeds?|seeders)/|\.(?:test|spec|stories|cy|e2e)\.[cm]?[jt]sx?$|_test\.[cm]?[jt]sx?$|"
    r"(?:^|/)test_[^/]*\.py$|_tests?\.py$|(?:^|/)conftest\.py$|(?:^|/)seed(?:s|er|ing)?\.(?:[cm]?[jt]s|py)$", re.I)


HASHED_NAME = re.compile(r"[.-]([A-Za-z0-9_-]{8,10})\.[cm]?js$")
GENERATED = re.compile(r"(?:^|[._-])generated\.[cm]?[jt]sx?$|\.gen\.[cm]?[jt]sx?$|_pb2(?:_grpc)?\.py$", re.I)
GENERATED_HEAD = re.compile(r"@generated\b|\bauto-?generated\b|\bDO NOT EDIT\b|\bcode generated by\b", re.I)


VERSION = r"(?:\bv\d+\.\d+(?:\.\d+)?|\b\d+\.\d+\.\d+)\b"  # 3.5.1 or v0.100: not "License, Version 2.0"
VENDOR_BANNER = re.compile(rf"^﻿?\s*/\*[!*]?(?:(?!\*/).){{0,600}}?(?:{VERSION}(?:(?!\*/).){{0,600}}?"
                           rf"(?:licen[sc]e|copyright|\(c\))|(?:licen[sc]e|copyright|\(c\))(?:(?!\*/).){{0,600}}?"
                           rf"{VERSION})", re.S | re.I)
VENDOR_DIR = re.compile(r"(?:^|/)(?:static|public|assets|vendors?|libs?|js|third[_-]party|external|plugins)/", re.I)


def _vendored(rel: str, text: str) -> bool:
    """A third-party library copied into the app (jQuery, Materialize, ...): a .js file in a static or vendor folder
    whose opening comment names a version and a license. Dependencies are `pah audit`'s job, not the app's."""
    return posixpath.splitext(rel)[1].lower() in (".js", ".mjs", ".cjs") and bool(VENDOR_DIR.search(rel)) and \
        bool(VENDOR_BANNER.match(text[:1500]))


def _bundle(rel: str, text: str) -> bool:
    """Built or generated output (minified, a hashed chunk name, a file a generator wrote): judged in its source
    instead."""
    name = posixpath.basename(rel)
    if name.endswith((".min.js", ".min.mjs", ".bundle.js")):
        return True
    if GENERATED.search(name) or (posixpath.splitext(name)[1].lower() in JS_EXT | PY_EXT
                                  and GENERATED_HEAD.search(text[:600])):
        return True
    if _vendored(rel, text):
        return True
    hashed = HASHED_NAME.search(name)
    if hashed and re.search(r"\d", hashed.group(1)) and re.search(r"[A-Za-z]", hashed.group(1)):
        return True
    if posixpath.splitext(name)[1].lower() not in JS_EXT:
        return False
    lines = text.count("\n") + 1
    return len(text) / lines > 300 or any(len(x) > 4000 for x in text.split("\n", 200)[:200])


def _skipped(rel: str) -> bool:
    parts = rel.split("/")[:-1]
    return any(p in SKIP_DIRS for p in parts) or any("/".join(parts[i:i + 2]) in SKIP_DIRS for i in range(len(parts)))


def _lang(rel: str) -> str:
    low = rel.lower()
    name = posixpath.basename(low)
    ext = posixpath.splitext(name)[1]
    if ENV_NAME.match(name):
        return "env"
    if name.endswith(".rules") or name == "database.rules.json":
        return "rules"
    if ext in JS_EXT:
        return "js"
    if ext in PY_EXT:
        return "py"
    if ext in TEMPLATE_EXT:
        return "tmpl"
    if ext == ".sql":
        return "sql"
    return "other"


@dataclass
class Src:
    rel: str
    text: str
    lang: str
    client: bool = False
    test: bool = False
    dead: bool = False  # a browser file nothing in the app imports
    _nl: list = field(default_factory=list, repr=False)

    def line(self, pos: int) -> int:
        if pos < 0:
            return 0
        if not self._nl:
            self._nl = [m.start() for m in re.finditer("\n", self.text)] or [len(self.text)]
        return bisect.bisect_left(self._nl, pos) + 1

    def line_text(self, pos: int) -> str:
        start = self.text.rfind("\n", 0, pos) + 1
        end = self.text.find("\n", pos)
        return self.text[start:len(self.text) if end < 0 else end]


class Out:
    def __init__(self, only: frozenset | None = None):
        self.findings: list[Finding] = []
        self._seen: set = set()
        self.only = only

    def add(self, rule_id: str, severity: str, src: Src, pos: int, message: str, evidence: str | None = None) -> None:
        if self.only is not None and rule_id not in self.only:
            return
        if src.test and rank(severity) > rank("low"):
            severity, message = "low", message + " (in a test or example file)"
        elif src.dead and rank(severity) > rank("low") and rule_id not in (R_BROWSER_KEY, R_SECRET):
            # a key is exposed in the repository whether or not the file runs
            severity, message = "low", message + " (in a file nothing in the app imports)"
        line = src.line(pos)
        key = (rule_id, src.rel, line)
        if evidence is None:
            evidence = _mask(src.line_text(pos).strip()) if pos >= 0 else ""
        finding = Finding(rule_id, severity, src.rel, line, message, clip(evidence, 160), "app")
        if key in self._seen:  # one finding per rule and line: the most severe
            for i, old in enumerate(self.findings):
                if (old.rule, old.path, old.line) == key and rank(severity) > rank(old.severity):
                    self.findings[i] = finding
            return
        self._seen.add(key)
        self.findings.append(finding)


# ------------------------------------------------------------------------------------------------ reading code

def _skip_quote(text: str, j: int, q: str, end: int) -> int:
    k = j + 1
    while k < end:
        ch = text[k]
        if ch == "\\":
            k += 2
            continue
        if ch == q:
            return k + 1
        if ch == "\n":
            return k
        k += 1
    return end


def _skip_template(text: str, j: int, end: int) -> int:
    k = j + 1
    while k < end:
        ch = text[k]
        if ch == "\\":
            k += 2
            continue
        if ch == "`":
            return k + 1
        if ch == "$" and k + 1 < end and text[k + 1] == "{":
            k = _close(text, k + 1)
            continue
        k += 1
    return end


def _close(text: str, i: int, py: bool = False, limit: int = 120_000) -> int:
    """Index just past the bracket that closes text[i], skipping strings, template literals and comments."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    if i >= len(text) or text[i] not in pairs:
        return i
    stack = [pairs[text[i]]]
    j, end = i + 1, min(len(text), i + limit)
    while j < end:
        c = text[j]
        if c in "'\"":
            if py and text.startswith(c * 3, j):
                k = text.find(c * 3, j + 3)
                j = end if k < 0 else k + 3
            else:
                j = _skip_quote(text, j, c, end)
            continue
        if c == "`" and not py:
            j = _skip_template(text, j, end)
            continue
        if py and c == "#":
            k = text.find("\n", j)
            j = end if k < 0 else k
            continue
        if not py and c == "/" and j + 1 < end and text[j + 1] in "/*":
            k = text.find("\n" if text[j + 1] == "/" else "*/", j + 2)
            j = end if k < 0 else (k if text[j + 1] == "/" else k + 2)
            continue
        if c in pairs:
            stack.append(pairs[c])
        elif c in ")]}" and c == stack[-1]:
            stack.pop()
            if not stack:
                return j + 1
        j += 1
    return end


QUOTED = re.compile(r"'(?:[^'\\\n]|\\.)*'|\"(?:[^\"\\\n]|\\.)*\"")


def _code_only(s: str) -> str:
    """The expression with the contents of quoted strings removed: words inside strings are not names."""
    return QUOTED.sub("''", s)


def _no_comments(s: str) -> str:
    """JavaScript without its comments (strings kept), so a comment is never read as an argument."""
    return re.sub(r"'(?:[^'\\\n]|\\.)*'|\"(?:[^\"\\\n]|\\.)*\"|`(?:[^`\\]|\\.)*`|(//[^\n]*|/\*.*?\*/)",
                  lambda m: " " if m.group(1) else m.group(0), s, flags=re.S)


def _top_level(obj: str) -> list[str]:
    """The entries of an object literal, split at its own commas only."""
    inner, parts, depth, cur, i = obj.strip()[1:-1], [], 0, "", 0
    while i < len(inner):
        c = inner[i]
        if c in "'\"`":
            j = _skip_template(inner, i, len(inner)) if c == "`" else _skip_quote(inner, i, c, len(inner))
            cur += inner[i:j]
            i = j
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "," and depth == 0:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += c
        i += 1
    if cur.strip():
        parts.append(cur.strip())
    return parts


def _call_args(text: str, open_paren: int, py: bool = False) -> str:
    return text[open_paren + 1:max(open_paren + 1, _close(text, open_paren, py) - 1)]


def _value_after(text: str, pos: int, py: bool = False) -> str:
    """The expression that starts at pos: a template literal, a bracketed group, or the rest of the item."""
    while pos < len(text) and text[pos] in " \t":
        pos += 1
    if pos >= len(text):
        return ""
    if text[pos] == "`":
        return text[pos:_skip_template(text, pos, min(len(text), pos + 20_000))]
    end = pos
    limit = min(len(text), pos + 600)
    while end < limit:
        c = text[end]
        if c in "([{":
            end = _close(text, end, py)
            continue
        if c in "'\"":
            end = _skip_quote(text, end, c, limit)
            continue
        if c == "`":
            end = _skip_template(text, end, limit)
            continue
        if c in ",;)}]\n":
            break
        end += 1
    return text[pos:end]


def _interpolations(literal: str) -> list[str]:
    """The ${...} parts of a template literal, or the {...} parts of a Python f-string."""
    out, i = [], 0
    if literal.startswith("`"):
        while True:
            i = literal.find("${", i)
            if i < 0:
                return out
            j = _close(literal, i + 1)
            out.append(literal[i + 2:j - 1])
            i = j
    return re.findall(r"(?<!\{)\{([^{}\n]{1,200})\}(?!\})", literal)


# ------------------------------------------------------------------------------------------------ request data

JS_SOURCE = re.compile(
    r"\breq\.(?:body|query|params|files?|cookies)\b|\brequest\.(?:body|query|params)\b|\bctx\.(?:request\.body|params|"
    r"query)\b|\b(?:req|request)\.(?:json|formData|text)\b|\bsearchParams\b|\bparams\b|\bevent\.body\b|"
    r"\bc\.req\.(?:json|param|query|parseBody|formData)\b|\bformData\.get(?:All)?\b|\bform\.get\b|\buseParams\b|"
    r"\brouter\.query\b")
PY_SOURCE = re.compile(
    r"\brequest\.(?:json|form|args|values|data|files|get_json|POST|GET|query_params|body|cookies|query|path_params)\b")
JS_WHOLE = re.compile(
    r"^\s*(?:await\s+)?(?:(?:req|request|ctx\.request|c\.req)\.(?:json|formData|parseBody)\s*\(\s*\)|(?:req|request|"
    r"ctx\.request)\.body|JSON\.parse\(\s*(?:event|req)\.body\s*\)|Object\.fromEntries\(\s*(?:await\s+)?\w+(?:\.\w+)*"
    r"(?:\(\s*\))?\s*\))\s*(?:as\s+[\w<>\[\], ]+)?\s*;?\s*$")
PY_WHOLE = re.compile(r"^\s*(?:await\s+)?request\.(?:json|form|data|POST|get_json\s*\([^)]*\)|json\s*\(\s*\))\s*$")
JS_DECL = re.compile(r"(?:const|let|var)\s+(\{[^{};]{0,400}\}|\[[^\[\];]{0,200}\]|[\w$]+)\s*(?::\s*[^=;\n]{1,80})?=(?![=>])"
                     r"\s*([^;\n]{1,400})")
PY_ASSIGN = re.compile(r"^[ \t]*([A-Za-z_][\w]*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?::\s*[^=\n]{1,60})?=(?!=)\s*([^\n]{1,400})$",
                       re.M)
LOOP_JS = re.compile(r"([\w$]+)(?:\.[\w$]+)*\.(?:map|forEach|flatMap|filter|some|every|find)\(\s*(?:async\s*)?\(?\s*"
                     r"(?:\{([^}]{1,200})\}|([\w$]+))"
                     r"|([\w$]+)(?:\.[\w$]+)*\.reduce\(\s*(?:async\s*)?\(\s*[\w$]+\s*,\s*([\w$]+)"
                     r"|for\s*\(\s*(?:const|let|var)\s+(?:\{([^}]{1,200})\}|([\w$]+))\s+of\s+([\w$]+)")
LOOP_PY = re.compile(r"\bfor\s+([\w, ]+?)\s+in\s+([\w.]+)")
LOOKUP_CALL = re.compile(r"(?:^|\.)(?:find\w*|get\w*|select\w*|fetch\w*|query|retrieve\w*|load\w*|lookup\w*|first|one|"
                         r"single|maybeSingle|filter\w*|where|aggregate|count|exists|read\w*|search\w*|resolve\w*|"
                         r"\w*[pP]rice\w*)$")


def _lhs_names(lhs: str) -> list[str]:
    lhs = lhs.strip()
    if not lhs or lhs[0] not in "{[":
        return [n.strip() for n in lhs.split(",") if re.fullmatch(r"[\w$]+", n.strip())]
    names = []
    for part in lhs[1:-1].split(","):
        part = part.strip()
        if part.startswith("..."):
            part = part[3:]
        part = part.split("=")[0].strip()
        if ":" in part:
            part = part.split(":", 1)[1].strip()
        if re.fullmatch(r"[\w$]+", part):
            names.append(part)
    return names


def _name_rx(names) -> re.Pattern | None:
    names = [n for n in names if n]
    if not names:
        return None
    alts = "|".join(re.escape(n) for n in sorted(set(names), key=len, reverse=True))
    return re.compile(rf"(?<![\w$.])(?:{alts})(?![\w$])")


class Taint:
    """Names in one handler that hold request data. raw names hold the whole body, before any schema."""

    def __init__(self, lang: str, names=(), raw=()):
        self.lang = lang
        self.names: set[str] = set(names)
        self.raw: set[str] = set(raw)
        self._rx = None
        self._rx_for: frozenset | None = None

    @property
    def rx(self):
        key = frozenset(self.names)
        if key != self._rx_for:
            self._rx, self._rx_for = _name_rx(self.names), key
        return self._rx

    def source(self, expr: str) -> bool:
        return bool((JS_SOURCE if self.lang == "js" else PY_SOURCE).search(expr))

    def touches(self, expr: str) -> bool:
        """Request data anywhere in the expression."""
        return self.source(expr) or bool(self.rx and self.rx.search(expr))

    def flows(self, expr: str) -> bool:
        """Request data reaches the value itself, not only as the key a value is looked up by."""
        return self.touches(_strip_lookups(expr, self))


def _strip_lookups(expr: str, taint: Taint) -> str:
    """Drop the arguments of lookups (find, get, select, ...) and the keys of server-side tables (PRICES[id])."""
    marks = {"(": "\x01", ")": "\x02", "[": "\x03", "]": "\x04"}
    e = expr
    for _ in range(4):
        before = e

        def call(m: re.Match) -> str:
            name = m.group(1)
            if LOOKUP_CALL.search(name):
                return name + "\x01\x02"
            return name + "\x01" + m.group(2) + "\x02"

        e = re.sub(r"(?<![\w$])([\w$.]+)\s*\(([^()]{0,400})\)", call, e)

        def index(m: re.Match) -> str:
            base = m.group(1)
            if taint.touches(base):
                return base + "\x03" + m.group(2) + "\x04"
            return base

        e = re.sub(r"(?<![\w$.])([\w$]+(?:\.[\w$]+)*)\s*\[([^\[\]]{0,200})\]", index, e)
        if e == before:
            break
    for k, v in marks.items():
        e = e.replace(v, k)
    return e


def _js_taint(body: str, params=()) -> Taint:
    t = Taint("js", params)
    decls = [(m.group(1), m.group(2)) for m in JS_DECL.finditer(body)]
    loops = list(LOOP_JS.finditer(body))
    for _ in range(4):
        size = len(t.names)
        for lhs, rhs in decls:
            if t.flows(rhs):
                names = _lhs_names(lhs)
                t.names.update(names)
                if lhs.strip()[:1] not in "{[" and (JS_WHOLE.match(rhs) or rhs.strip().rstrip(";") in t.raw):
                    t.raw.update(names)
        for m in loops:
            coll = m.group(1) or m.group(4) or m.group(8)
            item = m.group(2) or m.group(3) or m.group(5) or m.group(6) or m.group(7)
            if coll and item and coll in t.names:
                t.names.update(_lhs_names("{" + item + "}") if ("," in item or ":" in item) else [item.strip()])
        if len(t.names) == size:
            break
    return t


def _py_taint(body: str, params=()) -> Taint:
    t = Taint("py", params)
    assigns = [(m.group(1), m.group(2)) for m in PY_ASSIGN.finditer(body)]
    loops = [(m.group(1), m.group(2)) for m in LOOP_PY.finditer(body)]
    for _ in range(4):
        size = len(t.names)
        for lhs, rhs in assigns:
            if t.flows(rhs):
                names = _lhs_names(lhs)
                t.names.update(names)
                if len(names) == 1 and (PY_WHOLE.match(rhs) or rhs.strip() in t.raw):
                    t.raw.update(names)
        for target, coll in loops:
            if coll.split(".")[0] in t.names or t.source(coll):
                t.names.update(_lhs_names(target))
        if len(t.names) == size:
            break
    return t


# ------------------------------------------------------------------------------------------------ handlers

@dataclass
class Handler:
    src: Src
    start: int
    end: int
    method: str = "ANY"
    path: str = ""
    guards: str = ""
    kind: str = "route"  # route, page, action, file
    params: tuple = ()
    _taint: Taint | None = None

    @property
    def body(self) -> str:
        return self.src.text[self.start:self.end]

    @property
    def taint(self) -> Taint:
        if self._taint is None:
            body = self.body
            self._taint = (_js_taint if self.src.lang == "js" else _py_taint)(body, self.params)
        return self._taint

    @property
    def where(self) -> str:
        return f"{self.method} {self.path}".strip() if self.path else self.src.rel


JS_ROUTE = re.compile(r"(?<![\w$.])([\w$]+)\s*\.\s*(get|post|put|patch|delete|del|all)\s*\(\s*(['\"`])(/[^'\"`\n]{0,300})\3")
JS_EXPORT = re.compile(r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b|"
                       r"export\s+const\s+(GET|POST|PUT|PATCH|DELETE)\s*(?::\s*[\w<>\[\]]+)?\s*=")
JS_REQRES = re.compile(
    r"(?:export\s+)?(?:async\s+)?function\s+([\w$]+)\s*(?=\(\s*(?:req|request)\b)"
    r"|(?:export\s+)?(?:const|let|var)\s+([\w$]+)\s*=\s*(?:async\s*)?(?:function\s*)?(?=\(\s*(?:req|request)\b)"
    r"|exports\.([\w$]+)\s*=\s*(?:async\s*)?(?:function\s*)?(?=\(\s*(?:req|request)\b)")
JS_ANON = re.compile(r"\b(?:onRequest|onCall|serve|createServer|handler)\s*\(\s*(?:async\s*)?(?:function\s*)?"
                     r"(?=\(\s*(?:req|request|event|ctx|c)\b)")
JS_FILE_HANDLER = re.compile(r"(?:^|/)(?:pages/api|api|supabase/functions|netlify/functions|functions)/")
JS_PAGE = re.compile(r"(?:^|/)app/(?:.*/)?page\.[cm]?[jt]sx?$|(?:^|/)pages/(?!api/)[^.]+\.[jt]sx?$|"
                     r"(?:^|/)routes/.*\+page(?:\.server)?\.[jt]s$")
USE_CLIENT = re.compile(r"^\s*(?:(?://[^\n]*|/\*.*?\*/)\s*)*['\"]use client['\"]", re.S)
USE_SERVER = re.compile(r"^\s*(?:(?://[^\n]*|/\*.*?\*/)\s*)*['\"]use server['\"]", re.S)
JS_HANDLER_FN = re.compile(r"(?:async\s*)?(?:function\s*[\w$]*\s*)?\(\s*(?:req|request|ctx|c|context)\s*(?::[^,()]*)?"
                           r"(?:,[^()]*)?\)\s*(?::\s*[^={()]{1,80})?\s*(?:=>|\{)")
JS_REQ_FN = re.compile(r"(?:async\s*)?(?:function\s*[\w$]*\s*)?\(\s*(?:req|request)\s*(?::[^,()]*)?(?:,[^()]*)?\)\s*"
                       r"(?::\s*[^={()]{1,80})?\s*(?:=>|\{)")
JS_FILE_GUARD = re.compile(r"(?<![\w$.])[\w$]+\s*\.\s*use\s*\(\s*(?!['\"`]/)([^;\n]{1,300})")


def _fn_span(text: str, start: int) -> tuple[int, int, str] | None:
    """From just before a function's parameter list: (body start, body end, parameter text)."""
    p = text.find("(", start, start + 300)
    if p < 0:
        return None
    q = _close(text, p)
    params = text[p + 1:q - 1]
    m = re.compile(r"\s*(?::\s*[^={;]{1,120}?)?\s*(?:=>)?\s*").match(text, q)
    k = m.end() if m else q
    if k < len(text) and text[k] == "{":
        return k, _close(text, k), params
    end = text.find(";", k)
    nl = text.find("\n\n", k)
    stops = [x for x in (end, nl) if x >= 0]
    return p, (min(stops) if stops else len(text)), params


def _next_path(rel: str) -> str:
    parts = rel.split("/")
    for anchor in ("app", "pages", "routes"):
        if anchor in parts:
            parts = parts[len(parts) - parts[::-1].index(anchor):]
            break
    parts = [p for p in parts if not (p.startswith("(") and p.endswith(")"))]
    if parts:
        last = posixpath.splitext(parts[-1])[0]
        if last in ("route", "page", "index", "+server", "+page", "+page.server", "layout"):
            parts = parts[:-1]
        else:
            parts[-1] = last
    return "/" + "/".join(parts)


def _js_handlers(src: Src) -> list[Handler]:
    text, out = src.text, []
    file_guards = " ".join(m.group(1) for m in JS_FILE_GUARD.finditer(text))
    if USE_SERVER.match(text):
        for m in re.finditer(r"export\s+(?:async\s+)?function\s+([\w$]+)\s*(?=\()", text):
            span = _fn_span(text, m.end())
            if span:
                names = _lhs_names("{" + span[2].split(":")[0] + "}") if span[2].strip().startswith("{") else \
                    [p.split(":")[0].strip() for p in span[2].split(",") if p.strip()]
                out.append(Handler(src, span[0], span[1], "POST", f"action:{m.group(1)}", file_guards, "action",
                                   tuple(n for n in names if re.fullmatch(r"[\w$]+", n))))
        return out
    for m in JS_ROUTE.finditer(text):
        receiver = m.group(1)
        if receiver in ("axios", "http", "https", "fetch", "ky", "got", "superagent", "request", "client", "cache",
                        "map", "headers", "cookies", "searchParams", "params", "localStorage", "sessionStorage", "redis",
                        "store", "res", "response", "req", "formData", "url", "query", "$http", "instance"):
            continue
        open_paren = text.find("(", m.start(2))
        close = _close(text, open_paren)
        inner_start = m.end()
        inner = text[inner_start:close - 1]
        fn = list(JS_HANDLER_FN.finditer(inner))
        if fn:
            first = fn[-1]
            guards = inner[:first.start()]
            span = _fn_span(text, inner_start + first.start())
            start, end = (span[0], span[1]) if span else (inner_start + first.start(), close)
        else:
            names = re.findall(r"[\w$.]+", inner)
            if not names:
                continue
            target = names[-1].split(".")[-1]
            d = re.search(rf"(?:function\s+{re.escape(target)}\s*(?=\()|(?:const|let|var)\s+{re.escape(target)}\s*="
                          rf"\s*(?:async\s*)?(?:function\s*)?(?=\())", text)
            if not d:
                continue
            span = _fn_span(text, d.end())
            if not span:
                continue
            guards, (start, end) = inner, span[:2]
        method = {"del": "DELETE", "all": "ANY"}.get(m.group(2), m.group(2).upper())
        out.append(Handler(src, start, end, method, m.group(4), guards + " " + file_guards, "route"))
    for m in JS_EXPORT.finditer(text):
        span = _fn_span(text, m.end() if m.group(1) else m.end())
        if span:
            wrapper = text[m.end():span[0]]
            out.append(Handler(src, span[0], span[1], m.group(1) or m.group(2), _next_path(src.rel),
                               wrapper + " " + file_guards, "route"))
    covered = [(h.start, h.end) for h in out]

    def seen(pos: int) -> bool:  # inside a handler already found (its body, or the function that opens it)
        return any(a <= pos < b for a, b in covered)

    for m in list(JS_REQRES.finditer(text)) + list(JS_ANON.finditer(text)):
        if seen(m.start()):
            continue
        span = _fn_span(text, m.end())
        if span and not seen(span[0]):
            out.append(Handler(src, span[0], span[1], "ANY", "", file_guards, "route"))
            covered.append(span[:2])
    # any other function that takes the request: handlers returned by factories (return (req, res) => ...),
    # assigned to properties (this.show = (req, res) => ...) or passed to a framework
    for m in JS_REQ_FN.finditer(text):
        if seen(m.start()):
            continue
        span = _fn_span(text, m.start())
        if span and not seen(span[0]):
            out.append(Handler(src, span[0], span[1], "ANY", "", file_guards, "route"))
            covered.append(span[:2])
    if JS_PAGE.search(src.rel) and not out:
        out.append(Handler(src, 0, len(text), "GET", _next_path(src.rel), "", "page"))
    elif not out and (JS_FILE_HANDLER.search(src.rel) or (not src.client and JS_SOURCE.search(text) and
                                                          re.search(r"\b(?:req|request)\b", text))):
        out.append(Handler(src, 0, len(text), "ANY", _next_path(src.rel) if JS_FILE_HANDLER.search(src.rel) else "",
                           file_guards, "file"))
    return out


PY_DEF = re.compile(r"^([ \t]*)(?:async[ \t]+)?def[ \t]+(\w+)[ \t]*(?=\()", re.M)
PY_ROUTE = re.compile(r"^[ \t]*@([\w.]+)\.(route|get|post|put|patch|delete|api_route)\(\s*(?:rule\s*=\s*|path\s*=\s*)?"
                      r"[rbuRBU]*(['\"])([^'\"\n]*)\3", re.M)
PY_ROUTER = re.compile(r"^[ \t]*(\w+)\s*=\s*(?:\w+\.)?(?:Blueprint|APIRouter|Namespace)\s*(?=\()", re.M)
PY_DI = {"self", "cls", "request", "req", "db", "session", "current_user", "user", "background_tasks", "response",
         "settings", "args", "kwargs", "cursor", "conn"}


def _py_def_span(text: str, m: re.Match) -> tuple[int, int, str]:
    indent = len(m.group(1).expandtabs())
    p = m.end()
    q = _close(text, p, py=True)
    params = text[p + 1:q - 1]
    i = text.find("\n", q)
    if i < 0:
        return m.start(), len(text), params
    i += 1
    n = len(text)
    while i < n:
        j = text.find("\n", i)
        j = n if j < 0 else j
        line = text[i:j].expandtabs()
        s = line.strip()
        if s and not s.startswith("#") and len(line) - len(line.lstrip()) <= indent:
            return m.start(), i, params
        i = j + 1
    return m.start(), n, params


def _py_params(params: str) -> tuple[str, ...]:
    out, depth, cur = [], 0, ""
    for ch in params + ",":
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            cur = cur.strip()
            if cur and "Depends(" not in cur and "Security(" not in cur:
                name = re.match(r"\*{0,2}(\w+)", cur)
                if name and name.group(1) not in PY_DI:
                    out.append(name.group(1))
            cur = ""
        else:
            cur += ch
    return tuple(out)


def _decorators_above(text: str, pos: int) -> str:
    lines = text[max(0, pos - 2000):pos].split("\n")[:-1]
    keep = []
    for line in reversed(lines):
        if line.strip().startswith("@") or (keep and line.strip() and not line.strip().startswith(("def ", "class "))
                                             and line.startswith((" ", "\t", ")"))):
            keep.append(line)
            continue
        break
    return "\n".join(reversed(keep))


def _py_handlers(src: Src) -> list[Handler]:
    text, out = src.text, []
    prefixes: dict[str, tuple[str, str]] = {}
    for m in PY_ROUTER.finditer(text):
        args = _call_args(text, m.end(), py=True)
        pre = re.search(r"(?:url_prefix|prefix)\s*=\s*['\"]([^'\"]*)['\"]", args)
        deps = re.search(r"dependencies\s*=\s*\[", args)
        before = _call_args(args, deps.end() - 1, py=True) if deps else ""
        for b in re.finditer(rf"^[ \t]*@{re.escape(m.group(1))}\.before_(?:app_)?request\b[^\n]*\n", text, re.M):
            d = PY_DEF.search(text, b.end())
            if d:
                s, e, _ = _py_def_span(text, d)
                before += text[s:e]
        prefixes[m.group(1)] = (pre.group(1) if pre else "", before)
    app_before = ""
    for b in re.finditer(r"^[ \t]*@(?:app|api)\.before_request\b[^\n]*\n", text, re.M):
        d = PY_DEF.search(text, b.end())
        if d:
            s, e, _ = _py_def_span(text, d)
            app_before += text[s:e]
    seen = set()
    for r in PY_ROUTE.finditer(text):
        d = PY_DEF.search(text, r.end())
        if not d or d.start() in seen:
            continue
        seen.add(d.start())
        start, end, params = _py_def_span(text, d)
        receiver = r.group(1).split(".")[0]
        prefix, guard = prefixes.get(receiver, ("", ""))
        tail = text[r.end():d.start()]
        method = r.group(2).upper()
        if method in ("ROUTE", "API_ROUTE"):
            mm = re.search(r"methods\s*=\s*\[\s*['\"](\w+)", tail)
            method = mm.group(1).upper() if mm else "GET"
        guards = _decorators_above(text, r.start()) + "\n" + tail + "\n" + guard + "\n" + app_before
        out.append(Handler(src, start, end, method, prefix + r.group(4), guards, "route", _py_params(params)))
    name = posixpath.basename(src.rel)
    if not out and (name in ("views.py", "api.py", "viewsets.py") or "/views/" in "/" + src.rel):
        classes = [(m.start(), _close_class(text, m)) for m in re.finditer(r"^class\s+\w+\s*\([^)]*\)\s*:", text, re.M)]
        for d in PY_DEF.finditer(text):
            span = _py_def_span(text, d)
            if not re.match(r"\s*(?:self\s*,\s*)?request\b", span[2]):
                continue
            owner = next(((a, b) for a, b in classes if a < d.start() < b), None)
            guards = _decorators_above(text, d.start())
            if owner:
                first_def = text.find("\n    def ", owner[0])
                guards += "\n" + text[owner[0]:first_def if first_def > 0 else owner[1]]
            method = d.group(2).upper() if d.group(2) in ("get", "post", "put", "patch", "delete") else "ANY"
            out.append(Handler(src, span[0], span[1], method, "", guards, "route", ()))
    return out


def _close_class(text: str, m: re.Match) -> int:
    i = text.find("\n", m.end())
    while 0 <= i < len(text):
        j = text.find("\n", i + 1)
        j = len(text) if j < 0 else j
        line = text[i + 1:j]
        if line.strip() and not line.startswith((" ", "\t", "#")):
            return i + 1
        i = j
    return len(text)


# ------------------------------------------------------------------------------------------------ the project

@dataclass
class Project:
    srcs: dict[str, Src]
    deps: set[str] = field(default_factory=set)
    kinds: set[str] = field(default_factory=set)
    middleware: str = ""
    global_limit: bool = False
    git: dict | None = None
    ignores: list[tuple[str, list[str]]] = field(default_factory=list)
    limited: list[str] = field(default_factory=list)  # route prefixes a rate limiter is mounted on
    _role_fns: dict | None = field(default=None, repr=False)

    @property
    def role_fns(self) -> dict[str, bool]:
        """Functions defined anywhere in the app that decide on a role (name -> takes parameters), followed through
        helpers that call them: a role check kept in a permissions module still guards the route that calls it."""
        if self._role_fns is None:
            self._role_fns = _role_functions(self)
        return self._role_fns

    def role_call(self, text: str) -> bool:
        fns = self.role_fns
        if not fns:
            return False
        for m in CALL.finditer(text):
            takes = fns.get(m.group(1))
            if takes is not None and (m.group(2) is None or not takes):
                return True
        return False

    def ignored(self, rel: str) -> bool:
        result = False
        for base, patterns in self.ignores:
            if base and not rel.startswith(base + "/"):
                continue
            sub = rel[len(base) + 1:] if base else rel
            parts = sub.split("/")
            for raw in patterns:
                neg = raw.startswith("!")
                p = raw[1:] if neg else raw
                p = p.rstrip("/")
                if not p:
                    continue
                if "/" in p.strip("/"):
                    pat = p.lstrip("/")
                    hit = fnmatch.fnmatchcase(sub, pat) or sub.startswith(pat + "/")
                elif p.startswith("/"):
                    hit = fnmatch.fnmatchcase(parts[0], p[1:])
                else:
                    hit = any(fnmatch.fnmatchcase(x, p) for x in parts)
                if hit:
                    result = not neg
        return result


GLOBAL_LIMIT = re.compile(r"\.use\(\s*(?:[\w$]*(?:[lL]imit|[tT]hrottl)\w*\s*[,)]|(?:new\s+)?[\w$.]*[rR]ate_?[lL]imit\w*\s*\(|"
                          r"slowDown\s*\()|default_limits|AXES_|DEFAULT_THROTTLE|throttle_classes")
PATH_LIMIT = re.compile(r"\.use\(\s*(['\"`])(/[^'\"`]*)\1\s*,\s*[^;\n]{0,200}?(?:[lL]imit|[tT]hrottl)")
SERVER_DIR = re.compile(r"(?:^|/)(?:server|servers|api|backend|functions|lambdas?|workers?|edge|lib/server|scripts|prisma|"
                        r"db|migrations|supabase|netlify|routes/api|middleware)/", re.I)


NODE_SERVER = re.compile(r"\bmodule\.exports\b|\brequire\(\s*['\"](?:express|koa|fastify|hapi|@hapi/hapi|mongoose|"
                         r"sequelize|pg|mysql2?|fs|child_process|path|http)['\"]\s*\)|\(\s*req\s*,\s*res\b")


def _is_client(rel: str, text: str, kinds: set[str], spa_roots: tuple[str, ...] = ("",)) -> bool:
    low = rel.lower()
    name = posixpath.basename(low)
    ext = posixpath.splitext(name)[1]
    if USE_CLIENT.match(text):
        return True
    if USE_SERVER.match(text) or re.search(r"\.server\.|\+server\.|hooks\.server\.|(?:^|/)middleware\.[jt]s$", low):
        return False
    if ext in (".html", ".htm") and not re.search(r"(?:^|/)templates?/", low):
        return True
    if ext in (".vue", ".svelte"):
        return not SERVER_DIR.search(low)
    if re.search(r"(?:^|/)(?:public|static)/", low) and ext in (".js", ".mjs"):
        return True
    if ext not in JS_EXT:
        return False
    if "extension" in kinds or "expo" in kinds:
        return not SERVER_DIR.search(low)
    if kinds & {"vite", "cra"} and "next" not in kinds and not SERVER_DIR.search(low) and not NODE_SERVER.search(text):
        # only inside the browser app's own folder: a backend next to a frontend/ is not browser code
        for root in spa_roots:
            sub = low[len(root) + 1:] if root else low
            if root and not low.startswith(root.lower() + "/"):
                continue
            if re.match(r"src/", sub) or sub in ("main.tsx", "main.jsx", "main.ts", "main.js"):
                return True
    return False


IMPORT_SPEC = re.compile(r"(?:\bfrom\s*|\bimport\s*\(\s*|\brequire\s*\(\s*|^[ \t]*import\s+)(['\"`])([^'\"`\n]{1,200})\1",
                         re.M)
DYNAMIC_IMPORTS = re.compile(r"import\.meta\.glob|require\.context\s*\(")
ENTRY_FILE = re.compile(r"(?:^|/)(?:main|index|App|app|server|entry[\w.-]*|_app|_document|root|layout|sw|"
                        r"service-worker|worker|setupTests)\.[\w]+$|\.config\.[\w]+$|(?:^|/)\+[\w.]+$")
ENTRY_DIR = re.compile(r"(?:^|/)(?:app|pages|routes|api|functions|supabase|server|servers|backend|middleware|scripts|"
                       r"bin|netlify|electron|extension|background|content)/")
JS_SPEC_EXT = re.compile(r"\.(?:[cm]?[jt]sx?|vue|svelte|astro)$")


def _aliases(files: dict[str, str]) -> list[tuple[str, str, str]]:
    """(folder the alias applies under, prefix, target folder) from tsconfig/jsconfig paths, plus the usual ones."""
    out = []
    for rel, text in files.items():
        if re.fullmatch(r"(?:.*/)?[tj]sconfig(?:\.\w+)?\.json", rel):
            base = posixpath.dirname(rel)
            for m in re.finditer(r'"([^"*\s]*)\*"\s*:\s*\[\s*"([^"*]*)\*"', text):
                out.append((base, m.group(1), posixpath.normpath(posixpath.join(base, m.group(2) or "."))))
    roots = {posixpath.dirname(r) for r in files if posixpath.basename(r) == "package.json"} or {""}
    for root in roots:
        for prefix, target in (("@/", "src"), ("~/", "src"), ("$lib/", "src/lib"), ("src/", "src")):
            out.append((root, prefix, posixpath.normpath(posixpath.join(root, target))))
    return sorted(out, key=lambda a: (-len(a[0]), -len(a[1])))


def _dead_files(srcs: dict[str, Src], kinds: set[str]) -> set[str]:
    """Client files nothing in the app reaches: walk the imports from every entry point (server code, framework
    routes and pages, main/index/App files) and return the browser files never reached."""
    js = {r: s for r, s in srcs.items() if s.lang == "js" and not s.test}
    if len(js) < 2 or any(DYNAMIC_IMPORTS.search(s.text) for s in js.values()):
        return set()
    spa = bool(kinds & {"vite", "cra"}) and "next" not in kinds
    key = {}
    for r in js:
        k = JS_SPEC_EXT.sub("", r)
        key.setdefault(k, []).append(r)
        if posixpath.basename(k) == "index":
            key.setdefault(posixpath.dirname(k), []).append(r)

    def candidate(r: str, s: Src) -> bool:
        if ENTRY_FILE.search(r):
            return False
        if spa and re.search(r"(?:^|/)src/pages/", r):
            return True  # an app with a client router imports its pages
        return not ENTRY_DIR.search(r) and (s.client or bool(re.search(r"(?:^|/)(?:components|hooks|views|features|"
                                                                          r"widgets|ui)/", r)))

    cands = {r for r, s in js.items() if candidate(r, s)}
    if not cands or len(cands) == len(js):
        return set()
    aliases = _aliases({r: s.text for r, s in srcs.items()})
    tails: set[str] = set()
    reached, todo = set(), [r for r in js if r not in cands]
    while todo:
        r = todo.pop()
        if r in reached:
            continue
        reached.add(r)
        for m in IMPORT_SPEC.finditer(js[r].text):
            spec = m.group(2).split("?")[0]
            if spec.startswith("."):
                target = posixpath.normpath(posixpath.join(posixpath.dirname(r), spec))
            else:
                hit = next(((p, t) for base, p, t in aliases if spec.startswith(p) and
                            (not base or r.startswith(base + "/"))), None)
                if not hit:
                    tails.add("/".join(spec.split("/")[-2:]))
                    continue
                target = posixpath.normpath(posixpath.join(hit[1], spec[len(hit[0]):]))
            for f in key.get(JS_SPEC_EXT.sub("", target), ()):
                if f not in reached:
                    todo.append(f)
    dead = cands - reached
    return {r for r in dead if not any(JS_SPEC_EXT.sub("", r).endswith("/" + t) for t in tails if "/" in t)}


def _project(files: dict[str, str], git: dict | None, reach: bool = True) -> Project:
    deps: set[str] = set()
    kinds: set[str] = set()
    for rel, text in files.items():
        name = posixpath.basename(rel)
        if name == "package.json":
            try:
                data = json.loads(text)
            except ValueError:
                continue
            for key in ("dependencies", "devDependencies", "peerDependencies"):
                if isinstance(data.get(key), dict):
                    deps.update(data[key])
        elif name == "manifest.json" and '"manifest_version"' in text:
            kinds.add("extension")
        elif name in ("requirements.txt", "pyproject.toml"):
            deps.update(re.findall(r"^\s*([A-Za-z][\w.-]*)", text, re.M))
        if re.match(r"(?:.*/)?next\.config\.[cm]?[jt]s$", rel):
            kinds.add("next")
        if re.match(r"(?:.*/)?vite\.config\.[cm]?[jt]s$", rel):
            kinds.add("vite")
        if rel.startswith("supabase/") or "/supabase/" in rel:
            kinds.add("supabase")
    for dep, kind in (("next", "next"), ("vite", "vite"), ("react-scripts", "cra"), ("expo", "expo"),
                      ("@supabase/supabase-js", "supabase"), ("@supabase/ssr", "supabase"), ("supabase", "supabase")):
        if dep in deps:
            kinds.add(kind)
    spa_roots = sorted({posixpath.dirname(r) for r, t in files.items()
                        if re.match(r"(?:.*/)?vite\.config\.[cm]?[jt]s$", r)
                        or (posixpath.basename(r) == "package.json" and re.search(r'"(?:vite|react-scripts)"\s*:', t))},
                       key=len, reverse=True) or [""]
    srcs = {}
    for rel, text in files.items():
        lang = _lang(rel)
        srcs[rel] = Src(rel, text, lang, _is_client(rel, text, kinds, tuple(spa_roots)), bool(TEST_PATH.search(rel)))
    if reach:
        for rel in _dead_files(srcs, kinds):
            srcs[rel].dead = True
    middleware = "\n".join(s.text for r, s in srcs.items()
                           if re.search(r"(?:^|/)middleware\.[cm]?[jt]s$", r) and "node_modules" not in r)
    global_limit = bool(re.search(r"(?i)ratelimit|rate_limit|limiter|throttl", middleware)) or any(
        GLOBAL_LIMIT.search(s.text) for s in srcs.values() if s.lang in ("js", "py") and not s.test)
    limited = sorted({m.group(2) for s in srcs.values() if s.lang == "js" and not s.test
                      for m in PATH_LIMIT.finditer(s.text)})
    ignores = []
    for rel, text in sorted(files.items()):
        if posixpath.basename(rel) == ".gitignore":
            base = posixpath.dirname(rel)
            ignores.append((base, [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]))
    return Project(srcs, deps, kinds, middleware, global_limit, git, ignores, limited)


# ------------------------------------------------------------------------------------------------ 1. XSS

SANITIZED = re.compile(r"(?i)sanitiz|purif|escape|encode|\bxss\s*\(|bleach\.clean|markupsafe|strip_?tags|insane\s*\(")
USERISH = re.compile(r"(?i)\b(?:user(?:name)?|display_?name|bio|comment|message|review|nickname|query|search|input|q)\b")
LITERAL = re.compile(r"""^\s*(?:(['"])[^'"\n]*\1|`[^`$]*`)\s*;?\s*$""")


SAFE_HTML = re.compile(r"renderToString|renderToStaticMarkup|sanitiz|purif|escape")
DOM_SOURCE = re.compile(r"location\.(?:hash|search|href)|document\.(?:URL|referrer|cookie)|URLSearchParams|"
                        r"\.searchParams\b|window\.name")


def _safe_html(value: str, text: str) -> bool:
    """A value that cannot carry a visitor's markup: a literal, a constant, a ternary of literals, or a name that holds
    React-rendered or sanitized HTML."""
    v = value.strip().rstrip(";,").strip()
    if not v or LITERAL.match(v) or SANITIZED.search(v) or v in ("''", '""', "``"):
        return True
    if v.startswith("Object.entries(THEMES)"):
        return True  # the stock shadcn/ui ChartStyle: CSS variables from the developer's chart config
    if re.fullmatch(r"[A-Z][A-Z0-9_]*", v):
        return True
    if re.fullmatch(r"[^?]{1,200}\?\s*(['\"`])[^'\"`$]*\1\s*:\s*(['\"`])[^'\"`$]*\2", v):
        return True
    if re.fullmatch(r"[\w$]+", v):
        d = re.search(rf"(?:const|let|var)\s+{re.escape(v)}\s*(?::[^=\n]{{1,60}})?=\s*([^;\n]{{0,200}})", text)
        if d and (SAFE_HTML.search(d.group(1)) or LITERAL.match(d.group(1))):
            return True
    return False


def _xss(src: Src, out: Out) -> None:
    text = src.text
    if src.lang in ("js", "py"):
        for m in re.finditer(r"\bautoescape\s*[:=]\s*(?:false|False)\b|\bnoEscape\s*:\s*true\b", text):
            out.add(R_XSS, "medium", src, m.start(), "the template engine's escaping is switched off, so every value "
                                                     "a template prints is raw HTML")
    if src.lang == "js" or src.lang == "tmpl":
        for m in re.finditer(r"dangerouslySetInnerHTML\s*=\s*\{", text):
            value = text[m.end():_close(text, m.end() - 1) - 1]
            value = re.sub(r"^\s*\{\s*__html\s*:\s*", "", value).rstrip(" }\n\t,")
            if _safe_html(value, text):
                continue
            sev = "high" if JS_SOURCE.search(value) or USERISH.search(value) or re.search(r"\.(?:bio|comment)", value) \
                else "medium"
            out.add(R_XSS, sev, src, m.start(), "HTML from data rendered with dangerouslySetInnerHTML")
        dom = _name_rx(re.findall(r"(?:const|let|var)\s+([\w$]+)\s*=\s*[^;\n]{0,160}?(?:" + DOM_SOURCE.pattern + ")",
                                  text))
        for m in re.finditer(r"\.(?:innerHTML|outerHTML)\s*\+?=(?!=)\s*|\binsertAdjacentHTML\s*\(\s*['\"]\w+['\"]\s*,\s*|"
                             r"\bdocument\.write(?:ln)?\s*\(\s*|\$\([^)\n]{1,80}\)\.html\s*\(\s*", text):
            value = _value_after(text, m.end())
            if _safe_html(value, text):
                continue
            sev = "high" if JS_SOURCE.search(value) or DOM_SOURCE.search(value) or (dom and dom.search(value)) \
                else "medium"
            out.add(R_XSS, sev, src, m.start(), "data inserted into the page as HTML")
        for m in re.finditer(r"\bv-html\s*=\s*\"([^\"]+)\"|\{@html\s+([^}]+)\}|bypassSecurityTrust(?:Html|Script|Url|"
                             r"ResourceUrl)\s*\(", text):
            value = m.group(1) or m.group(2) or ""
            if SANITIZED.search(value):
                continue
            out.add(R_XSS, "high" if USERISH.search(value) else "medium", src, m.start(), "raw HTML rendering")
    if src.lang == "tmpl":
        for m in re.finditer(r"\{\{[^{}\n]{1,200}\|\s*safe\b[^{}\n]*\}\}|\{%-?\s*autoescape\s+(?:false|off)\s*-?%\}|"
                             r"<%-(?!\s*include\b)[^%]{1,200}%>|\{\{\{[^}\n]{1,200}\}\}\}|\{!![^!\n]{1,200}!!\}|"
                             r"<\?=?\s*(?:echo\s+)?\$_(?:GET|POST|REQUEST|COOKIE)\b", text):
            token = m.group(0)
            if re.match(r"\{\{\s*form\.\w+\s*\|\s*safe\s*\}\}", token):
                continue  # a Django form field renders its widget, escaping the value itself
            if re.match(r"<%-\s*(?:body|defineContent\s*\(|contentFor\s*\(|blocks?\.|script|style)\b", token):
                continue  # the layout slot (express-ejs-layouts): the view that was rendered, escaped, already
            sev = "high" if USERISH.search(token) or "$_" in token else "medium"
            out.add(R_XSS, sev, src, m.start(), "template prints a value without escaping it")
    if src.lang == "py":
        for m in re.finditer(r"\b(?:Markup|mark_safe|SafeString|render_template_string)\s*\(", text):
            arg = _call_args(text, m.end() - 1, py=True)
            if re.match(r"\s*[rbuRBU]*['\"][^'\"{}%]*['\"]\s*$", arg) or SANITIZED.search(arg):
                continue
            if re.match(r"\s*[rR]?[fF]['\"]", arg) or re.search(r"\.format\(|%\s*[\w(]|\+", arg) or PY_SOURCE.search(arg):
                out.add(R_XSS, "high", src, m.start(), "HTML or a template built from data and marked safe")


def _xss_handler(h: Handler, out: Out) -> None:
    text, t = h.src.text, h.taint
    if h.src.lang == "js":
        for m in re.finditer(r"\bres\.(?:send|write|end)\s*\(", text[h.start:h.end]):
            pos = h.start + m.end() - 1
            arg = _call_args(text, pos)
            if not re.search(r"<[a-zA-Z]", arg) or SANITIZED.search(arg):
                continue
            parts = _interpolations(arg.strip()) if arg.strip().startswith("`") else re.split(r"\+", arg)[1:]
            if any(t.touches(p) and not SANITIZED.search(p) for p in parts):
                out.add(R_XSS, "high", h.src, h.start + m.start(), "request data written into an HTML response")
    else:
        for m in re.finditer(r"\breturn\s+[rR]?[fF](['\"]{1,3})", text[h.start:h.end]):
            line = h.src.line_text(h.start + m.start())
            if not re.search(r"<[a-zA-Z]", line):
                continue
            if any(t.touches(p) and not SANITIZED.search(p) for p in _interpolations(line)):
                out.add(R_XSS, "high", h.src, h.start + m.start(), "request data written into an HTML response")


# ------------------------------------------------------------------------------------------------ 2. IDOR

PRIVATE = re.compile(r"(?i)order|invoice|payment|message|document|\bdocs?\b|file|note|profile|account|\busers?\b|address|"
                     r"ticket|chat|conversation|booking|reservation|transaction|subscription|receipt|attachment|upload|"
                     r"appointment|patient|contact|card|wallet|secret|statement|record|submission|draft|journal|diary|"
                     r"medical|health|private|inbox|basket|cart|allocation|benefit|salary|payroll|memo")
JS_LOOKUP = re.compile(r"\.\s*(findUnique(?:OrThrow)?|findFirst(?:OrThrow)?|findById(?:AndUpdate|AndDelete|AndRemove)?|"
                       r"findOne(?:AndUpdate|AndDelete|AndRemove)?|findByPk|findOneBy|find|update|delete|destroy|"
                       r"deleteOne|updateOne|remove|(?:get|find|fetch|load)\w*By\w*)\s*\(")
ID_KEY = re.compile(r"\b(?:id|_id|uuid|pk|slug)\b|[a-z]Id\b|_id\b")
OWNER_ARG = re.compile(r"(?i)\b(?:user_?id|owner(?:_?id)?|author(?:_?id)?|created_?by|tenant_?id|org(?:anization)?_?id|"
                       r"team_?id|account_?id|workspace_?id|customer_?id|member(?:_?id|s)?|uid|user)\s*:")
ACCESS_HELPER = re.compile(r"(?i)\b(?:verify|check|assert|ensure|require|can|has|is|user)\w*(?:access|owner|ownership|"
                           r"permission|authori[sz]ed|allowed|owns)\w*\s*\(")
ADMIN_GUARD = re.compile(r"(?i)admin|superuser|staff|accounting|\brole|permission")
OWNER_CHECK = re.compile(
    r"\.(?:user_?[iI]d|owner(?:_?[iI]d)?|author_?[iI]d|created_?[bB]y|tenant_?[iI]d|org_?[iI]d|organization_?[iI]d|"
    r"team_?[iI]d|account_?[iI]d|workspace_?[iI]d|customer_?[iI]d|uid)\s*(?:!==?|===?)|(?:!==?|===?)\s*[\w$.?]*\."
    r"(?:user_?[iI]d|owner(?:_?[iI]d)?|author_?[iI]d|uid)\b|\b(?:authorize|assertOwner\w*|checkOwnership|isOwner|"
    r"canAccess|checkAccess|requireOwner\w*|ability\.can|enforce)\b|\bcan\s*\(|\b(?:isAdmin|is_admin|requireAdmin|"
    r"admin_required|requireRole)\b|role\s*(?:!==?|===?)")
MUTATION = re.compile(r"(?i)update|delete|destroy|remove")
PY_LOOKUPS = (
    re.compile(r"\b(\w+)\.query\.(?:get|get_or_404)\(\s*(\w+)\s*\)"),
    re.compile(r"\bget_object_or_404\(\s*(\w+)\s*,\s*(?:pk|id)\s*=\s*(\w+)\s*\)"),
    re.compile(r"\b(\w+)\.objects\.get\(\s*(?:pk|id)\s*=\s*(\w+)\s*\)"),
    re.compile(r"\b(?:session|db|db\.session)\.get\(\s*(\w+)\s*,\s*(\w+)\s*\)"),
    re.compile(r"\b(\w+)\.query\.filter_by\(\s*id\s*=\s*(\w+)\s*\)"),
    re.compile(r"\bselect\(\s*(\w+)\s*\)\.where\(\s*\w+\.id\s*==\s*(\w+)\s*\)"),
    re.compile(r"\b(\w+)\.find_one\(\s*\{\s*['\"]_id['\"]\s*:\s*(?:ObjectId\()?(\w+)"),
)
PY_OWNER = re.compile(
    r"\b(?:user_id|owner_id|author_id|owner|author|created_by|tenant_id|org_id|organization_id|team_id|account_id|"
    r"workspace_id|customer_id|user)\s*(?:==|!=|=)|\.(?:user|owner|author)(?:_id)?\s*(?:==|!=|is\b)|(?:==|!=)\s*"
    r"(?:current_user|request\.user|g\.user)\b|\b(?:has_perm|has_object_permission|check_object_permissions|"
    r"PermissionDenied|Forbidden|is_admin|is_staff|is_superuser|admin_required)\b|abort\(\s*403")
DRF_VIEW = re.compile(r"^class\s+\w+\s*\(([^)]*(?:ModelViewSet|ReadOnlyModelViewSet|RetrieveAPIView|RetrieveUpdateAPIView|"
                      r"RetrieveDestroyAPIView|RetrieveUpdateDestroyAPIView|UpdateAPIView|DestroyAPIView|"
                      r"GenericViewSet)[^)]*)\)\s*:", re.M)


def _idor(h: Handler, project: Project, out: Out) -> None:
    text, body, t = h.src.text, h.body, h.taint
    context = body + "\n" + h.guards
    if ADMIN_GUARD.search(h.guards) or ACCESS_HELPER.search(body) or project.role_call(context):
        return  # admins may reach any record; an access helper is the owner check
    if h.src.lang == "js":
        if OWNER_CHECK.search(context):
            return
        for m in JS_LOOKUP.finditer(body):
            name = m.group(1)
            args = _no_comments(_call_args(text, h.start + m.end() - 1)).strip()
            where = re.search(r"\bwhere\s*:\s*\{", args)
            if where:
                selector = args[where.end() - 1:_close(args, where.end() - 1)]
            else:
                selector = _value_after(args, 0)
                receiver = re.search(r"([\w$.]+)\s*$", body[:m.start()])
                last = receiver.group(1).split(".")[-1] if receiver else ""
                if name == "find" and not selector.startswith("{"):
                    continue  # Array.prototype.find
                if MUTATION.fullmatch(name) or name in ("deleteOne", "updateOne", "find"):
                    model = last[:1].isupper() or re.search(r"(?i)collection|model|dao|repo|table|store", last) or \
                        (receiver and receiver.group(1).startswith(("db.", "prisma.", "this.prisma", "ctx.db")))
                    if not model:
                        continue  # an instance's own update: record.update({...})
            code = _code_only(selector)
            if not (ID_KEY.search(code) or ID_KEY.search(name)) or not t.touches(code) or OWNER_ARG.search(code):
                continue
            window = body[max(0, m.start() - 60):m.start()]
            mutation = bool(MUTATION.search(name)) or h.method in ("DELETE", "PUT", "PATCH")
            private = bool(PRIVATE.search(window) or PRIVATE.search(h.path) or PRIVATE.search(name))
            if mutation and (private or re.search(r"(?i)delete|destroy|remove", name) or h.method == "DELETE"):
                sev = "high"
            elif mutation or private:
                sev = "medium"
            else:
                continue
            what = "changes or deletes" if mutation else "returns"
            out.add(R_IDOR, sev, h.src, h.start + m.start(), f"{h.where} {what} a record by the ID it is sent, with "
                                                               "no check that it belongs to the signed-in user")
            return
    else:
        if PY_OWNER.search(context):
            return
        for rx in PY_LOOKUPS:
            for m in rx.finditer(body):
                model, arg = m.group(1), m.group(2)
                if arg not in t.names:
                    continue
                mutation = h.method in ("DELETE", "PUT", "PATCH") or bool(re.search(r"\.delete\(|\bdelete\(", body))
                if not mutation and not PRIVATE.search(model + " " + h.path):
                    continue
                out.add(R_IDOR, "high" if mutation else "medium", h.src, h.start + m.start(),
                        f"{h.where} looks up {model} by the ID in the request with no check that it belongs to the "
                        "signed-in user")
                return


def _drf(src: Src, out: Out) -> None:
    for m in DRF_VIEW.finditer(src.text):
        end = _close_class(src.text, m)
        cls = src.text[m.start():end]
        q = re.search(r"\bqueryset\s*=\s*(\w+)\.objects\.all\(\)", cls)
        if not q or re.search(r"def\s+get_(?:queryset|object)\b", cls):
            continue
        perms = re.search(r"permission_classes\s*=\s*[\[(]([^\])]*)", cls)
        named = set(re.findall(r"\w+", perms.group(1))) if perms else set()
        if named - {"IsAuthenticated", "AllowAny", "IsAuthenticatedOrReadOnly", "permissions"}:
            continue
        writes = "ReadOnly" not in m.group(1) and not re.search(r"Retrieve(?:API)?View\b", m.group(1))
        private = bool(PRIVATE.search(q.group(1)))
        if not private and not writes:
            continue
        out.add(R_IDOR, "high" if private and writes else "medium", src, m.start() + q.start(),
                f"{q.group(1)}.objects.all() is served by ID to any user the permission classes let in; filter it by "
                "owner in get_queryset")


# ------------------------------------------------------------------------------------------------ 3. admin routes

ROLE = re.compile(
    r"(?i)\b(?:is_?admin|requireAdmin|require_admin|adminOnly|admin_only|ensureAdmin|checkAdmin|verifyAdmin|withAdmin|"
    r"admin_required|isSuperuser|is_superuser|is_staff|staff_member_required|superuser_required|has_?role|"
    r"roles?_required|require_?role|checkRole|IsAdminUser|has_perm|permission_required|authorize)\b|\.role\b|"
    r"\brole\s*(?:!==?|===?|==|!=|\bin\b)|roles?\.includes\s*\(|['\"]admin['\"]|\brequireRoles?\b|\bpermissions?\b")
AUTH = re.compile(
    r"(?i)\b(?:requireAuth\w*|require_?auth\w*|isAuthenticated|is_authenticated|ensureAuth\w*|authenticate\w*|"
    r"login_required|jwt_required|verify_?token|verifyJWT|getServerSession|getSession|currentUser|current_user|withAuth|"
    r"clerkMiddleware|auth\.protect|getAuth|requireUser|protect|passport|get_current_user|getUser|auth)\b")
DB_ACCESS = re.compile(r"\b(?:prisma|db|knex|sql|pool|supabaseAdmin|mongoose|drizzle)\s*\.\s*\w+|\.from\(\s*['\"]|"
                       r"\b[A-Z]\w*\.(?:find\w*|query|objects|all)\b")
ADMIN_PATH = re.compile(r"(?i)(?:^|/)admin(?:/|$|[^\w])")


CALL = re.compile(r"(?<![\w$.])([\w$]+)\s*\(\s*(\))?")
JS_FN_DEF = re.compile(r"(?<![\w$.])(?:async\s+)?function\s*\*?\s*([\w$]+)\s*(?=\()"
                       r"|(?<![\w$.])(?:const|let|var)\s+([\w$]+)\s*(?::[^=\n]{1,80})?=\s*(?:async\s+)?"
                       r"(?:function\s*[\w$]*\s*)?(?=\()")
DECIDE = re.compile(r"\b(?:if|return|assert|throw|raise|abort|unless|elif|redirect|unauthori[sz]ed|forbidden)\b|"
                    r"\?\?|&&|\|\||\b40[13]\b")
NOT_HELPER = {"GET", "POST", "PUT", "PATCH", "DELETE", "handler", "default", "get", "post", "use", "main", "render",
              "middleware", "app", "route", "next"}


def _statement(expr: str) -> str:
    """An arrow function's expression body up to the end of its statement: the first line break outside brackets
    (code without semicolons would otherwise run on into the next function)."""
    depth = 0
    for i, ch in enumerate(expr):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth < 0:
                return expr[:i]
        elif ch in "\n;" and depth <= 0 and expr[:i].strip():
            return expr[:i]
    return expr


def _role_functions(project: Project) -> dict[str, bool]:
    bodies: dict[str, list[tuple[str, bool]]] = defaultdict(list)
    for s in project.srcs.values():
        if s.test or s.lang not in ("js", "py") or s.client:
            continue
        text = s.text
        if s.lang == "js":
            for m in JS_FN_DEF.finditer(text):
                name = m.group(1) or m.group(2)
                span = _fn_span(text, m.end())
                if span and len(name) > 2 and name not in NOT_HELPER:
                    body = text[span[0]:span[1]]
                    if not body.lstrip().startswith("{"):
                        body = "return " + _statement(body)  # an arrow function's expression is what it returns
                    bodies[name].append((body, bool(span[2].strip())))
        else:
            for m in PY_DEF.finditer(text):
                if m.group(2) in NOT_HELPER or len(m.group(2)) <= 2:
                    continue
                start, end, params = _py_def_span(text, m)
                params = [p for p in _py_params(params) if p not in ("self", "cls")]
                bodies[m.group(2)].append((text[start:end], bool(params)))
    role: dict[str, bool] = {}
    for name, defs in bodies.items():
        for body, takes in defs:
            if any(ROLE.search(ln) and DECIDE.search(ln) for ln in body.splitlines()):
                role[name] = takes
    for _ in range(2):  # a helper that calls a role check is one too
        for name, defs in bodies.items():
            if name in role:
                continue
            for body, takes in defs:
                if any(c.group(1) in role and c.group(1) != name and DECIDE.search(body) for c in CALL.finditer(body)):
                    role[name] = takes
    return role


USER_LIST = re.compile(r"\b(?:User|Users|UserModel|userModel|db\.users?|db\.User|models\.User|prisma\.user)\s*\.\s*"
                       r"(?:find|findAll|findMany)\s*\(\s*(?:\{\s*\})?\s*[,)]|\bUser\.objects\.all\(\)|"
                       r"\bUser\.query\.all\(\)|\bquery\(\s*User\s*\)\.all\(\)")


def _user_list(h: Handler, project: Project, out: Out) -> None:
    """An admin function without /admin in its path: every user account, to anyone who can call the route."""
    if h.kind != "route" or ADMIN_PATH.search(h.path or "") or h.src.client:
        return
    body = h.body
    m = USER_LIST.search(body)
    context = h.guards + "\n" + body
    if not m or ROLE.search(context) or ADMIN_CHECK.search(context) or project.role_call(context):
        return
    # the list must reach the response: sent as it is, or put into what is sent
    line = h.src.line_text(h.start + m.start())
    held = re.search(r"([\w$]+)\s*=\s*(?:await\s+)?$", body[max(0, m.start() - 80):m.start()])
    if not held:  # UserModel.findAll().then(users => ...)
        held = re.match(r"\s*\.then\(\s*\(?\s*([\w$]+)", body[_close(body, body.find("(", m.start())):])
    sent = re.search(r"\b(?:res\.(?:json|send|render|status\([^)]*\)\.(?:json|send))|jsonify|Response|JsonResponse|"
                     r"render|return)\b", line)
    if not sent and held:
        name = re.escape(held.group(1))
        after = body[m.end():]
        sent = re.search(rf"\b(?:res\.\w+|jsonify|Response|JsonResponse|render|return)\b[^\n;]*(?<![\w$.]){name}\b"
                         rf"(?!\s*\.\s*(?:length|count))|\.\w+\s*=\s*{name}\b|\b\w+\s*:\s*{name}\b", after)
    if not sent:
        return
    out.add(R_ADMIN, "medium", h.src, h.start + m.start(), f"{h.where} hands every user account to whoever can call "
                                                           "it: listing all users is an admin function, with no admin "
                                                           "check here")


def _admin_handler(h: Handler, project: Project, out: Out) -> None:
    _user_list(h, project, out)
    if not ADMIN_PATH.search(h.path or ""):
        return
    context = h.guards + "\n" + h.body
    if h.src.lang == "js" and h.path.startswith("/") and re.search(r"(?i)admin", project.middleware) and \
            ROLE.search(project.middleware):
        return
    if h.kind == "page":
        layouts = "\n".join(s.text for r, s in project.srcs.items()
                            if posixpath.basename(r).startswith("layout.") and "admin" in r.lower()
                            and h.src.rel.startswith(posixpath.dirname(r) + "/"))
        if (ROLE.search(layouts) or project.role_call(layouts)) and not USE_CLIENT.match(layouts):
            return
        if ROLE.search(context) or project.role_call(context):
            if h.src.client:
                out.add(R_ADMIN, "low", h.src, -1, f"{h.path} checks the role only in the browser; make sure every "
                                                   "admin API checks it on the server too")
            return
        if h.src.client or not DB_ACCESS.search(h.body):
            # a page that loads nothing on the server gives nothing away: what it shows comes from APIs and
            # database policies, which are checked on their own
            out.add(R_ADMIN, "low", h.src, -1, f"{h.path} has no role check; whatever it loads must check the role "
                                               "on the server or in the database policies")
            return
        out.add(R_ADMIN, "high", h.src, -1, f"anyone who types {h.path} gets the admin page: no role check on the "
                                            "server")
        return
    if ROLE.search(context) or project.role_call(context):
        return
    if AUTH.search(context):
        out.add(R_ADMIN, "medium", h.src, h.start, f"{h.where} needs a sign-in but no admin role: any user gets in")
    else:
        out.add(R_ADMIN, "high", h.src, h.start, f"{h.where} has no sign-in or role check: anyone gets in")


JS_IMPORT = r"(?:import\s+(?:\*\s+as\s+)?{n}\s+from\s*|(?:const|let|var)\s+{n}\s*=\s*require\(\s*)(['\"`])(\.[^'\"`]+)\1"


def _resolve(src: Src, spec: str, project: Project) -> Src | None:
    base = posixpath.normpath(posixpath.join(posixpath.dirname(src.rel), spec))
    for cand in [base] + [base + e for e in (".ts", ".js", ".tsx", ".jsx", ".mjs", ".cjs")] + \
            [base + "/index" + e for e in (".ts", ".js", ".mjs")]:
        if cand in project.srcs:
            return project.srcs[cand]
    return None


def _router_checks_role(router: Src, project: Project) -> bool:
    text = router.text
    if any(ROLE.search(g.group(1)) or project.role_call(g.group(1)) for g in JS_FILE_GUARD.finditer(text)):
        return True
    regs = [_call_args(text, text.find("(", m.start(2))) for m in JS_ROUTE.finditer(text)]
    return bool(regs) and all(ROLE.search(a) or project.role_call(a) for a in regs)


def _admin_mounts(src: Src, project: Project, out: Out) -> None:
    for m in re.finditer(r"\.use\(\s*(['\"`])(/[^'\"`]*admin[^'\"`]*)\1\s*,\s*", src.text, re.I):
        args = _call_args(src.text, src.text.find("(", m.start()))
        guards = args[args.find(",") + 1:]
        if ROLE.search(guards) or project.role_call(guards):
            continue
        names = re.findall(r"[\w$]+", guards)
        imp = re.search(JS_IMPORT.format(n=re.escape(names[-1])), src.text) if names else None
        router = _resolve(src, imp.group(2), project) if imp else None
        if router and _router_checks_role(router, project):
            continue  # every route of the mounted router checks the role itself
        sev = "medium" if AUTH.search(guards) else "high"
        out.add(R_ADMIN, sev, src, m.start(), f"routes under {m.group(2)} are mounted without a role check")


# ------------------------------------------------------------------------------------------------ 4, 13. keys

PUBLIC_ENV = re.compile(r"\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|PUBLIC|GATSBY|STORYBOOK)_[A-Z0-9_]+")
SECRET_NAME = re.compile(
    r"SECRET|SERVICE_ROLE|SERVICE_KEY|PRIVATE|PASSWORD|PASSWD|DATABASE_URL|DB_URL|POSTGRES|MONGO(?:DB)?_URI|JWT|WEBHOOK|"
    r"ADMIN_KEY|(?:OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE_AI|GROQ|MISTRAL|COHERE|REPLICATE|TOGETHER|PERPLEXITY|DEEPSEEK|"
    r"XAI|OPENROUTER|ELEVENLABS|HUGGINGFACE|HF|RESEND|SENDGRID|MAILGUN|POSTMARK|TWILIO|AWS|STRIPE_SK|"
    r"SUPABASE_SERVICE)\w*(?:KEY|TOKEN)")
PUBLIC_OK = re.compile(r"PUBLISHABLE|ANON|SITE_KEY|CLIENT_ID|MEASUREMENT|POSTHOG|SENTRY_DSN|FIREBASE_API_KEY|MAPS|MAPBOX|"
                       r"_URL$|_HOST$|_DOMAIN$")
PROVIDER_HOST = re.compile(r"api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.groq\.com|"
                           r"api\.mistral\.ai|openrouter\.ai/api|api\.elevenlabs\.io|api\.resend\.com|api\.sendgrid\.com|"
                           r"api\.stripe\.com|api\.replicate\.com|api\.together\.xyz|api\.deepseek\.com|api\.x\.ai")
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.(eyJ[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{20,}")
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
PLACEHOLDER = re.compile(r"(?i)x{5,}|\*{4,}|your|example|dummy|fake|placeholder|sample|redacted|changeme|<|>|\.\.\.|"
                         r"0{8,}|1234567")


def _key_patterns():
    from .checkup import KEY_PATTERNS

    return KEY_PATTERNS


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def _real(value: str) -> bool:
    core = re.sub(r"^[a-z]{2,8}[-_](?:[a-z]{2,8}\d{0,2}[-_])?", "", value)
    return not PLACEHOLDER.search(value) and _entropy(core) >= 3.5


def _jwt_claims(token_body: str) -> dict:
    try:
        pad = "=" * (-len(token_body) % 4)
        data = json.loads(base64.urlsafe_b64decode(token_body + pad))
    except (ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def _service_role(token_body: str) -> bool:
    """A Supabase service-role key, except the published one every local Supabase uses (issuer supabase-demo)."""
    claims = _jwt_claims(token_body)
    return claims.get("role") == "service_role" and claims.get("iss") != "supabase-demo"


AWS_SECRET = re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")


def _secrets(text: str) -> list[tuple[int, str, str]]:
    """(position, kind, first characters) of each real-looking secret in the text."""
    found = []
    for kind, rx in _key_patterns():
        for m in rx.finditer(text):
            if not _real(m.group(0)):
                continue
            if kind == "AWS" and not any(_entropy(s.group(0)) >= 4.0 for s in
                                         AWS_SECRET.finditer(text, max(0, m.start() - 400), m.end() + 400)):
                continue  # an access key ID alone (as in AWS's own examples) opens nothing without its secret
            found.append((m.start(), f"{kind} key", m.group(0)[:4]))
    for m in JWT.finditer(text):
        if _service_role(m.group(1)):
            found.append((m.start(), "Supabase service-role key", m.group(0)[:4]))
    for m in PRIVATE_KEY.finditer(text):
        found.append((m.start(), "private key", "----"))
    return found


LONG_TOKEN = re.compile(r"[A-Za-z0-9_\-+/=.]{32,}")


def _mask(line: str) -> str:
    """A line of code safe to print: every key-shaped value cut to its first four characters."""
    def cut(m: re.Match) -> str:
        return m.group(0)[:4] + "…"
    for _, rx in _key_patterns():
        line = rx.sub(cut, line)
    line = JWT.sub(cut, line)
    return LONG_TOKEN.sub(lambda m: cut(m) if _entropy(m.group(0)) >= 3.5 else m.group(0), line)


def _browser_keys(src: Src, out: Out) -> None:
    text = src.text
    if src.lang in ("js", "tmpl", "env", "other"):
        for m in PUBLIC_ENV.finditer(text):
            name = m.group(0)
            if SECRET_NAME.search(name) and not PUBLIC_OK.search(name):
                out.add(R_BROWSER_KEY, "high", src, m.start(), f"{name} is a secret, but its prefix puts it in the "
                                                               "browser bundle", evidence=name)
        if src.lang == "env":
            for m in re.finditer(r"^[ \t]*(?:export[ \t]+)?((?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|PUBLIC|"
                                 r"GATSBY)_\w+)[ \t]*=[ \t]*['\"]?([^'\"\s#]+)", text, re.M):
                if not SECRET_NAME.search(m.group(1)) and _secrets(m.group(2)) and not PUBLIC_OK.search(m.group(1)):
                    out.add(R_BROWSER_KEY, "high", src, m.start(), f"{m.group(1)} holds a secret key and is shipped to "
                                                                   "the browser", evidence=m.group(1))
    if src.lang == "js":
        for m in re.finditer(r"dangerouslyAllowBrowser\s*:\s*true", text):
            out.add(R_BROWSER_KEY, "high", src, m.start(), "the AI SDK is told to run in the browser, so its API key "
                                                           "is there too")
    if src.client:
        for m in PROVIDER_HOST.finditer(text):
            out.add(R_BROWSER_KEY, "high", src, m.start(), f"browser code calls {m.group(0)} directly, so the key that "
                                                           "call needs is in the page")
        for m in re.finditer(r"\bnew\s+(?:OpenAI|Anthropic|Groq|Stripe|Mistral|Replicate)\s*\(|service_?role|"
                             r"SERVICE_ROLE", text):
            out.add(R_BROWSER_KEY, "high", src, m.start(), "a server-only client or key is used in browser code")
        for pos, kind, head in _secrets(text):
            out.add(R_BROWSER_KEY, "critical", src, pos, f"{kind} written into browser code",
                    evidence=f"{kind} starting {head}…")


ENV_LINE = re.compile(r"^[ \t]*(?:export[ \t]+)?([A-Za-z_][\w.]*)[ \t]*=[ \t]*(.*)$", re.M)  # a value never spans lines
SECRET_PART = re.compile(r"(?i)^(?:\w*(?:api|secret|access|auth|private|client|master|signing|encryption|app|service|"
                         r"license|webhook|session)key|keys?|\w*secrets?|\w*tokens?|\w*passwords?|passwd|pwd|pass|dsn|"
                         r"private|credentials?)$")
FILLER = {"api", "key", "keys", "secret", "token", "password", "pass", "your", "my", "here", "the", "service", "server",
          "client", "id", "app", "value", "change", "me", "this", "goes"}
SELF_SECRET = re.compile(r"(?i)jwt|session|nextauth|auth_?secret|secret_?key|signing|encryption|cookie|salt|app_?key|"
                         r"csrf|hash|crypt")
TEST_VALUE = re.compile(r"(?i)^(?:sk|pk|rk)_test_|^test_|sandbox")


def _echoes_name(name: str, value: str) -> bool:
    """A placeholder that spells out the variable it fills: DISCORD_CLIENT_SECRET=discord-client-secret."""
    words = [w for w in re.split(r"[-_. ]+", value.lower()) if w]
    parts = {p.lower() for p in re.split(r"[_.\-]+", name) if p}
    return bool(words) and all(w.isalpha() for w in words) and set(words) <= parts | FILLER


def _secretish(name: str) -> bool:
    """A variable name that holds a secret, judged by its parts (SPORTS_API_HOCKEY_BASE is not a key)."""
    if re.search(r"(?i)database_?url|db_?url|connection_?string", name):
        return True
    return any(SECRET_PART.match(p) for p in re.split(r"[_.\-]+", name) if p)


def _env_secret(name: str, value: str, example: bool = False) -> str:
    """The kind of secret a NAME=value line holds, or "". In a file meant to be shared (example=True) only a key in a
    provider's own format counts: generated sample values are what such files are for."""
    value = value.strip().strip("'\"")
    if not value or "${" in value or value.startswith("$"):
        return ""
    if PUBLIC_ENV.match(name) or PUBLIC_OK.search(name):
        return ""  # meant for the browser: PAH-W004 judges what a public variable holds
    jwt = JWT.fullmatch(value)
    if jwt:
        return "Supabase service-role key" if _service_role(jwt.group(1)) else ""
    found = _secrets(value)
    if found:
        return found[0][1]
    url = re.match(r"\w+://[^:/\s]+:([^@\s]+)@([^/\s:]+)", value)
    if url:
        pw, host = url.groups()
        if not PLACEHOLDER.search(pw) and pw.lower() not in ("password", "pass", "postgres", "root", "secret", "admin") \
                and host not in ("localhost", "127.0.0.1", "db", "postgres", "mysql"):
            return "database password"
        return ""
    if not _secretish(name) or PLACEHOLDER.search(value) or _echoes_name(name, value):
        return ""
    if example:
        # a sample signing secret is what an example file is for; a third-party key that looks real may be someone's
        if SELF_SECRET.search(name) or TEST_VALUE.search(value) or len(value) < 20 or _entropy(value) < 3.5 or \
                re.fullmatch(r"[a-z]+(?:[-_ ][a-z]+)+", value):  # email-server-password describes, it is no key
            return ""
        return "possible key"
    if len(value) >= 16 and _entropy(value) >= 3.3:
        return "secret"
    return ""


def _git_state(project: Project, rel: str) -> str:
    """tracked, untracked (not ignored), ignored, or none (no git): where a file stands."""
    git = project.git
    if git is None:
        return "ignored" if project.ignored(rel) else "none"
    if rel in git["tracked"]:
        return "tracked"
    if rel in git["untracked"]:
        return "untracked"
    return "ignored"


def _secret_files(project: Project, out: Out) -> None:
    for rel, src in project.srcs.items():
        name = posixpath.basename(rel)
        if src.lang == "env":
            example = bool(ENV_EXAMPLE.search(name))
            found = [(m.start(), _env_secret(m.group(1), m.group(2), example)) for m in ENV_LINE.finditer(src.text)]
            found = [(pos, kind) for pos, kind in found if kind]
            state = _git_state(project, rel)
            if example:
                for pos, kind in found:
                    if kind == "possible key":
                        out.add(R_SECRET, "medium", src, pos, f"{name} is meant to be shared, but this value looks "
                                                              "like a real key, not a sample", evidence=f"{kind} in {name}")
                    else:
                        out.add(R_SECRET, "high", src, pos, f"{name} is meant to be shared, but holds a real {kind}",
                                evidence=f"{kind} in {name}")
                continue
            if state == "tracked":
                if found:
                    out.add(R_SECRET, "high", src, found[0][0], f"{rel} is committed to git with {len(found)} "
                                                                f"secret(s) in it", evidence=f"{found[0][1]} in {name}")
                else:
                    out.add(R_SECRET, "low", src, -1, f"{rel} is committed to git; keep .env files out of it",
                            evidence=name)
            elif found and state in ("untracked", "none"):
                where = "is not in .gitignore" if state == "none" else "is not ignored by git"
                out.add(R_SECRET, "medium", src, found[0][0], f"{rel} {where}: the next `git add .` commits its "
                                                              f"{len(found)} secret(s)", evidence=f"{found[0][1]} in {name}")
            continue
        if src.client or src.lang not in ("js", "py", "tmpl", "other", "sql", "rules") or name.lower() in LOCKFILES:
            continue
        state = _git_state(project, rel)
        if state == "ignored":
            continue
        for pos, kind, head in _secrets(src.text):
            out.add(R_SECRET, "medium" if state == "untracked" else "high", src, pos,
                    f"{kind} written into the code" + (" (not yet committed)" if state == "untracked" else ""),
                    evidence=f"{kind} starting {head}…")
    git = project.git
    if git:
        for rel in sorted(git.get("history", ())):
            name = posixpath.basename(rel)
            if ENV_NAME.match(name) and not ENV_EXAMPLE.search(name) and rel not in git["tracked"]:
                stub = project.srcs.get(rel) or Src(rel, "", "env", test=bool(TEST_PATH.search(rel)))
                out.add(R_SECRET, "high", stub, -1, f"{rel} was committed in the past and is still in git history; "
                                                    "rotate every key it held", evidence=f"{rel} in history")


# ------------------------------------------------------------------------------------------------ 5. prompt injection

LLM_CALL = re.compile(r"chat\.completions\.create|responses\.create|messages\.create|\bgenerateText\s*\(|"
                      r"\bstreamText\s*\(|\bgenerateObject\s*\(|ChatOpenAI|ChatAnthropic|ChatGoogleGenerativeAI|"
                      r"generate_content|generateContent|\bcompletion\s*\(|litellm|createChatCompletion|\.invoke\s*\(|"
                      r"ollama\.chat")
OUT_JS = re.compile(r"(?:const|let|var)\s+(\{[^{};]{0,200}\}|[\w$]+)\s*=\s*[^;\n]{0,200}?(?:choices\s*\[\s*0\s*\]\s*\."
                    r"\s*message\s*\??\.\s*content|\.content\s*\[\s*0\s*\]\s*\??\.\s*text|\.output_text\b|"
                    r"\bgenerateText\s*\(|\bgenerateObject\s*\(|\bcompletion\.content\b)")
OUT_PY = re.compile(r"^[ \t]*(\w+)\s*=\s*[^\n]{0,200}?(?:choices\s*\[\s*0\s*\]\s*\.\s*message\s*\.\s*content|"
                    r"\.content\s*\[\s*0\s*\]\s*\.\s*text|\.output_text\b|\bresponse\.text\b)", re.M)
SINK_JS = re.compile(r"(?<![\w$.])(?:eval|Function|execSync|exec|spawnSync|spawn|execFile|execFileSync)\s*\(|"
                     r"\bnew\s+Function\s*\(|\bvm\.run\w*\s*\(|\.(?:query|execute|raw|unsafe|\$queryRawUnsafe|"
                     r"\$executeRawUnsafe)\s*\(|\.innerHTML\s*=(?!=)|\bdocument\.write\s*\(")
SINK_PY = re.compile(r"(?<![\w.])(?:eval|exec)\s*\(|\bos\.(?:system|popen)\s*\(|\bsubprocess\.\w+\s*\(|"
                     r"\.execute(?:script)?\s*\(|\b(?:Markup|mark_safe|render_template_string)\s*\(")
SYS_JS = re.compile(r"role\s*:\s*['\"]system['\"]\s*,\s*content\s*:|\bsystem\s*:|\bsystem_?[pP]rompt\s*[:=](?!=)|"
                    r"\binstructions\s*:")
SYS_PY = re.compile(r"['\"]role['\"]\s*:\s*['\"]system['\"]\s*,\s*['\"]content['\"]\s*:|\bsystem(?:_prompt|_message)?\s*"
                    r"=(?!=)|\binstructions\s*=(?!=)")
TOOLS = re.compile(r"\btools\s*[:=]|@tool\b|\btool\s*\(\s*\{|function_declarations|\bfunctions\s*:")
SHELL = re.compile(r"child_process|\bexecSync\s*\(|(?<![\w$.])exec\s*\(|\bspawn\s*\(|\bsubprocess\.|\bos\.system\s*\(")


POWER_TOOLS = re.compile(r"SQLDatabaseToolkit|create_sql_agent|QuerySQLData[bB]ase\w*Tool|PythonREPL\w*|"
                         r"PythonAstREPLTool|ShellTool|BashProcess|TerminalTool|create_pandas_dataframe_agent|"
                         r"create_csv_agent|PythonInterpreterTool|\bcode_interpreter\b")
AGENT = re.compile(r"create_react_agent|AgentExecutor|initialize_agent|\bcreate_\w*agent\s*\(|\bStateGraph\b|"
                   r"\.bind_tools\s*\(|\bAgent\s*\(")


def _prompt_file(src: Src, out: Out) -> None:
    text = src.text
    if src.lang not in ("js", "py"):
        return
    power = POWER_TOOLS.search(text)
    if power and (AGENT.search(text) or LLM_CALL.search(text)):
        out.add(R_PROMPT, "medium", src, power.start(), "the model is given a tool that runs SQL, code or shell "
                                                        "commands with the app's own access: a prompt injection in a "
                                                        "message or a document it reads runs them")
    if not LLM_CALL.search(text):
        return
    py = src.lang == "py"
    names = set()
    for m in (OUT_PY if py else OUT_JS).finditer(text):
        names.update(_lhs_names(m.group(1)))
    direct = re.compile(r"choices\s*\[\s*0\s*\]|\.content\s*\[\s*0\s*\]\s*\.\s*text|\.output_text\b")
    rx = _name_rx(names)
    for m in (SINK_PY if py else SINK_JS).finditer(text):
        if text[m.end() - 1] == "(":
            arg = _call_args(text, m.end() - 1, py)
        else:
            arg = _value_after(text, m.end(), py)
        first = re.split(r",(?![^(\[{]*[)\]}])", arg)[0] if "query" in m.group(0) or "execute" in m.group(0) else arg
        if direct.search(first) or (rx and rx.search(first)):
            out.add(R_PROMPT, "high", src, m.start(), "the model's answer is run as code, SQL or HTML; a prompt "
                                                      "injection decides what runs")
    if TOOLS.search(text) and SHELL.search(text):
        m = SHELL.search(text)
        out.add(R_PROMPT, "low", src, m.start(), "the model can call tools in a file that also runs shell commands: "
                                                 "if users can talk to it, an injected prompt can reach them")


def _prompt_handler(h: Handler, out: Out) -> None:
    text, t = h.src.text, h.taint
    if not LLM_CALL.search(text):
        return
    py = h.src.lang == "py"
    for m in (SYS_PY if py else SYS_JS).finditer(h.body):
        value = _value_after(text, h.start + m.end(), py)
        if value.startswith("`") or re.match(r"[rR]?[fF]['\"]", value):
            parts = _interpolations(re.sub(r"^[rR]?[fF]", "", value))
        else:
            parts = re.split(r"\+|\.format\(|%", value)[1:]
        if any(t.touches(p) for p in parts):
            out.add(R_PROMPT, "medium", h.src, h.start + m.start(), "text from the request is written into the system "
                                                                    "prompt, where it can rewrite the rules")
            return


# ------------------------------------------------------------------------------------------------ 6. mass assignment

CREATE_JS = re.compile(r"\.\s*(create|createMany|insert|insertOne|insertMany|update|updateOne|updateMany|upsert|"
                       r"findByIdAndUpdate|findOneAndUpdate|build|merge|assign)\s*\(|\bnew\s+([A-Z][\w$]*)\s*\(")
USER_MODEL = re.compile(r"(?i)user|account|profile|member|customer|admin|sign_?up|register|auth|team|org|subscription|"
                        r"order|payment|wallet|credit|plan|tenant")
PRIV_FIELD = re.compile(r"\b(role|roles|is_?admin|isAdmin|admin|is_staff|is_superuser|isSuperuser|permissions?|plan|tier|"
                        r"credits|balance|is_?verified|isVerified|email_?verified|emailVerified|is_?pro|isPro|"
                        r"is_?premium|isPremium|subscription_?status|subscriptionStatus)\s*[:=](?![=>])\s*")
NOT_MODEL = re.compile(r"^(?:Response|NextResponse|Request|Headers|URL|URLSearchParams|Date|Map|Set|WeakMap|WeakSet|Promise|"
                       r"Blob|File|FormData|TextEncoder|TextDecoder|Buffer|RegExp|Array|Object|Image|Audio|Worker|"
                       r"WebSocket|EventSource|AbortController|OpenAI|Anthropic|Stripe|Resend|Redis|Pool|Client|"
                       r"PrismaClient|Hono|Router|Proxy|Function)$|(?:Error|Exception|Response|Stream|Event|Client|"
                       r"Controller|Encoder|Decoder|Array|Observer|Builder|Parser|Formatter)$")
ADMIN_CHECK = re.compile(r"\b(?:isAdmin|is_admin|requireAdmin|admin_required|IsAdminUser|is_staff|is_superuser|hasRole|"
                         r"has_role|requireRole|checkRole)\b|role\s*(?:!==?|===?|==|!=)\s*['\"]admin|['\"]admin['\"]\s*"
                         r"(?:!==?|===?|==|!=)|roles?\.includes\(\s*['\"]admin|"
                         r"\.eq\(\s*['\"]role['\"]\s*,\s*['\"]\w*admin\w*['\"]|"  # a user_roles lookup for the admin role
                         r"!\s*[\w$.]+\.(?:admin|isAdmin|is_admin)\b")


def _mass_handler(h: Handler, out: Out, project: Project | None = None) -> None:
    text, body, t = h.src.text, h.body, h.taint
    if ADMIN_CHECK.search(body + h.guards) or (project is not None and project.role_call(body + h.guards)) or \
            _signed_webhook(h):
        return
    if h.src.lang == "js":
        whole = [r"(?:req|request|ctx\.request)\.body"] + [re.escape(n) for n in t.raw]
        whole_rx = re.compile(r"(?<![\w$.])(?:" + "|".join(whole) + r")(?![\w$]|\s*[.\[(?])")
        for m in CREATE_JS.finditer(body):
            if m.group(2) and NOT_MODEL.search(m.group(2)):
                continue
            args = _code_only(_call_args(text, h.start + m.end() - 1))
            if whole_rx.search(args):
                window = body[max(0, m.start() - 60):m.start() + 20] + " " + h.path + " " + h.src.rel
                sev = "high" if USER_MODEL.search(window) else "medium"
                out.add(R_MASS, sev, h.src, h.start + m.start(), "the whole request body is saved, so the client "
                                                                 "chooses every field, role and plan included")
                return
            for f in PRIV_FIELD.finditer(args):
                value = _value_after(args, f.end())
                if t.flows(value):
                    out.add(R_MASS, "high", h.src, h.start + m.start(), f"{f.group(1)} is set from the request")
                    return
            for name in t.names:
                if PRIV_FIELD.match(name + ":") and re.search(rf"(?<![\w$.:]){re.escape(name)}\s*[,}}]", args):
                    out.add(R_MASS, "high", h.src, h.start + m.start(), f"{name} is set from the request")
                    return
    else:
        for m in re.finditer(r"\b([A-Z]\w*|\w+\.objects\.(?:create|update_or_create|get_or_create)|\.update)\s*\(\s*"
                             r"\*\*\s*([\w.]+(?:\(\s*\))?)", body):
            arg = m.group(2)
            if PY_SOURCE.search(arg) or arg.split("(")[0] in t.raw or arg in t.names:
                window = m.group(1) + " " + h.path + " " + h.src.rel
                out.add(R_MASS, "high" if USER_MODEL.search(window) else "medium", h.src, h.start + m.start(),
                        "the whole request is unpacked into the model, so the client chooses every field")
                return
        for m in re.finditer(r"\bfor\s+(\w+)\s*,\s*\w+\s+in\s+([\w.]+(?:\(\s*\))?)\.items\(\)\s*:[^\n]*\n[^\n]*setattr\(",
                             body):
            if PY_SOURCE.search(m.group(2)) or m.group(2).split(".")[0] in t.names:
                out.add(R_MASS, "high", h.src, h.start + m.start(), "every key in the request is copied onto the record")
                return
        for f in PRIV_FIELD.finditer(body):
            if body[f.start() - 1:f.start()] in ("[", "'", '"', "."):
                continue
            value = _value_after(body, f.end(), py=True)
            if t.flows(value):
                out.add(R_MASS, "high", h.src, h.start + f.start(), f"{f.group(1)} is set from the request")
                return


def _mass_file(src: Src, out: Out) -> None:
    text = src.text
    for m in re.finditer(r"\buser_metadata\s*\??\.\s*(?:role|is_?admin|isAdmin|admin|plan|tier|is_?pro|isPro|"
                         r"subscription\w*)\b|raw_user_meta_data\s*->>?\s*'(?:role|is_admin|admin|plan|tier)'|"
                         r"auth\.jwt\(\)\s*->\s*'user_metadata'", text):
        out.add(R_MASS, "high", src, m.start(), "the role or plan is read from Supabase user_metadata, which every user "
                                                "can change for themselves")
    if src.lang == "py":
        for m in re.finditer(r"\bfields\s*=\s*['\"]__all__['\"]", text):
            model = re.findall(r"\bmodel\s*=\s*([\w.()]+)", text[max(0, m.start() - 600):m.start()])
            name = model[-1] if model else ""
            sev = "high" if re.search(r"(?i)user|account|profile|member|customer", name) else "medium"
            out.add(R_MASS, sev, src, m.start(), f"a form or serializer{' for ' + name if name else ''} accepts every "
                                                 "field of the model from the client")


# ------------------------------------------------------------------------------------------------ 7. price

PAYMENT = re.compile(r"(?i)stripe|paypal|checkout|payment|razorpay|lemonsqueezy|paddle|braintree|mollie|polar|charge|"
                     r"cart|invoice|order")
PRICE_KEY = re.compile(r"\b(unit_amount|unitAmount|amount|price|total|subtotal|amount_total|amountTotal|unitPrice|"
                       r"unit_price|cost|grand_?total|grandTotal|amount_cents|amountCents|price_cents|priceCents)"
                       r"\s*[:=](?![=>])\s*")
QTY_TOKEN = re.compile(r"[\w$.\[\]'\"]*\b(?:quantity|qty|units|seats|tickets|nights)\b[\]'\"]*")


def _price(h: Handler, out: Out) -> None:
    if not PAYMENT.search(h.src.text) or _signed_webhook(h):
        return
    body, t = h.body, h.taint
    py = h.src.lang == "py"
    for m in PRICE_KEY.finditer(body):
        if body[m.start() - 1:m.start()] in (".", "'", '"', "[") or (py and body[m.end() - 2:m.end()] == "=="):
            continue
        value = _value_after(body, m.end(), py)
        if not t.flows(QTY_TOKEN.sub("0", value)):
            continue
        key = m.group(1)
        sev = "high" if key != "amount" or re.search(r"(?i)price|total|cost", value) else "medium"
        out.add(R_PRICE, sev, h.src, h.start + m.start(), f"{key} comes from the request: the client sets what it pays")
        return


# ------------------------------------------------------------------------------------------------ 8. payment proof

VERIFY = re.compile(r"(?i)constructEvent(?:Async)?\s*\(|construct_event\s*\(|\bverify_?header\b|\bwebhooks?\.(?:verify|"
                    r"unwrap|constructEvent)\b|\bWebhook\s*\(|\bwh\.verify\s*\(|\bsvix\b|createHmac\s*\(|"
                    r"\bhmac\.(?:new|compare_digest)\b|timingSafeEqual\s*\(|compare_digest\s*\(|verify_?(?:webhook|"
                    r"signature)\w*\s*\(|validate_?(?:webhook|signature)\w*\s*\(|\bisValidSignature\b|\bunwrap\s*\(|"
                    r"verify-webhook-signature|standardwebhooks|validateEvent\s*\(|verifyPaddle\w*|"
                    r"\bwebhook\.verify\s*\(|\bverify\w*(?:signature|webhook|hmac)\w*\s*\(|"
                    r"\bsubtle\.(?:verify|sign)\s*\(")
WEBHOOK_WHERE = re.compile(r"(?i)webhook|\bipn\b|[-_/]ipn|callback")
PAY_TABLE = re.compile(r"(?i)pay|order|subscri|invoice|purchase|transaction|billing|checkout|charge|donation|credit|"
                       r"wallet|plan|premium|licen[sc]e|entitlement")
REQUEST_TABLE = re.compile(r"(?i)request|application|pending|approval|inquir")
WRITE_TABLE = re.compile(r"\.from\(\s*['\"`]([\w.-]+)['\"`]\s*\)|\b(?:collection|doc)\(\s*[\w$.]+\s*,\s*['\"`]([\w-]+)")
FULFIL = re.compile(r"(?i)paid|status|subscri|credits?|plan|premium|is_?pro|fulfil|order|license|access|balance|upgrade")
PAID_SET = re.compile(r"\b(?:paid|isPaid|is_paid|payment_?status|paymentStatus|status)\s*[:=](?![=>])\s*(?:true|True|"
                      r"['\"](?:paid|active|complete|completed|succeeded|success|pro|premium)['\"])|\b(?:is_?pro|isPro|"
                      r"premium|is_?premium|isPremium|plan|tier|credits|subscription(?:_?status|Status)?|hasPaid|"
                      r"has_paid|unlocked|isSubscribed|is_subscribed)\s*[:=](?![=>])\s*[^,}\n;=]")
PROVIDER_CHECK = re.compile(r"(?i)sessions\.retrieve|Session\.retrieve|paymentIntents\.retrieve|PaymentIntent\.retrieve|"
                            r"orders\.get|\.capture\s*\(|\bretrieve\s*\(|verifyPayment|verify_payment|getCheckout|"
                            r"checkouts\.get")
SUCCESS_PATH = re.compile(r"(?i)success|thank|callback|return|complete|confirm|paid|payment-done|verify-payment")
CLIENT_WRITE = re.compile(r"\.(?:update|upsert|insert)\s*\(|\b(?:setDoc|updateDoc|addDoc)\s*\(")


def _signed_webhook(h: Handler) -> bool:
    """A webhook whose sender's signature is checked: what it carries comes from the provider, not a visitor."""
    return bool(WEBHOOK_WHERE.search((h.path or "") + " " + h.src.rel) and VERIFY.search(h.src.text))


def _payment_handler(h: Handler, out: Out) -> None:
    if h.src.client or h.kind == "page" and not DB_ACCESS.search(h.body):
        return  # a page in the browser receives nothing; browser writes are _payment_client's
    where = (h.path or "") + " " + h.src.rel
    if re.search(r"(?i)webhook", where):
        if VERIFY.search(h.src.text):
            return
        sev = "high" if FULFIL.search(h.body) else "medium"
        out.add(R_PAYMENT, sev, h.src, h.start, f"{h.where} acts on webhook events without checking the provider's "
                                                "signature: anyone can post a fake \"paid\"")
        return
    if SUCCESS_PATH.search(where) and PAID_SET.search(h.body) and not PROVIDER_CHECK.search(h.src.text):
        m = PAID_SET.search(h.body)
        out.add(R_PAYMENT, "high", h.src, h.start + m.start(), f"{h.where} marks a purchase paid when the page is "
                                                               "opened, without asking the payment provider")


def _payment_client(src: Src, out: Out) -> None:
    if not src.client:
        return
    for m in CLIENT_WRITE.finditer(src.text):
        args = _call_args(src.text, m.end() - 1)
        tables = [t.group(1) or t.group(2) for t in WRITE_TABLE.finditer(src.text[max(0, m.start() - 300):m.start()])]
        table = tables[-1] if tables else ""
        if REQUEST_TABLE.search(table):
            continue  # a request waits for someone to approve it; it grants nothing
        for p in PAID_SET.finditer(args):
            bare = re.match(r"status\b", p.group(0)) and not re.search(r"paid|succeeded", p.group(0))
            if bare and not PAY_TABLE.search(table):
                continue  # the status of a match, a league or a game, not of a payment
            if ADMIN_PATH.search(src.rel):
                out.add(R_PAYMENT, "low", src, m.start(), "an admin page writes the paid or plan status from the "
                                                          "browser; make sure the database policies let only admins "
                                                          "make this write")
            else:
                out.add(R_PAYMENT, "high", src, m.start(), "browser code writes the paid or plan status itself; anyone "
                                                           "can run the same write from the console")
            break


# ------------------------------------------------------------------------------------------------ 9. races

REDEEM = re.compile(r"(?i)coupon|promo|voucher|redeem|redemption|gift_?card|referral|invite_?code|discount_?code|claim|"
                    r"reward|credits?|balance|withdraw|stock|inventory")
READ = re.compile(r"\.(?:findUnique|findFirst|findOne|findById|findByPk|maybeSingle|single|first|get_or_404|"
                  r"fetchone|scalar_one|scalar)\s*\(|\.objects\.get\s*\(|\.query\.get\s*\(|\.select\s*\(|\bSELECT\b")
USE_CHECK = re.compile(r"\bif\b[^\n]{0,160}\b(?:used|redeemed|claimed|uses|usage|remaining|times_used|timesUsed|"
                       r"max_?uses|maxUses|balance|stock|is_?used|isUsed|is_?redeemed|isRedeemed|redeemed_?at|"
                       r"redeemedAt|claimed_?at|claimedAt|available|limit)\b")
WRITE = re.compile(r"\.(?:update|updateOne|save|set|decrement|increment|upsert)\s*\(|\.save\(\)|\bUPDATE\s|[+-]=")
ATOMIC = re.compile(r"(?i)isolationLevel|serializable|FOR UPDATE|select_for_update|\block\b|Lock\s*\(|mutex|redlock|"
                    r"advisory|updateMany\s*\(|update\(\)\s*\.where|\.filter\([^)]*\)\s*\.update\(|ON CONFLICT|"
                    r"onConflict|@@?unique\b|\bunique\s*[(:=]|UniqueConstraint|IntegrityError|P2002|RETURNING|"
                    r"\.returning\(|\.rpc\s*\(|"
                    r"findOneAndUpdate\s*\(\s*\{[^}]*\$(?:lt|lte|gt|gte|ne|exists|eq)|\bcount\s*===?\s*0|rowCount|"
                    r"affectedRows|rowcount|\bchanges\b")


def _race(h: Handler, out: Out) -> None:
    body = h.body
    if not REDEEM.search(body + h.path) or ATOMIC.search(body) or ATOMIC.search(h.src.text):
        return
    r = READ.search(body)
    if not r:
        return
    c = USE_CHECK.search(body, r.end())
    if not c or not WRITE.search(body, c.end()):
        return
    out.add(R_RACE, "medium", h.src, h.start + r.start(), f"{h.where} reads, checks and then updates in separate "
                                                          "steps; parallel requests all pass the check")


# ------------------------------------------------------------------------------------------------ 10. quantity

QTY = re.compile(r"\b(quantity|qty|units|seats|tickets|nights)\b")
# A lower bound only: "stock >= quantity" caps an order but lets -1 through.
BOUND = re.compile(r"(?i)\b(?:quantity|qty|units|seats|tickets|nights)\w*['\"\]]*\s*(?:<\s*[01]\b|<=\s*0\b|>\s*0\b|>=\s*1\b)|"
                   r"\b[01]\s*(?:<=?|>=?)\s*[\w$.\[\]'\"]*\b(?:quantity|qty|units|seats|tickets|nights)\b|"
                   r"\.positive\(\)|\.min\(\s*[1-9]|\.gte?\(\s*[0-9]|"
                   r"nonnegative\(\)|isInt\(\s*\{\s*min|Math\.max\(\s*1|Math\.abs\(|PositiveInteger|"
                   r"PositiveSmallInteger|MinValueValidator|\bgt\s*=\s*0|\bge\s*=\s*1|conint\(|PositiveInt|@Min\(|"
                   r"@Positive|\bmin\s*:\s*1|minimum\s*:\s*1|\bclamp\s*\(")
ARITH_QTY = re.compile(r"\*\s*[\w$.\[\]'\"]*\b(?:quantity|qty)\b|\b(?:quantity|qty)\b['\"\]]*\s*\*")


def _quantity(h: Handler, out: Out) -> None:
    body, t = h.body, h.taint
    if BOUND.search(body) or BOUND.search(h.src.text):
        return
    for m in QTY.finditer(body):
        start = m.start()
        while start > 0 and (body[start - 1].isalnum() or body[start - 1] in "_$.[]'\""):
            start -= 1
        expr = body[start:m.end()]
        if not t.touches(expr):
            continue
        sev = "high" if ARITH_QTY.search(body) else "medium"
        out.add(R_QUANTITY, sev, h.src, h.start + m.start(), f"{m.group(1)} comes from the request and is never "
                                                             "checked for 0, negative or huge values")
        return


def _quantity_schema(src: Src, out: Out) -> None:
    text = src.text
    if re.search(r"(?i)config|settings", posixpath.basename(src.rel)):
        return  # the app's own configuration, not what a customer sends
    for m in re.finditer(r"\b(quantity|qty)\s*:\s*z\.(?:coerce\.)?number\(\)((?:\s*\.\s*\w+\([^()]*\))*)", text):
        if not re.search(r"positive|min|gte?\(|nonnegative", m.group(2)):
            out.add(R_QUANTITY, "medium", src, m.start(), f"the schema accepts any number for {m.group(1)}, "
                                                          "negative ones included")
    if src.lang == "py" and re.search(r"BaseModel|pydantic|models\.Model", text):
        for m in re.finditer(r"^[ \t]+(quantity|qty)\s*:\s*int\b([^\n]*)$", text, re.M):
            if not re.search(r"gt\s*=|ge\s*=|PositiveInt|conint", m.group(2)):
                out.add(R_QUANTITY, "medium", src, m.start(), f"{m.group(1)} accepts any integer, negative ones "
                                                              "included")
        for m in re.finditer(r"^[ \t]+(quantity|qty)\s*=\s*models\.(?:Integer|SmallInteger|BigInteger|Float|Decimal)"
                             r"Field\(([^)]*)\)", text, re.M):
            if "MinValueValidator" not in m.group(2):
                out.add(R_QUANTITY, "medium", src, m.start(), f"{m.group(1)} is stored with no lower bound")


# ------------------------------------------------------------------------------------------------ 11. login codes

CODE_PATH = re.compile(r"(?i)verif|otp|2fa|mfa|totp|code|magic|passcode|\bpin\b|confirm|login|log-in|signin|sign-in|"
                       r"reset")
CODE_CMP = re.compile(r"(?i)\b(?:code|otp|pin|passcode|verification_?code|one_?time_?code|onetimecode)\b['\"\]]*\s*"
                      r"(?:!==?|===?|!=|==)|(?:!==?|===?|!=|==)\s*[\w$.\[\]'\"]*\b(?:code|otp|pin|passcode)\b|"
                      r"where\s*:\s*\{[^}]{0,120}\b(?:code|otp|pin)\b|filter_by\([^)]{0,120}\b(?:code|otp|pin)\s*=|"
                      r"\.eq\(\s*['\"](?:code|otp|pin)['\"]|\bverify(?:_?otp|Otp|OTP|_?code|Code)\s*\(")
LIMIT = re.compile(r"(?i)rate_?limit|ratelimit|limiter|throttl|slowapi|attempt|\btries\b|lockout|locked_?until|"
                   r"max_?attempts|retry_?count|\baxes\b|too many|\b429\b|brute")
MANAGED = re.compile(r"(?i)supabase\.auth\.verifyOtp|auth\.verifyOtp|signInWithOtp|clerk|firebase|cognito|auth0|"
                     r"verificationChecks|verify\.v2|lucia|better-auth|next-auth|authjs")
WEAK_JS = re.compile(r"(?i)\b([\w$]*(?:code|otp|pin|token|secret|password|passcode|nonce|reset|invite|salt|apikey|"
                     r"api_key)[\w$]*)\s*[:=](?![=>])\s*[^;\n]{0,160}?Math\.random\s*\(\s*\)")
WEAK_PY = re.compile(r"(?i)\b(\w*(?:code|otp|pin|token|secret|password|passcode|nonce|reset|invite|salt)\w*)\s*=(?!=)"
                     r"\s*[^\n]{0,160}?\brandom\.(?:randint|randrange|choice|choices|random|sample|getrandbits)\s*\(")


def _code_handler(h: Handler, project: Project, out: Out) -> None:
    if not CODE_PATH.search((h.path or "") + " " + h.src.rel):
        return
    m = CODE_CMP.search(h.body)
    if not m:
        return
    if project.global_limit or LIMIT.search(h.body + h.guards) or LIMIT.search(h.src.text) or MANAGED.search(h.src.text):
        return
    if h.path and any(h.path.startswith(p) for p in project.limited):
        return
    out.add(R_CODE, "high", h.src, h.start + m.start(), f"{h.where} checks a code with no limit on wrong attempts; a "
                                                        "script can try every value")


def _weak_codes(src: Src, out: Out) -> None:
    if src.lang == "js":
        for m in WEAK_JS.finditer(src.text):
            out.add(R_CODE, "high", src, m.start(), f"{m.group(1)} is made with Math.random(), which can be predicted")
    elif src.lang == "py" and not re.search(r"SystemRandom|random\s*=\s*secrets", src.text):
        for m in WEAK_PY.finditer(src.text):
            out.add(R_CODE, "high", src, m.start(), f"{m.group(1)} is made with the random module, which can be "
                                                    "predicted; use secrets")


# ------------------------------------------------------------------------------------------------ 12. database

SQL = re.compile(r"(?is)\bselect\b.{0,400}?\bfrom\b|\binsert\s+into\b|\bupdate\s+[\w.\"`]+\s+set\b|\bdelete\s+from\b|"
                 r"\bwhere\b\s+[\w.\"`]+\s*(?:=|like|in)\b")
SAFE_PART = re.compile(r"^\s*(?:[A-Z][A-Z0-9_]*|\d+|Number\(.*\)|parseInt\(.*\)|Math\.\w+\(.*\)|int\(.*\)|"
                       r"placeholders?|\w+\.join\(\s*['\"],\s*['\"]\s*\))\s*$")
JS_SQL_CALL = re.compile(r"(?<![\w$])(?:[\w$]+\s*\.\s*)*(query|execute|exec|raw|run|all|get|prepare|unsafe|"
                         r"\$queryRawUnsafe|\$executeRawUnsafe|queryRawUnsafe|executeRawUnsafe)\s*\(\s*")
PY_SQL_CALL = re.compile(r"\.(?:execute|executemany|executescript|raw|extra|from_statement|exec_driver_sql)\s*\(\s*|"
                         r"(?<![\w.])text\s*\(\s*")


def _sql_literal_unsafe(literal: str, rest: str, py: bool) -> bool:
    """Is this string, with what follows it, SQL with data pasted in?"""
    if py:
        fstring = re.match(r"[rRbB]?[fF]|[fF][rRbB]", literal)
        body = re.sub(r"^[rRbBfF]+", "", literal)
        if not SQL.search(body):
            return False
        if fstring:
            return any(not SAFE_PART.match(p) for p in _interpolations(body))
        return bool(re.match(r"\s*(?:%\s*[\w(\[]|\.format\s*\(|\+\s*\w)", rest))
    if not SQL.search(literal):
        return False
    if literal.startswith("`"):
        return any(not SAFE_PART.match(p) for p in _interpolations(literal))
    return bool(re.match(r"\s*\+\s*[\w$(]", rest))


def _string_at(text: str, pos: int, py: bool) -> tuple[str, int] | None:
    m = re.compile(r"[rRbBfFuU]{0,2}(['\"`])").match(text, pos) if py else re.compile(r"(['\"`])").match(text, pos)
    if not m:
        return None
    q = m.group(1)
    start = m.end() - 1
    if py and text.startswith(q * 3, start):
        end = text.find(q * 3, start + 3)
        end = len(text) if end < 0 else end + 3
    elif q == "`":
        end = _skip_template(text, start, min(len(text), start + 20_000))
    else:
        end = _skip_quote(text, start, q, min(len(text), start + 5000))
    return text[pos:end], end


MONGO = re.compile(r"mongoose|mongodb|MongoClient|pymongo|motor\.|\.collection\(")
MONGO_QUERY = re.compile(r"\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|"
                         r"deleteMany|countDocuments|exists|find_one|update_one|delete_one)\s*\(")
SECRET_FIELD = re.compile(r"(?i)pass(?:word)?|pwd|token|code|otp|secret|hash|pin")


def _nosql(h: Handler, project: Project, out: Out) -> None:
    """A request value placed in a MongoDB query as it came: JSON and query strings can carry {"$ne": null}."""
    if h.src.lang != "js" or not (MONGO.search(h.src.text) or project.deps & {"mongoose", "mongodb"}):
        return
    t = h.taint
    for m in MONGO_QUERY.finditer(h.body):
        first = _value_after(_no_comments(_call_args(h.src.text, h.start + m.end() - 1)).strip(), 0)
        if not first.startswith("{") or re.search(r"\bwhere\s*:", first):
            continue  # where: is Sequelize or Prisma, which do not read operators from plain values
        raw = []
        for entry in _top_level(first):
            kv = re.fullmatch(r"([\w$]+)\s*:\s*(req\.(?:body|query)\.[\w$.]+)", entry)
            if kv:
                raw.append(kv.group(1))
            elif re.fullmatch(r"[\w$]+", entry) and entry in t.names and not re.search(
                    rf"\b(?:String|Number|parseInt|ObjectId)\s*\(\s*{re.escape(entry)}\b", h.body):
                raw.append(entry)
        if raw:
            sev = "high" if any(SECRET_FIELD.search(k) for k in raw) else "medium"
            out.add(R_DB, sev, h.src, h.start + m.start(), f"{', '.join(raw)} goes into the MongoDB query as the "
                                                           "client sent it: {\"$ne\": null} would match any record")
            return


def _sql(src: Src, out: Out) -> None:
    text, py = src.text, src.lang == "py"
    if src.lang not in ("js", "py"):
        return
    for m in re.finditer(r"['\"]?\$where['\"]?\s*:\s*", text):
        value = _value_after(text, m.end(), py)
        if "${" in value or re.search(r"[rR]?[fF]['\"]", value[:3]) or re.search(r"['\"`]\s*\+", value):
            out.add(R_DB, "high", src, m.start(), "a MongoDB $where runs JavaScript built from data: the data can "
                                                  "rewrite the query")
    variables = set()
    decl = re.compile(r"^[ \t]*(\w+)\s*=\s*(?=[rRbBfF]{0,2}['\"])", re.M) if py else \
        re.compile(r"(?:const|let|var)\s+([\w$]+)\s*=\s*(?=['\"`])")
    for m in decl.finditer(text):
        lit = _string_at(text, m.end(), py)
        if lit and _sql_literal_unsafe(lit[0], text[lit[1]:lit[1] + 40], py):
            variables.add(m.group(1))
    for m in (PY_SQL_CALL if py else JS_SQL_CALL).finditer(text):
        pos = m.end()
        lit = _string_at(text, pos, py)
        if lit:
            unsafe = _sql_literal_unsafe(lit[0], text[lit[1]:lit[1] + 40], py)
        else:
            name = re.match(r"([\w$]+)\s*[,)]", text[pos:pos + 80])
            unsafe = bool(name and name.group(1) in variables)
        if unsafe:
            out.add(R_DB, "high", src, m.start(), "SQL is built from strings with data pasted in: the data can rewrite "
                                                  "the query")


TABLE = r"((?:\"?\w+\"?\.)?\"?\w+\"?)"


def _table(name: str) -> tuple[str, str]:
    name = name.replace('"', "").lower()
    schema, _, table = name.rpartition(".")
    return schema or "public", table


SQL_NOISE = re.compile(r"'(?:[^']|'')*'|--[^\n]*|/\*.*?\*/", re.S)
TABLE_NC = r"(?:\"?\w+\"?\.)?\"?\w+\"?"
POLICY_NAME = r"(\"(?:[^\"]|\"\")+\"|\w+)"
MIGRATION_DIR = re.compile(r"(?:^|/)migrations?/")
RLS_EVENT = re.compile(
    rf"\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?(?P<ct>{TABLE_NC})"
    rf"|\bdrop\s+table\s+(?:if\s+exists\s+)?(?P<dt>{TABLE_NC}(?:\s*,\s*{TABLE_NC})*)"
    rf"|\balter\s+table\s+(?:(?:if\s+exists|only)\s+)*(?P<rt>{TABLE_NC})\s+(?P<rls>enable|disable)\s+row\s+level\s+"
    r"security"
    rf"|\bcreate\s+policy\s+(?P<cp>{POLICY_NAME[1:-1]})\s+on\s+(?P<cpt>{TABLE_NC})"
    rf"|\bdrop\s+policy\s+(?:if\s+exists\s+)?(?P<dp>{POLICY_NAME[1:-1]})\s+on\s+(?P<dpt>{TABLE_NC})"
    rf"|\balter\s+policy\s+(?P<ap>{POLICY_NAME[1:-1]})\s+on\s+(?P<apt>{TABLE_NC})", re.I)
OPEN_CLAUSE = re.compile(r"(?i)\b(?:using|with\s+check)\s*\(\s*true\s*\)")
NULL_OWNER = re.compile(r"(?i)\bor\s+\(?\s*(?:\w+\.)?(\w*(?:user|owner|author|creator|created_by|account|customer|member)"
                        r"\w*)\s+is\s+null\b|\b(?:\w+\.)?(\w*(?:user|owner|author|creator|created_by|account|customer|"
                        r"member)\w*)\s+is\s+null\s+or\b")
SERVICE_ONLY = re.compile(r"(?i)\bto\s+(?:service_role|postgres|supabase_admin)(?:\s*,\s*(?:service_role|postgres|"
                          r"supabase_admin))*\b")
PUBLIC_FORM = re.compile(r"(?i)wait_?list|sign_?ups?|early_?access|newsletter|subscribers?|contact|feedback|inquir|"
                         r"enquir|leads?\b|rsvp|survey|page_?views?|analytics")


def _sql_code(text: str) -> str:
    """SQL with comments blanked out (same length, newlines kept), so positions still point at the right line."""
    return SQL_NOISE.sub(lambda m: m.group(0) if m.group(0).startswith("'") else re.sub(r"[^\n]", " ", m.group(0)),
                         text)


def _policy_name(raw: str) -> str:
    return raw[1:-1].replace('""', '"') if raw.startswith('"') else raw.lower()


def _rls(project: Project, out: Out) -> None:
    """Replay the SQL in the order it is applied (schema files first, then migrations by file name) and report what
    the final database has: tables without row level security and policies that are still open."""
    sql = [s for s in project.srcs.values() if s.lang == "sql"]
    if not sql or not ("supabase" in project.kinds or any(s.rel.startswith("supabase/") for s in sql)):
        return
    order = sorted((s for s in sql if not MIGRATION_DIR.search(s.rel)), key=lambda s: s.rel) + \
        sorted((s for s in sql if MIGRATION_DIR.search(s.rel)), key=lambda s: (posixpath.basename(s.rel), s.rel))
    created: dict[tuple, tuple] = {}  # table -> (src, pos) of the create that stands
    rls: dict[tuple, tuple] = {}  # table -> (on, src, pos) of the last enable or disable
    policies: dict[tuple, tuple] = {}  # (table, name) -> (src, pos, statement)
    for s in order:
        code = _sql_code(s.text)
        for m in RLS_EVENT.finditer(code):
            if m.group("ct"):
                created[_table(m.group("ct"))] = (s, m.start())
            elif m.group("dt"):
                for name in m.group("dt").split(","):
                    t = _table(name.strip())
                    created.pop(t, None)
                    rls.pop(t, None)
                    for key in [k for k in policies if k[0] == t]:
                        del policies[key]
            elif m.group("rt"):
                rls[_table(m.group("rt"))] = (m.group("rls").lower() == "enable", s, m.start())
            elif m.group("cp"):
                end = code.find(";", m.end())
                policies[(_table(m.group("cpt")), _policy_name(m.group("cp")))] = \
                    (s, m.start(), code[m.start():len(code) if end < 0 else end])
            elif m.group("dp"):
                policies.pop((_table(m.group("dpt")), _policy_name(m.group("dp"))), None)
            elif m.group("ap"):
                key = (_table(m.group("apt")), _policy_name(m.group("ap")))
                end = code.find(";", m.end())
                if key in policies:
                    s0, p0, stmt = policies[key]
                    policies[key] = (s0, p0, stmt + " " + code[m.end():len(code) if end < 0 else end])
    for (schema, table), (s, pos) in created.items():
        state = rls.get((schema, table))
        if schema == "public" and not (state and state[0]):
            if state:
                out.add(R_DB, "high", state[1], state[2], f"row level security is switched off on {table}")
            else:
                out.add(R_DB, "high", s, pos, f"table {table} has no row level security: anyone with the anon key in "
                                              "your web page can read and change it")
    for (schema, table), (on, s, pos) in rls.items():
        if not on and (schema, table) not in created:
            out.add(R_DB, "high", s, pos, f"row level security is switched off on {table}")
    for ((_, table), _name), (s, pos, stmt) in policies.items():
        if SERVICE_ONLY.search(stmt):
            continue  # the service role skips row level security anyway
        action = (re.search(r"(?i)\bfor\s+(all|select|insert|update|delete)\b", stmt) or [None, "all"])[1].lower()
        if OPEN_CLAUSE.search(stmt):
            if action == "select":
                sev = "medium" if PRIVATE.search(table) else "low"
            elif action == "insert" and PUBLIC_FORM.search(table):
                sev = "low"  # a public sign-up or contact form: anyone may add a row, by design
            else:
                sev = "high"
            out.add(R_DB, sev, s, pos, f"the policy on {table} lets anyone {action} every row (using true)")
        elif NULL_OWNER.search(stmt):
            col = next(g for g in NULL_OWNER.search(stmt).groups() if g)
            # adding rows with no owner is how anonymous events and forms work; reading or changing them is the hole
            verb = {"all": "read and change", "select": "read", "update": "change"}.get(action, action)
            if action == "insert":
                out.add(R_DB, "low", s, pos, f"the policy on {table} lets anyone add rows with no {col}")
            else:
                out.add(R_DB, "medium", s, pos, f"the policy on {table} lets anyone {verb} the rows whose {col} is "
                                                "empty")


def _firebase(src: Src, out: Out) -> None:
    text = src.text
    if posixpath.basename(src.rel) == "database.rules.json" or ('"rules"' in text and src.rel.endswith(".json")
                                                                 and '".read"' in text):
        for m in re.finditer(r"\"\.(read|write)\"\s*:\s*(?:true|\"true\")", text):
            out.add(R_DB, "high" if m.group(1) == "write" else "medium", src, m.start(),
                    f"the Realtime Database lets anyone {m.group(1)}")
        return
    if src.lang != "rules" or not re.search(r"service\s+(?:cloud\.firestore|firebase\.storage)", text):
        return
    for m in re.finditer(r"allow\s+[\w\s,]+:\s*if\s+true\s*;|allow\s+[\w\s,]+?\s*;", text):
        out.add(R_DB, "high", src, m.start(), "this rule lets anyone in")
    for m in re.finditer(r"request\.time\s*<\s*timestamp\.date\s*\(", text):
        out.add(R_DB, "high", src, m.start(), "test-mode rules: until that date anyone can read and write everything")
    for m in re.finditer(r"match\s*/\{document=\*\*\}\s*\{[^}]{0,300}?allow\s+[\w\s,]+:\s*if\s+request\.auth\s*!=\s*"
                         r"null\s*;", text):
        out.add(R_DB, "medium", src, m.start(), "any signed-in user can read and change every document")


# ------------------------------------------------------------------------------------------------ 14. uploads

TYPE_CHECK = re.compile(r"\.type\b|mimetype|\bmime\b|content_?[tT]ype|fileTypeFromBuffer|file-type|\bmagic\b|imghdr|"
                        r"sharp\s*\(|ALLOWED|allowed|\baccept\b|Image\.open|\bPIL\b|filetype\.|\.verify\(\)")
MAGIC_CHECK = re.compile(r"fileTypeFromBuffer|file-type|\bmagic\b|imghdr|sharp\s*\(|Image\.open|filetype\.guess|"
                         r"image-size|probe-image")
FS_WRITE = re.compile(r"\b(?:writeFile|writeFileSync|createWriteStream)\s*\(")
STORE_WRITE = re.compile(r"\.upload\s*\(|\bput\s*\(|PutObjectCommand|uploadBytes\w*\s*\(")
SVG = re.compile(r"image/svg\+xml|['\"]\.?svg['\"]")
OTHER_IMAGE = re.compile(r"image/(?:png|jpe?g|gif|webp|avif)|['\"]\.?(?:png|jpe?g|gif|webp|avif)['\"]")
PY_STORE = re.compile(r"\.save\s*\(|shutil\.copyfileobj\s*\(|\bopen\s*\([^)\n]*['\"]wb?['\"]|upload_fileobj\s*\(|"
                      r"put_object\s*\(|\.upload\s*\(|default_storage\.save\s*\(")


def _uploads(src: Src, out: Out) -> None:
    text = src.text
    if src.lang == "js":
        for m in re.finditer(r"\bdiskStorage\s*\(", text):
            args = _call_args(text, m.end() - 1)
            fn = re.search(r"\bfilename\s*[:(]", args)
            sanitized = re.search(r"(?:sanitiz\w*|basename|slugify|filenamify)\s*\(\s*\w+\.originalname", args)
            if fn and "originalname" in args[fn.start():] and not sanitized:
                part = args[fn.start():]
                only_ext = re.search(r"extname\(\s*\w+\.originalname\s*\)", part) and \
                    not re.search(r"(?<!extname\()\b\w+\.originalname\b(?!\s*\))", part.replace("extname(", "extname("))
                out.add(R_UPLOAD, "medium" if only_ext else "high", src, m.start(),
                        "uploads are saved under the name the uploader chose, so they pick the extension (.html, .svg) "
                        "or a path")
        for m in re.finditer(r"([\w$]+)\s*=\s*req\.files\s*(?:\.\s*[\w$]+|\[\s*['\"][\w-]+['\"]\s*\])", text):
            var = re.escape(m.group(1))  # express-fileupload: the file object, then file.mv(destination)
            built = _name_rx(re.findall(rf"([\w$]+)\s*=\s*[^;\n]*(?<![\w$]){var}\.name\b", text))
            for mv in re.finditer(rf"(?<![\w$.]){var}\.mv\s*\(", text):
                dest = re.split(r",(?![^(\[{]*[)\]}])", _call_args(text, mv.end() - 1))[0]
                if (re.search(rf"(?<![\w$]){var}\.name\b", dest) or (built and built.search(dest))) and \
                        not re.search(r"sanitiz|basename|slugify|randomUUID|uuid|nanoid", dest):
                    out.add(R_UPLOAD, "high", src, mv.start(), "the upload is saved under the name the uploader sent, "
                                                               "so they pick the extension (.html, .svg) or a path")
                    break
        if re.search(r"\bmulter\s*\(", text) and "fileFilter" not in text and not TYPE_CHECK.search(text):
            m = re.search(r"\bmulter\s*\(", text)
            out.add(R_UPLOAD, "medium", src, m.start(), "multer accepts any file type; add a fileFilter and limits")
        file_vars = set(re.findall(r"(?:const|let|var)\s+([\w$]+)\s*=\s*[^;\n]{0,80}\.get\(\s*['\"][\w-]+['\"]\s*\)\s*"
                                   r"as\s+File\b", text))
        file_vars |= set(re.findall(r"([\w$]+)\s+instanceof\s+File\b", text))
        if file_vars and (FS_WRITE.search(text) or STORE_WRITE.search(text)):
            names = "|".join(map(re.escape, file_vars))
            for w in list(FS_WRITE.finditer(text)) + list(STORE_WRITE.finditer(text)):
                args = _call_args(text, w.end() - 1)
                if re.search(rf"(?<![\w$.])(?:{names})\.name\b", args) and not re.search(r"sanitiz|basename|slugify",
                                                                                          args):
                    fs = bool(FS_WRITE.match(text, w.start()))
                    out.add(R_UPLOAD, "high" if fs else "medium", src, w.start(),
                            "the file is stored under the name the uploader sent" +
                            (", which can climb out of the folder" if fs else ""))
                    break
            if not TYPE_CHECK.search(text):
                out.add(R_UPLOAD, "medium", src, (FS_WRITE.search(text) or STORE_WRITE.search(text)).start(),
                        "uploads are stored without checking their type or size")
    elif src.lang == "py":
        if ("request.files" in text or "UploadFile" in text or "request.FILES" in text) and PY_STORE.search(text):
            for m in re.finditer(r"\.save\s*\(|\bopen\s*\(", text):
                args = _call_args(text, m.end() - 1, py=True)
                if re.search(r"\.filename\b", args) and "secure_filename" not in args and \
                        (m.group(0).startswith(".save") or re.search(r"['\"]w", args)):
                    out.add(R_UPLOAD, "high", src, m.start(), "the upload is saved under the name the uploader sent; "
                                                              "use secure_filename or a generated name")
                    break
            if not TYPE_CHECK.search(text):
                m = re.search(r"request\.files|UploadFile|request\.FILES", text)
                out.add(R_UPLOAD, "medium", src, m.start(), "uploads are stored without checking their type or size")
    if src.lang in ("js", "py") and re.search(r"upload|multer|request\.files|UploadFile|formData", text, re.I):
        for m in SVG.finditer(text):
            line = src.line_text(m.start())
            if re.search(r"(?i)allow|accept|types?|mime|ext", line) and OTHER_IMAGE.search(line):
                out.add(R_UPLOAD, "medium", src, m.start(), "SVG uploads are allowed; an SVG can carry script")
                break


# ------------------------------------------------------------------------------------------------ running it

def analyze(project: Project, out: Out, local: bool = False) -> None:
    for src in project.srcs.values():
        if src.lang in ("js", "tmpl", "py"):
            _xss(src, out)
        _browser_keys(src, out)
        if src.lang in ("js", "py"):
            _prompt_file(src, out)
            _mass_file(src, out)
            _sql(src, out)
            _weak_codes(src, out)
            _uploads(src, out)
            _payment_client(src, out)
            if not local:
                _quantity_schema(src, out)
                if src.lang == "js":
                    _admin_mounts(src, project, out)
                else:
                    _drf(src, out)
        elif src.lang == "sql":
            _mass_file(src, out)
        if src.lang in ("rules", "other") and not local:
            _firebase(src, out)
        if src.lang not in ("js", "py"):
            continue
        handlers = _js_handlers(src) if src.lang == "js" else _py_handlers(src)
        for h in handlers:
            _xss_handler(h, out)
            _prompt_handler(h, out)
            _mass_handler(h, out, project)
            _price(h, out)
            _payment_handler(h, out)
            _nosql(h, project, out)
            if not local:
                _idor(h, project, out)
                _admin_handler(h, project, out)
                _race(h, out)
                _quantity(h, out)
                _code_handler(h, project, out)
    if not local:
        _rls(project, out)
    _secret_files(project, out) if not local else _local_secrets(project, out)


def _local_secrets(project: Project, out: Out) -> None:
    for src in project.srcs.values():
        if src.client or src.lang == "env":
            continue
        for pos, kind, head in _secrets(src.text):
            out.add(R_SECRET, "high", src, pos, f"{kind} written into the code", evidence=f"{kind} starting {head}…")


def _decode(data) -> str | None:
    if isinstance(data, str):
        return data
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def check_files(files: dict, *, target: str = "(in memory)", git: dict | None = None) -> Report:
    """Check files held in memory, keyed by their path from the app's root. git: tracked, untracked (not ignored) and
    history (paths ever added) sets, or None outside a repository."""
    started = time.monotonic()
    texts, count = {}, 0
    for rel, data in files.items():
        rel = rel.replace("\\", "/")
        if _skipped(rel):
            continue
        count += 1
        text = _decode(data)
        if text is None or len(text) > MAX_BYTES:
            continue
        if posixpath.splitext(rel.lower())[1] not in TEXT_EXT and not ENV_NAME.match(posixpath.basename(rel)):
            continue
        if _bundle(rel, text):
            continue
        texts[rel] = text
    project = _project(texts, git)
    out = Out()
    analyze(project, out)
    report = Report(target, out.findings)
    report.stats = {"files": count, "seconds": round(time.monotonic() - started, 2), "checks": len(RULE_IDS)}
    return report


def _git(root: Path) -> dict | None:
    if shutil.which("git") is None:
        return None
    base = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull, "-C", str(root)]
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")

    def run(*args: str) -> list[str] | None:
        try:
            res = subprocess.run(base + list(args), capture_output=True, timeout=60, check=False, env=env)
        except (OSError, subprocess.SubprocessError):
            return None
        if res.returncode != 0:
            return None
        return [p for p in res.stdout.decode("utf-8", "replace").replace("\n", "\x00").split("\x00") if p]

    inside = run("rev-parse", "--is-inside-work-tree")
    if not inside or inside[0].strip() != "true":
        return None
    tracked = run("ls-files", "-z")
    untracked = run("ls-files", "-z", "--others", "--exclude-standard")
    history = run("log", "--all", "--relative", "--diff-filter=A", "--name-only", "--format=", "-z", "--",
                  ":(glob)**/.env", ":(glob)**/.env.*", ":(glob)**/*.env")
    if tracked is None:
        return None
    return {"tracked": set(tracked), "untracked": set(untracked or ()), "history": set(history or ())}


def check(target: str | os.PathLike, *, max_seconds: float | None = None) -> Report:
    """Check a local app folder (or one file). Nothing in it is run."""
    started = time.monotonic()
    root = Path(str(target)).expanduser()
    if not root.exists():
        raise FileNotFoundError(str(target))
    files: dict[str, bytes] = {}
    incomplete = []
    if root.is_file():
        files[root.name] = root.read_bytes()
        git = None
    else:
        root = root.resolve()
        git = _git(root)
        stack = [(root, "")]
        while stack:
            directory, prefix = stack.pop()
            try:
                entries = sorted(os.scandir(directory), key=lambda e: e.name)
            except OSError as err:
                incomplete.append(f"{prefix or '.'}: could not list ({err.strerror})")
                continue
            for entry in entries:
                rel = prefix + entry.name
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name not in SKIP_DIRS and rel not in SKIP_DIRS:
                        stack.append((Path(entry.path), rel + "/"))
                    continue
                if len(files) >= MAX_FILES:
                    incomplete.append(f"more than {MAX_FILES:,} files; the rest were not checked")
                    stack = []
                    break
                if max_seconds and time.monotonic() - started > max_seconds:
                    incomplete.append(f"time limit of {max_seconds:.0f}s reached")
                    stack = []
                    break
                try:
                    size = entry.stat(follow_symlinks=False).st_size
                    ext = posixpath.splitext(entry.name.lower())[1]
                    if size > MAX_BYTES or (ext not in TEXT_EXT and not ENV_NAME.match(entry.name)):
                        files[rel] = b"\x00"  # counted, not read
                        continue
                    files[rel] = Path(entry.path).read_bytes()
                except OSError as err:
                    incomplete.append(f"{rel}: could not read ({err.strerror})")
    report = check_files(files, target=str(target), git=git)
    report.incomplete = incomplete
    report.stats["seconds"] = round(time.monotonic() - started, 2)
    return report


def note_for_write(rel: str, content: str) -> str:
    """What an agent is told right after it writes a file with a hole only that file can show; "" when there is none.
    rel is the file's path inside the project: folders above it must not make an app look like test code."""
    rel = str(rel).replace("\\", "/").lstrip("/")
    name = rel.rsplit("/", 1)[-1]
    if TEST_PATH.search(rel) or _lang(name) not in ("js", "py", "tmpl") or len(content) > MAX_BYTES \
            or _bundle(rel, content):
        return ""
    short = rel
    project = _project({short: content}, None, reach=False)
    out = Out(only=LOCAL_RULES)
    analyze(project, out, local=True)
    found = sorted((f for f in out.findings if rank(f.severity) >= rank("high")), key=lambda f: (f.line, f.rule))
    if not found:
        return ""
    lines = [f"agent-white-hat app check: {short} has {len(found)} security hole(s) an attacker could use. Fix them "
             "now, then carry on:"]
    for f in found[:6]:
        lines.append(f"- {short}:{f.line} {f.rule} {RULES[f.rule].title}: {f.message}. Fix: {RULES[f.rule].fix}")
    if len(found) > 6:
        lines.append(f"- and {len(found) - 6} more; run `pah appsec .` for the whole app.")
    return "\n".join(lines)[:2000]
