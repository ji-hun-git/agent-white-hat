# Shields and the protection log

When an attack becomes known, there are days between the advisory and the fix reaching you: the hijacked release is
still the newest version, the worm's command-and-control host still answers, the patched agent is not out yet. A
**shield** covers those days. It is a narrow guard rule for one incident (a package version, a host, a command, a
path), it watches before it blocks, it expires on its own, and every change to it is recorded.

The design follows [Shirudo](https://openai.com/index/introducing-shirudo/) (OpenAI and Cisco, November 2026), which
shields a running Linux service from one exploit path until the patch ships. Shirudo works in the kernel with eBPF;
agent-white-hat works in front of your AI agent's actions, so the ideas carry over and the mechanism does not:

| Shirudo | agent-white-hat |
| --- | --- |
| An eBPF program blocks one vulnerable code path | A shield denies (or asks about) one package version, host, command pattern or path |
| Operators watch a shield's effect before enforcing it | Shields start in **monitor mode**: they record what they would have stopped and change nothing |
| Shields are temporary, until the permanent fix | Every shield **expires**, at most 90 days ahead |
| Shields are signed and verified before loading | Bundles of shields are **signed with Ed25519** and refused unless you trust the key |
| A TPM records every protection loaded or removed | The **protection log** chains every change to the one before it; `pah log verify` shows edits, removals and a cut-off tail |

A shield can only make the guard stricter. It never allows anything the guard would stop.

## Quick start

An advisory says `@ctrl/tinycolor` 4.1.1 is a hijacked release and the fix is days away:

```sh
pah shield add --package npm:@ctrl/tinycolor@4.1.1 --reason "hijacked release, see the advisory" \
  --ref https://example.com/advisory --days 14
# Added shield local-20261124-3f2a in monitor mode until 2026-12-08 12:00:00 UTC. ...

pah check-command "npm install @ctrl/tinycolor"
# DEFER: no objection from agent-white-hat
# MONITOR: shield local-20261124-3f2a would deny this once enforced (installs @ctrl/tinycolor (npm) without an
#          exact version, which may resolve to 4.1.1)

pah shield report            # after a day of work: what it matched, and how much of that the guard alone allowed
pah shield enforce local-20261124-3f2a
```

From then on, an agent that tries `npm install @ctrl/tinycolor@4.1.1`, an unpinned `npm i @ctrl/tinycolor`, a
`package.json` that pins 4.1.1, or the same install hidden in `echo … | base64 -d | sh` is denied with the shield's
reason. Version 4.1.0 and `@ctrl/tinycolor2` are not touched.

Adding, enforcing or removing a shield is your decision. When an agent runs `pah shield add`, `enforce`, `monitor`,
`remove`, `import`, `trust-key` or `untrust-key`, the guard asks you, and the agent cannot write the guard's folder.

## What a shield matches

| Match | Written as | Judged on |
| --- | --- | --- |
| `package` | `npm:name`, `npm:@scope/name@1.2.3`, `pypi:name@1.2.3` (or `pypi:name==1.2.3`) | Install and run commands (`npm i`, `pnpm add`, `yarn add`, `npx`, `pip install`, `uv add`, `uvx`, `pipx`, `poetry add`), also once a disguise is undone; `package.json` and `requirements*.txt` the agent writes |
| `command` | a regular expression (case-insensitive) | The command and what it really runs once quotes, variables, base64, hex and similar disguises are undone |
| `host` | `evil.example` | Hosts a command reaches and URLs the agent fetches; subdomains match (`cdn.evil.example`), look-alikes do not (`evil.example.com`, `notevil.example`) |
| `path` | a glob: `*/.vscode/tasks.json`, `~/.npmrc`, `*.pth` | Files the agent writes or reads |

A shield that names a version matches that exact version, and also an install without an exact version (no version,
`^4.1.0`, `>=2`, `latest`): pah cannot know what a range resolves to, so it counts the install as a match, and the
report in monitor mode shows whether that is too broad. Another exact version does not match.

Shields that would match everything are refused: a command pattern that matches an empty command, a path made only of
wildcards, a host with a `*`. So are shields without a reason, without an expiry, with an expiry more than 90 days
ahead, or with an action other than `deny` or `ask`. The title and reason are shown to the agent, so they are cleaned
of control and invisible characters and clipped.

## Monitor first, then enforce

A new shield records each match in `shield-hits.jsonl` with what the guard alone decided, and changes nothing.
`pah shield report` shows, for each shield, how many steps it matched and how many of those the guard alone would have
let through: that second number is what enforcing it adds. Read the examples it prints: a legitimate command among
them means the shield is too broad, and it is cheaper to learn that before it blocks your work.

`pah check-command` shows monitor shields too ("MONITOR: shield … would deny this once enforced") without counting
the question as a match. `pah shield add --enforce` and `pah shield import --enforce` skip the waiting when an attack
is spreading and there is no time to watch.

## Expiry

Every shield has an end date, 14 days by default and at most 90. After it, the shield stops acting by itself; its end
is recorded in the protection log the next time `pah shield list` runs, and `pah shield remove --expired` clears the
list. If the fix is still not out, add the shield again: renewing is a decision, not a default.

## Signed bundles

A security team or the maintainers can publish shields for an incident as a bundle:

```json
{
  "format": "pah-shields/1",
  "publisher": "agent-white-hat maintainers",
  "issued": "2026-11-24T00:00:00Z",
  "shields": [
    {"id": "2026-11-example-host", "title": "Example worm's collection host", "action": "deny",
     "reason": "Collection host of an example worm; blocked until the takedown.",
     "ref": "https://example.com/advisory", "match": {"host": ["collector.example"]},
     "expires": "2026-12-08T00:00:00Z"}
  ],
  "signature": {"alg": "ed25519", "key": "…", "sig": "…"}
}
```

The signature covers the bundle without its `signature` field, as JSON with sorted keys and no spaces. Signatures are
Ed25519 (RFC 8032), checked by a pure-Python implementation tested against the RFC's vectors and against OpenSSL,
because the Python standard library has no signature functions.

**Publishers:**

```sh
pah shield keygen ~/keys/shields          # ~/keys/shields (secret) and ~/keys/shields.pub
pah shield sign bundle.json --key ~/keys/shields
```

Give people the `.pub` file through a channel they already trust. The secret file stays with you; on Windows, keep it
in a folder only your account can read. Signing in pure Python is not constant-time, so sign on a machine only you use.

**Users:**

```sh
pah shield trust-key shields.pub --name "our security team"
pah shield verify bundle.json             # signed by a key you trust, and unchanged since?
pah shield import bundle.json             # report-only; add --enforce to act at once
```

A bundle is imported whole or not at all. Its shields start in monitor mode whatever the publisher wrote, because what
the guard enforces on your computer is your decision. Shields that expired since signing are skipped, and expiries
more than 90 days ahead are cut back to 90. An unsigned bundle is refused unless you add `--unsigned`, which you should
do only for a bundle you wrote yourself. A key in `pah/data/shield-keys.json` ships with pah; there is none yet.

Why sign shields that can only make the guard stricter? Because a forged bundle could still deny the commands you
need, put text of an attacker's choosing in front of your agent as a shield's reason, or carry a regular expression
slow enough to stall every check.

## The protection log

Every change to what the guard allows goes into `protection-log.jsonl` in the guard's folder
(`~/.personal-anti-hack/`, or `PAH_HOME`):

- shields added, replaced, switched between monitor and enforce, removed, expired, and bundles imported
- signing keys trusted and untrusted
- projects trusted and untrusted (`pah trust`)
- configuration baselines taken or accepted (`pah watch init`, `pah watch accept`)
- hooks, skills and MCP servers installed (`pah install --yes`)
- quarantine: files added, restored and deleted
- real-time protection added to or removed from login

Each entry carries the SHA-256 of the entry before it, and `protection-log.head` holds the newest. `pah log` prints
the last entries and the head; `pah log verify` recomputes the chain and also compares the shields and trusted keys on
disk with what the log says they should be. It reports an edited entry, a deleted or reordered one, a tail cut off, a
deleted log, a shield added, changed or removed by hand, and a key trusted without the log knowing. The exit code is 2
when something is wrong.

What a chain kept on the same disk cannot show is someone with your file permissions rewriting the whole history and
its head consistently. Shirudo answers that with a TPM; here, note the head somewhere else (a password manager, a
message to yourself) and later run `pah log verify --anchor <head>`: an anchor noted earlier must still be in the
chain, however many entries came after it.

## Files

| File | What it holds |
| --- | --- |
| `shields.json` | The shields, with their mode and expiry |
| `shield-hits.jsonl` | Matches, for `pah shield report` (trimmed to the newest 2,000 past 1 MB) |
| `shield-keys.json` | Signing keys you trust |
| `protection-log.jsonl`, `protection-log.head` | The protection log and its newest hash |

The guard reads `shields.json` on every check, which costs one file read; with no shields it is one `stat`. A broken
or unreadable `shields.json` never stops the rest of the guard: its own verdict stands, and `pah shield list` and
`pah log verify` say what is wrong.

## Limits

- A shield sees what the guard sees: the commands, writes, reads and fetches an agent makes through its hooks. It
  does not see what a program does once it runs, and it does not see a human typing in a terminal.
- Package matching reads install commands and the two most common manifests; a dependency pulled in by another
  package, or a lockfile the agent writes, is not matched. `pah scan --online` and `pah audit` cover those.
- `path` patterns are matched against the files an agent's tools write and read, not against paths that appear inside
  a shell command; use a `command` pattern for those.
