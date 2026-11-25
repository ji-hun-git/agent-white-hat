# How agent-white-hat is built

Standard library only, Python 3.10 or newer. Nothing in a scanned target is executed: every module reads files.

## What a scan does

```
collect()      read the folder, file or archive; open archive members (scan.py)
   |
dispatch       each file to the handlers that understand it (surfaces/, packages.py):
   |           hooks, settings, MCP servers, skills, instruction files, editor tasks, workflows, git, manifests
   |           -> surfaces (what runs, and what starts it), files marked "autoexec", and entry files: the code that
   |              runs as soon as the package is loaded (npm main, an eagerly activated editor extension, a top-level
   |              __init__.py)
toxic_flows    the repository's agent setup as a whole (surfaces/agent_setup.py, flows.py)
   |
propagate      what autoexec code imports or starts through a runtime also runs on its own (scan.py)
   |
scan_text      content rules on every text file, in its context: autoexec, code, doc, config (patterns.py)
   |           with decoding first (deobfuscate.py), campaign shapes (campaigns.py), hidden text (text.py);
   |           in an entry file, a capture or tunnel endpoint and details of the machine sent out count as high,
   |           since nothing has to call them, and so does a program downloaded and run by an editor extension that
   |           starts with the editor (scan.py)
   |
adjust         where a file sits changes what a finding means: fixtures, CI, containers (policy.py)
   |
Report         findings, surfaces, verdict (model.py, report.py)
```

`pah diff` runs this twice and keeps what is new (diff.py, capabilities.py). `pah checkup` looks at the computer
instead of a target (checkup.py, incidents.py, flows.py). Model files are read in the dispatch step (models.py).

## What the guard does with each step

```
hook payload  each agent's own format, read into one ToolEvent (agents.py; hooks.py for Claude Code)
   |
judge alone   the command, write, read or fetch on its own (guard.py, with patterns.py), a scan of the
   |          project before setup or a model load, and last the active shields (shields.py), which can only
   |          make the answer stricter and, in monitor mode, only record
judge in its  the step reduced to tags (credential read, download, send, run, persistence, tamper, ...) and
session       checked against the session's earlier steps (behavior.py, session.py)
   |
answer        deny or ask in the agent's protocol, or nothing; the step is recorded with the answer

after a tool  what it returned is read for instructions aimed at the agent (outputs.py); a hit warns the agent
ran            and marks the session, so its later sensitive steps need the user; a file the agent just wrote is
               read for app security holes it shows on its own (appsec.py), and the agent is told the fix
```

## Modules

| Module | What it holds |
| --- | --- |
| `scan.py` | `collect()` and the scan pipeline above |
| `surfaces/` | One module per kind of file that runs without being read: `agent_configs.py` (Claude Code, Cursor, Codex, Gemini CLI, Copilot, OpenCode, Crush, Aider, OpenClaw), `instructions.py` (AGENTS.md, CLAUDE.md, rules files, setup documents, skills), `mcp.py`, `ide.py` (tasks, settings, dev containers, direnv), `workflows.py`, `git.py`, `env.py`; `base.py` holds File, State and command parsing, `dispatch.py` decides which handler reads a file, `agent_setup.py` reads a repository's agent setup as a whole, `rules.py` the rules they report |
| `packages.py` | Package manifests and build files: npm, pnpm, Yarn, Bun, PyPI, Cargo, RubyGems, Gradle, Maven, MSBuild, Make, CMake, Xcode |
| `patterns.py` | Content rules and command analysis (`scan_text`, `analyze_command`) |
| `content_rules.py` | The rules `patterns.py`, `campaigns.py` and `deobfuscate.py` report |
| `campaigns.py` | Shapes of named campaigns that need two pieces of evidence near each other |
| `deobfuscate.py` | Decoding before the rules: pieces joined, character codes, escapes, ROT13, brackets, getattr, shell variables |
| `shellfold.py` | What a shell command really runs, worked out without running it: quote and backslash breaks, `${IFS}`, variables, runners (`script -qc`, `watch`, `bash -c`) and decode-and-run pipelines (base64, hex, `printf`, `tr`, `rev`, gzip); `analyze_command` judges every form it finds |
| `codectx.py` | Where a match sits: string, comment, regular expression, test data |
| `hosts.py` | Where a URL points: official installer or registry, reference host, user content, look-alike |
| `indicators.py`, `text.py` | Shared regular expressions; invisible characters, padding, encoded blobs |
| `policy.py` | How a file's location changes a finding's severity |
| `capabilities.py` | What a file can do: network, sending data, processes, dynamic code, credentials, persistence, install hooks |
| `diff.py` | `pah diff`: two versions, or a source checkout and the package built from it |
| `flows.py` | Toxic flows (PAH-A021) and pre-approved commands that run any program (PAH-A020) |
| `incidents.py`, `data/incidents.json` | The incident catalog: what happened, what checks it, traces, the response in order |
| `checkup.py`, `watch.py`, `protect.py`, `av.py` | The computer: exposures and traces, configuration baseline, real-time protection and quarantine, the local antivirus engine |
| `guard.py`, `hooks.py`, `install.py`, `agents.py` | The guard in each agent's hook protocol, and installing it |
| `behavior.py`, `session.py` | Steps judged by the steps before them (PAH-B rules), and the per-session record behind `pah session` |
| `shields.py`, `ed25519.py`, `data/shield-keys.json` | Shields for an incident happening now: matching, monitor and enforce, expiry, signed bundles (Ed25519 in pure Python) and the keys shipped with pah ([shields](shields.md)) |
| `ledger.py` | The protection log: every change to what the guard allows, hash-chained, and its verification |
| `outputs.py` | What tools return: injected instructions, hidden text, exfiltration links, terminal sequences (PAH-O rules) |
| `appsec.py` | `pah appsec`: the user's own web app, read route handler by route handler for the fourteen holes attackers try first (PAH-W rules), and the note an agent gets after writing a file with one ([appsec](appsec.md)) |
| `models.py` | Model files read without loading them: pickles, PyTorch, Keras, GGUF, NumPy, remote code (PAH-M rules) |
| `intel.py`, `names.py`, `lockfiles.py`, `review.py` | Registry and OSV lookups (opt-in), look-alike names, pinned versions, the model review (opt-in) |
| `report.py`, `ci.py`, `mcp_server.py`, `cli.py` | Text, JSON and SARIF; GitHub Actions; the MCP server; the command line |
| `model.py`, `collector.py` | Findings, rules registry, reports; one file's findings, deduplicated |

## Where a change goes

- **A rule about what a file contains:** define it in `content_rules.py` with the incident or study behind it, add
  the pattern to `patterns.py` (or a shape to `campaigns.py`), and a malicious TrapRepo case with a benign twin in
  `bench/fixtures/_build_cases.py`.
- **A new kind of file that runs on its own:** a handler in the matching `surfaces/` module (or `packages.py` for a
  build or package manifest) that records the surface and marks what it runs as autoexec; the content rules then judge
  that code as code that runs on its own. Route it in `surfaces/dispatch.py` or `dispatch_packages`.
- **A way to hide code:** an operator in `bench/fuzz.py` first, then the decoding in `deobfuscate.py` (or, for a shell
  command, in `shellfold.py`, scored with `bench/shellgate.py`).
- **A real incident:** an entry in `pah/data/incidents.json`, then `pah incident list --markdown > docs/incidents.md`.
- **A lesson from the held-out test:** draw and push the next round first (`bench/independent.py plan --exclude`
  names every earlier sample, so none is drawn again; `--split` halves sets taken whole and sets one half aside for
  tuning), then study only samples that round will not measure. Pin each principle in `tests/test_heldout_lessons.py`
  with inputs written for the test (never code copied from a sample), and check it against the cached popular
  packages of earlier rounds before trusting it. Look at malicious samples by shape (strings emptied, hosts removed)
  and keep them in memory: excerpts printed to a file can be quarantined by antivirus, which means they touched disk.
- **An attack that shows only as a sequence:** a tag for the step in `behavior.act_of` if it needs one, the rule in
  `behavior.evaluate`, and a chain with its ordinary counterpart in `bench/fixtures/drill-chains.json`.
- **A model format:** a reader in `models.py` that lists what loading would import or call, and a case in
  `bench/fixtures/model_bytes.py` (assembled, never loaded) with its benign twin.
- **A new agent:** its configuration files in `surfaces/agent_configs.py`, its hook protocol in `hooks.py` and
  `agents.py`, its user-level files in `watch.locations()`.

Every change keeps the benchmark at 0 benign flagged, the fuzzer at 0 got past, and the 30 popular repositories
unblocked ([CONTRIBUTING.md](../CONTRIBUTING.md)).
