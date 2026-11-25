# Changelog

## Unreleased

**Shields for an incident happening now, and a protection log.** After Shirudo (OpenAI and Cisco, November 2026),
which shields a running service from one exploit path until its patch ships, `pah shield` adds narrow guard rules for
the days between an advisory and its fix: a package version an agent would install (`npm:@ctrl/tinycolor@4.1.1`; an
install without an exact version counts, since it may resolve to it), a command pattern, a host and its subdomains, or
a path the agent writes or reads. A shield starts in monitor mode: it records what it would have denied or asked
about, with what the guard alone decided, and changes nothing until the user runs `pah shield enforce`;
`pah shield report` shows how many of its matches the guard would otherwise have let through, and
`pah check-command` names monitor shields without counting the question. Every shield expires, after 14 days unless
told otherwise and never more than 90. Shields judge commands once their disguises are undone, and `package.json` and
`requirements*.txt` the agent writes. A shield can only make the guard stricter, a broken `shields.json` leaves the
rest of the guard as it was, and shields that would match everything (a pattern matching an empty command, a path of
wildcards) are refused. Bundles of shields from a publisher are signed with Ed25519 (`pah shield keygen`, `sign`) and
imported only when a key the user trusts signed them (`trust-key`, `verify`, `import`); they arrive in monitor mode
whatever the publisher wrote. The standard library cannot verify signatures, so `pah/ed25519.py` implements RFC 8032
in pure Python, tested against the RFC's vectors and, both ways, against OpenSSL 3.5. Every change to what the guard
allows now goes into `protection-log.jsonl`, each entry chained to the one before by SHA-256: shields and keys, `pah
trust`, `pah watch init` and `accept`, `pah install --yes`, quarantine, and protection at login. `pah log verify` shows
an entry edited, removed or reordered, a tail cut off and a deleted log, and compares the shields and keys on disk with
what the log says they should be; `--anchor` checks against a head noted somewhere else, which is what shows a history
rewritten whole. The guard asks before an agent runs the shield commands that change protection
([docs/shields.md](docs/shields.md)). Scanning is untouched: no rule changed, and the scan never loads the guard or
shields, so round three of the held-out evaluation gets the same verdicts on either side of this change (the code hash
its results record covers every file in `pah/`, so that hash will differ). TrapRepo, the fuzzer and both drills give
the same verdicts as before.

**A held-out test on real malware.** `bench/independent.py` measures the rules on software they were never tuned
on: a random draw of 1,423 malicious samples from Datadog's malicious software packages dataset (npm and PyPI packages
published to attack, agent skills, IDE extensions and hijacked releases of real packages) and the latest release of
1,000 of the most-downloaded PyPI and npm packages. The sample and protocol were committed before the first download
(71e982b). Every file was unpacked and scanned in memory, through the new `pah.scan.scan_files`, and nothing was
written to disk or run. It caught 56% of the npm and 66% of the PyPI packages published to attack, 37% of the agent
skills, 23% of the IDE extensions, and 88% and 82% of the hijacked npm and PyPI releases; it flagged 10.9% of the
popular packages and blocked 3.3%. TrapRepo's 76 of 76 measures how well the rules cover the techniques they were
built against; these numbers measure the rest. Most misses run their code at another moment than setup (on import,
when an editor extension activates) or attack through a skill's instructions; most blocks of popular packages come
from the obfuscated-code rule on bundled JavaScript, invisible characters in Unicode test data, `.pth` startup hooks
and prebuilt binaries. `docs/statistics.md` gives every rate an exact 95% interval and names every flagged package;
the README's new figure is a forest plot of all of it.

**The guard reads disguised shell commands.** Scored on ViKernel's shell benchmark (FINAL-Bench/Obfuscated-Shell-Gate,
the public dev split: 222 bash commands, each risky one paired with a harmless one in the same disguise), the guard
first reached 55.5 balanced accuracy. It denied anything decoded into a shell, harmless or not, and could not read
`${IFS}`, quote and backslash breaks, octal `printf`, rot13 or reversal. The new `pah/shellfold.py` works out what a
command really runs without running it (those breaks, variables, runners such as `script -qc`, `watch` and `bash -c`,
and pipelines through base64, hex, `printf`, `tr`, `rev` and gzip), and the same rules judge that. A decode-and-run
whose payload decodes completely to nothing risky is reported, not blocked; one that cannot be read is still denied.
Written against half of the commands and measured on the other half, it lifted balanced accuracy there from 56.0 to
93.8 (exact McNemar p = 3.7e-11); on the whole set it scores 96.1 and lets every harmless command through. New
single-step checks for an agent's commands: deleting or silencing logs (PAH-C030, denied), recursive or bulk deletion
outside the project folder (asked), a program downloaded and made executable (asked; denied over plain HTTP, from a
bare IP or a look-alike host), and a file with a secret-looking name uploaded anywhere (denied). TrapRepo, the fuzzer,
both drills and the 30 popular repositories give the same verdicts as before.

**What the held-out test taught.** Round one's false alarms and misses, studied only on samples that round two does
not measure, led to the fixes below. Round two is a fresh draw committed before its download (f36ee66). It judged
every sample with both these rules and round one's (`bench/independent.py run --baseline 71e982b`), and
`bench/stats.py` tests the difference set by set with an exact McNemar test, Holm-adjusted, an analysis fixed before
the download. Its results close this entry.

*False alarms.* A message wrapped with `+` for line length is not obfuscation when the URL or name in it is written
out whole elsewhere in the file; escapes, character codes and ROT13 count however often the name is spelled out.
Zero-width joiners between letters of scripts that need them (Persian, Indic, Sinhala, Lao, Mongolian) are not hidden
text. Invisible characters inside string literals are reported low when there are only a few, or when they sit in
bundled files or test data, unless eight or more zero-width characters run together and spell out data. A `.pth` file or
`sitecustomize.py` inside a folder does not run at startup, and a `.pth` that imports the package's own module is
judged by that module, which is how editable installs work. Reported low or not at all: native extensions (`.pyd`)
and binaries in wheels or in npm packages built for named platforms, bytecode cached in `__pycache__` without its
source (except in a skill, which can tell the agent to run it), submodule pointers inside the tree, install commands
in a README, development dependencies, git dependencies pinned to a commit, long lines in data files such as source
maps, `marshal` used to store data, near-identical names among a package's own dependencies (types-boto3-rds and
types-boto3-drs), and the documentation domains (example.com).

*Misses.* Decoded code run through a renamed module (`import base64 as b`), a decryptor or a helper function, or
decoded into a variable that runs later; the machine's name or user sent out while installing, in a URL or a DNS
lookup; a download written, made executable and run from Python; a package that publishes itself (PAH-C031, how the
IndonesianFoods worm spread); an attack tool fetched at install (PAH-C032). In an entry file, the code that runs as
soon as a package is loaded (npm `main`, an editor extension activated at startup, a top-level `__init__.py`), a
capture or tunnel endpoint and details of the machine sent out now count as high, since nothing has to call them, and
so does a program that such an editor extension downloads and runs. Skills that require a program downloaded from a
link, run commands from a Python or JavaScript block, or tell the agent to run code without checking it are caught.

*The guard* denies a recursive search for passwords, tokens or keys in credential folders (`grep -r token ~/.config`,
`find ~ -name '*.pem'`); the same searches inside the project still run. ViKernel's dev split now scores 100.0 (103
of 103 risky commands stopped, 119 of 119 harmless ones let through; `bench/results/2026-11-19-tuned-shellgate.json`),
a tuned figure, since every command in it had been read; the held-out 93.8 above is the measurement.

*On the samples they were written against* (tuning data, not a measurement), the rules now catch 395 of round one's
500 npm packages published to attack (round one: 280), 373 of 500 PyPI ones (332), 52 of the 102 agent skills studied
(37), 16 of the 51 IDE extensions studied (13), 85 of 100 hijacked npm releases (88) and 7 of the 8 hijacked PyPI
releases studied (7), and they flag 43 of the 1,000 popular packages (109) and block 13 (33). 93 of the 115 new npm
catches are spam packages that publish copies of themselves, 68 of them named the IndonesianFoods way (an Indonesian
name, a food and a number); without PAH-C031 the npm rate would be 302 of 500. The four catches lost were
coincidences: three hijacked @mastra releases carry their payload in an added dependency named to pass for dayjs
(easy-day-js), which a scan of the package itself cannot see, and round one flagged them only for long lines in their
source maps; a copy of Microsoft's React Native Tools under another publisher was flagged only for invisible
characters in strings and a look-alike name in its README. TrapRepo, the fuzzer, both drills and the 30 popular
repositories give the same verdicts as before.

*Measured on round two* (2,262 fresh samples, none left out, run once): the rules catch 911 of 1,262 malicious samples
where round one's caught 737 on the same files (176 caught only now, 2 only before; exact McNemar p = 1.7e-49, Holm),
and flag 53 of 1,000 popular packages where round one's flagged 108 (2 only now, 57 only before; p = 6.1e-15); 24 are
blocked, against 37. By set: npm packages published to attack 74.8% (round one's rules 52.4%), PyPI ones 74.2%
(67.2%), agent skills 56.9% (37.3%) and IDE extensions 35.3% (19.6%), each significant after Holm's adjustment;
hijacked releases unchanged in npm (84 of 100) and one fewer in PyPI (6 of 9); popular PyPI projects flagged 8.8%
(14.0%), popular npm packages 1.8% (7.6%). 92 of the 113 new npm catches rest on PAH-C031 alone. Each catch lost
rested on one medium finding a fix lowered (a long line in a data file; a name close to a popular package's). Both
new false alarms are blocks by the entry-file rule: esptool, whose serial-port server reads the machine's name next to
its network code in an `__init__.py`, and disposable-email-domains, whose list of domains includes webhook.site. Most
misses still run on import or when an extension activates, or are written as instructions. No rule changed after the
run. `docs/statistics.md` adds what changed, counted after the results, and the README a forest plot of both versions
on the same samples.

**Round three is drawn** (`bench/fixtures/independent-sample-round3.json`), before any rule changed after round two:
500 npm and 500 PyPI packages published to attack, 100 hijacked npm releases and 1,000 popular packages, none of them
in rounds one or two. The dataset's newest commit is still 72c723b, so with nothing added since round one, the agent
skills, IDE extensions and hijacked PyPI releases are used up and round three cannot measure fixes for them. It will
run against the code round two measured (`--baseline 3c92edf`), with round two's analysis; this time the description
of what changed is fixed before the download too. `bench/independent.py plan --exclude` takes several earlier
samples, and leaves their packages out of the sets taken whole unless `--split` halves them.

**What round two taught.** Round two's misses and false alarms were studied only after round three was drawn and
pushed (f3b41d8), and led to the fixes below; round three measures them. Each principle is pinned by a test in
tests/test_heldout_lessons.py with inputs written for it. Malicious samples were looked at in memory and by shape
only (strings emptied, hosts removed): one diagnostic file that held redacted lines was blocked by the antivirus, which
means it touched disk, and was deleted.

*Misses.* Install scripts that take the user or machine name in a shell (`$(whoami)`, `$USER`, `%COMPUTERNAME%`) and,
a few statements later, run a network command built from variables, as the beacons that hex-encode the name into a
subdomain do (PAH-C004, high). Reverse shells written over several statements: a socket connected out and handed to a
shell through `os.dup2`, or piped to a spawned shell in Node (PAH-C021). A string that code writes to a file and then
runs is judged as code, which catches droppers that keep their second stage, a download that is run, in a string. A
setup.py that replaces pip's install steps and makes a network call warns (PAH-C006, medium): none of the 2,000
popular packages of rounds one and two does. Discord's and Telegram Desktop's token stores count as credentials.

*False alarms.* Invisible characters in a table of characters (a whitespace set, an identifier class in a grammar, a
list of named symbols, a regex class), in test data files, and an emoji's presentation selector repeated are not
hidden text; files in a top-level `dist/` folder count as bundles; a run of distinct zero-width characters is a set,
not a payload. A quoted piece that a method applies to (`"&".join(names)`) is not a literal piece of a hidden string,
and a dotted grammar scope (`keyword.other.constructor.constructor-type`) is not the Function constructor. In an entry
file, only code that runs on import is raised: not a function that nothing calls while importing (a server's
`main()`), and not a name in a list of names. Reported low instead of medium or high: an in-tree build backend for
existing (its code is judged as install-time code), install commands from code hosts over SSH or git and public PyPI
mirrors in documentation, registry flags pointing at documentation domains, escape bytes inside PDFs, megabyte lines
in minified bundles outside the code that runs on load, and `core.hooksPath` set to a folder inside the project, as
hook managers do. Checking against the 30 popular repositories narrowed the beacon rule before commit: `uname -a` is
how nvm and the Maven wrapper tell the operating system, and a `whoami` in an error message far from a download is not
a beacon.

*On round two's samples* (tuning data, not a measurement), against round two's code: 383 of 500 npm packages
published to attack caught (374), 399 of 500 PyPI ones (371), 58 of 102 agent skills (58), 16 of 51 IDE extensions
(18), 84 of 100 hijacked npm releases (84) and 6 of 9 hijacked PyPI releases (6); popular packages flagged 28 of 1,000
(53), blocked 10 (24); of round one's popular packages, 36 flagged (43), blocked 9 (13). No popular package of the
2,000 is newly flagged. The two IDE extensions lost, copies of basedpyright and a Smarty formatter, had been caught
only for megabyte-long lines in their language-server bundles, which the originals share. TrapRepo (76 of 76, 0 of
40), the fuzzer (353 of 353), both drills and the 30 popular repositories give the same verdicts as before.

*Not fixed.* Clones of the pino logger that start a detached copy of Node on one of their own scripts when loaded
(10 of round two's npm misses): the shape is update-notifier's own, and telling them apart needs what the started
script does, in another file. Hijacked @mastra releases, whose payload sits in an added dependency. Most misses still
run on import or when an extension activates, or are written as instructions.

## 0.5.1 (2026-11-17)

**Fixed: a download in a long folder was not matched to its run.** The session record masks anything token-shaped,
and that masking also shortened long paths. macOS keeps its temporary folder under `/var/folders/<random>/T/`, so a
file downloaded there and later unblocked, made executable or run was not recognized as the download (PAH-B002), and
the Windows-style download, `Unblock-File`, `Start-Process` chain went through on macOS. CI's chain drill caught it on
macOS, where 68 of 77 attack runs were stopped; Linux and Windows were not affected. Paths that later steps are
compared with are now kept whole (they are local paths, and commands are still masked), and a test with a long
temporary folder keeps it fixed. The chain drill is back to 77 of 77 on every platform.

## 0.5.0 (2026-11-17)

**Attack chains, judged as chains.** Each step an agent takes is now recorded per session, as a short description with
anything token-shaped masked (no file contents, output or secret values, and nothing leaves the machine), and judged
against the steps before it, the way endpoint products judge behavior rather than single events (CrowdStrike's
indicators of attack, Cortex XDR's causality chains). Seven rules: credentials read, then data sent to a host that is
not a known service (PAH-B001); a downloaded file made executable or run, a step at a time (PAH-B002); a sensitive step
after a tool returned injected instructions (PAH-B003); persistence set up after a download (PAH-B004); the guard or an
agent's permission checks switched off (PAH-B005); history cleared after credential access (PAH-B006); credentials
collected from several stores or packed into one file (PAH-B007). It works in all nine agents, through each agent's own
session id, and `pah session list | show` prints the steps behind each alert. MCP tool calls now pass the guard too.

**What tools return is checked before the agent acts on it.** Web pages, search results, MCP results, issue text and
files in projects you have not trusted are read for text aimed at the agent: overrides of its instructions, fake
system or tool-result markers, orders to act without telling you, requests for secrets, image links built to carry
data out, the same text hidden in invisible Unicode, and terminal sequences that write the clipboard (PAH-O001 to
PAH-O004). The agent is told to treat the output as data, and the rest of that session's sensitive steps need your
approval: a runtime form of keeping untrusted data away from actions (CaMeL, FIDES). Codex and Gemini CLI replace a
high-severity output with the warning; Claude Code, Cursor and Copilot get the warning next to it. `pah install` adds
these output hooks, and now updates an earlier version of its hook entries in place.

**Model files.** Pickles (raw, in PyTorch zips, joblib, NumPy object arrays, compressed, or nested in another pickle),
Keras archives and HDF5 files, GGUF chat templates, 7z-packed checkpoints and model repositories that run their own
code are read without being loaded, as Protect AI's ModelScan and Trail of Bits' fickling do (PAH-M001 to PAH-M006): a
pickle that imports `os.system` or `builtins.exec`, a Lambda layer with bytecode or a config that names arbitrary
functions (CVE-2025-1550, CVE-2025-9906), a chat template that reaches `__globals__` (CVE-2024-34359), a stream that
breaks right after its payload (nullifAI), and the files `auto_map` makes `trust_remote_code` import (the Load/Mine
campaign), whose code is then judged as code that runs on its own. Files too large to read whole are judged from the
parts that can run code. A command that loads a model (`from_pretrained`, `torch.load`, `joblib.load`, `llama-cli`)
now has the folder scanned first, like `npm install`.

**Tamper protection.** A write that turns off hooks, permission prompts or this guard in an agent's settings
(`disableAllHooks`, `bypassPermissions`, the plugin disabled, Codex's `danger-full-access` or `approval_policy =
"never"`) is denied rather than asked about. Doing it after untrusted content or a download is a chain (PAH-B005).

**Incidents from June to November 2026.** IronWorm, the Hades PyPI wave, Agentjacking, CVE-2026-54316 (an issue that
made Claude Code in CI leak its key), SANDWORM_MODE and Load/Mine join the catalog, now 39 incidents, each with its
response in order.

**Measured:** TrapRepo 76 of 76 malicious repositories caught, with 11 model cases added (6 malicious, 5 benign
twins), 0 of 40 benign flagged; attack drill 1,131 decisions, 0 unexpected; chain drill (new, `bench/chains.py`) 77 of
77 attack runs stopped across the nine agents, 51 of them only because of the steps before, and 0 of 72 ordinary runs
given a prompt the same steps would not get on their own; fuzzer 353 of 353 rewrites caught, 0 of 12 harmless
rewrites flagged; 30 popular repositories 26 pass, 4 warn, none blocked (67,014 files), the same verdicts as 0.4.0 at the same commits.

## 0.4.0 (2026-11-17)

**Real incidents, and what to do about each one.** A catalog of 33 attacks on people who use AI agents, from
s1ngularity (August 2025) to MIDNIGHT NEPTUNE (November 2026): what happened, how it got in, which rules and trap
repositories cover it, the files it leaves on a computer, and the response in order, each with its sources
([docs/incidents.md](docs/incidents.md)). `pah incident list | show | check`, the MCP tool `incident` and `pah checkup`
read it. Order is the point: ChainDrop, strutil-core and the testmetest worm wipe the home folder when their stolen
token is revoked, so their responses remove the persistence before any token is touched. Added from August to November
2026: ChainDrop, WFX Phantom, MIDNIGHT NEPTUNE, strutil-core, the Paperclip and Browser Use skill clones,
@subql/common, the arrayref crates, Deadbugz, unauthorized Codex and Claude Code relays, and `.pth` typosquats of AI
libraries.

**`pah diff`: what a new version does that the old one did not.** Capabilities (network, sending data, processes,
dynamic code, credentials, persistence, decoding, install hooks) are compared file by file, as Chainguard's malcontent
does; code that runs on its own and gains one is reported (PAH-D001), with new dependencies and findings that are new.
With `--source`, a published package is compared with its source at the same tag, as LastPyMile and OSS Rebuild do:
code that runs on its own and exists only in the package blocks (PAH-D002). Folders and archives both work, and an npm
tarball lines up with its folder.

**Agent setups as a whole.** When a tool that brings in content anyone can write and a tool that sends data out both
run without asking, the agent's access to your files completes the lethal trifecta: a repository's settings or your own
setup (`pah checkup`) is reported (PAH-A021). Pre-approved commands that run any program through their arguments, such
as `find -exec`, `go test -exec`, `rg --pre` and package runners, are reported too (PAH-A020), after Trail of Bits'
argument-injection work.

**New detection from the incidents.** RubyGems native extensions (`extconf.rb`, and whatever a gemspec lists under
`extensions`) run at gem install and are now judged as install-time code. A file that install-time code starts through a
runtime (`bun Math_Symbol.js`, `spawn(bun, ['x.js'])`) is install-time code too. Documents a skill tells the agent to
follow before first use are read as part of the skill. A workflow that hands `toJSON(secrets)` to a repository script
that posts them blocks. A download decoded on its way to an interpreter (`curl … | base64 -d > /tmp/t.mjs && node
/tmp/t.mjs`) is high wherever it is written. Nine TrapRepo cases cover these and the agent-setup checks, two of them
benign twins.

**Modular.** The two largest modules were split by responsibility. `patterns.py` became the content rules plus host
trust (`hosts.py`), where a match sits (`codectx.py`), decoding (`deobfuscate.py`), campaign shapes (`campaigns.py`) and
the rule catalog (`content_rules.py`); `surfaces.py` became a package with one module per kind of file (agent
configurations, instructions and skills, MCP, editors, workflows, git, environment). Benchmark, drill and fuzzer results
were identical before and after the split. [docs/architecture.md](docs/architecture.md) maps the modules and says where
a change goes.

**Calibrated on popular repositories.** The 30-repository check, run at each project's current commit (19 had moved
on since 0.3.0), caught five false alarms while this release was built. All were fixed and are kept as tests
(`tests/test_calibration.py`): a shell script kept in a Rust raw string in Codex's sandbox tests (multi-line raw strings
in test suites are now data, like Python's triple-quoted strings), a skill's link text read as an instruction to follow
(cli/cli; the follow verb must come before the link), a reference page judged like a file the agent loads on its own
(Anthropic's skills; documents a skill sends the agent to are read like setup documents), an attacker's phrase quoted
in a warning (everything-claude-code), and a test file that a setup document says to run (everything-claude-code).

**Measured:** TrapRepo 70 of 70 malicious repositories caught, 0 of 35 benign flagged; attack drill 1,032 decisions,
0 unexpected; fuzzer 347 of 347 rewrites caught, 0 of 11 harmless rewrites flagged; 30 popular repositories
26 pass, 4 warn, none blocked (67,014 files).

## 0.3.0 (2026-11-12)

**Renamed to agent-white-hat.** The repository, the package, the Action and the plugin's display name are now
agent-white-hat. Like a white-hat hacker, it attacks its own rules before an attacker does (the fuzzer below). The
plugin's ID, the `pah` command, the `PAH-` rule IDs, the `~/.personal-anti-hack` folder and the default SARIF file name
keep the first name, so installed hooks and CI keep working. The pre-commit hook is `agent-white-hat` and still answers
to `agent-virus-check` and `personal-anti-hack`; GitHub redirects both old repository URLs. `pah protect --uninstall`
also removes a login item that 0.2.0 or 0.2.1 set up under its name, and the guard asks before an agent disables or
uninstalls the plugin under any of the three names.

**An evasion fuzzer.** [`bench/fuzz.py`](bench/fuzz.py) rewrites every malicious TrapRepo case in 20 ways attackers
hide a payload, across JavaScript, Python and shell, without changing what it does: strings split and joined, built
from character codes, written as hex escapes or ROT13; calls such as `execSync` and `os.system` made through brackets
or `getattr`; `require` reached through an alias; the whole file run from base64 by `eval`, `Function` or `exec`; the
payload delayed; tool names assembled in shell variables and addresses by `printf`; base64 piped into a shell.
Harmless rewrites of the benign cases' code (renamed variables, added comments) check that none of this raises a
false alarm. CI fails if a rewrite gets past or a harmless one is flagged.

**Decoding before the rules.** The first fuzz run got 8 rewrites past 0.2.1: tool names held in shell variables,
strings built from character codes, hex escapes and ROT13, calls made through brackets and `getattr`, and a payload
whose severity was lost when the decoded finding was merged with the plain one. In code, the
scanner now decodes all of these before the rules run and scans the decoded copy too; a more severe finding there
replaces the plain one, and a sensitive name or address that appears only after decoding is reported as obfuscated
code (PAH-C012). Comments and strings that only describe a trick stay quiet. Escapes count as hiding text only
when they stand for letters or digits: the check on popular repositories caught the first version of the decoding
blocking Codex, whose clickable terminal links escape only the control characters around a plain URL. A control
character added to an escaped string as padding no longer stops it from being decoded.

**Measured:** fuzzer 318 of 318 rewrites caught, 0 of 11 harmless rewrites flagged; TrapRepo 63 of 63 malicious
repositories caught, 0 of 33 benign flagged; attack drill 951 decisions, 0 unexpected; 30 popular repositories
26 pass, 4 warn, none blocked, with the same findings as 0.2.1.

## 0.2.1 (2026-11-12)

**Renamed to agent-virus-check.** The repository, the package and the plugin's display name are now agent-virus-check,
the antivirus for people who use AI agents. The plugin's ID, the `pah` command, the `PAH-` rule IDs, the
`~/.personal-anti-hack` folder and the default SARIF file name keep the old name, so installed hooks and CI keep
working; the pre-commit hook is `agent-virus-check` and still answers to `personal-anti-hack`; GitHub redirects the
old repository URL.

**A white-hat round against our own rules.** Three of six evasive variants of an install-time payload got past 0.2.0:
module and host names built from pieces (`require(['ht','tps'].join(''))`), `eval` reached through
`globalThis[['ev','al'].join('')]`, and the `Function` constructor reached through `[].constructor.constructor`.
Split string literals are now joined before the rules run, a sensitive name built from pieces is flagged on its own,
and the `Function` alias is caught. The variants are kept as tests; every bypass found from now on joins them.
The same round found that the guard let an agent delete its whole folder (`rm -rf ~/.personal-anti-hack`: only paths
inside it were caught), which holds the quarantine, the trusted projects and the configuration baseline; it now asks.

**Measured:** TrapRepo 63 of 63 malicious repositories caught, 0 of 33 benign flagged; attack drill 951 decisions,
0 unexpected; 30 popular repositories 26 pass, 4 warn, none blocked (the same verdicts as 0.2.0, so the new checks
added no false alarms).

## 0.2.0 (2026-11-12)

personal-anti-hack now does an antivirus's job for people who use AI agents, and new checks cover the attacks
reported between September and November 2026, chosen by comparing the rules with the leading scanners (GuardDog,
Socket, Cisco's skill and MCP scanners, Snyk agent-scan, zizmor, malcontent) and with the configuration files each
agent documents. 108 rules, 17 of them new.

**Antivirus duties**
- `pah sweep`: a full scan of this computer, one item at a time: Downloads and Desktop, every project in your code
  folders, installed agent skills, plugins and extensions, editor extensions; plus the checkup and the engine built
  into the operating system (Microsoft Defender) or ClamAV. Unchanged items are remembered between sweeps.
- `pah protect`: real-time protection that scans new downloads, clones, extensions, skills and startup items within
  seconds of arriving, with a desktop notification; `--install` starts it at login (Task Scheduler, a LaunchAgent or a
  systemd user service) after showing the change.
- `pah quarantine`: blocked items move into quarantine (a download, extension or skill as a whole; a project only by
  its payload files) and `restore` puts them back.
- The trojanized Claude Code extension's backdoor shapes: switching on the SSH server and a reverse tunnel to port 22.

**More agents' files**
- Hooks a repository ships for Codex, GitHub Copilot (`.github/hooks`), Kiro, Devin, Cline, Factory, Augment and
  Amazon Q; plugins for OpenCode, Kilo and Amp; Crush's startup script; Gemini CLI and Qwen Code tool commands;
  Cursor's sandbox and permission overrides; cloud-agent setup commands (Cursor, Devin); Aider's startup commands.
- Claude Code plugins: a plugin's `hooks/hooks.json`, marketplaces and plugins a project asks you to install, skill
  shell lines (`` !`cmd` ``) and `allowed-tools: Bash`, HTTP hooks, a loosened sandbox and new command settings.
- `.env` and settings that relocate an agent (`GEMINI_CLI_HOME`, `GEMINI_SYSTEM_MD`) or put the repository first on
  `PATH`; a `git.exe` planted at the top of the repository; bare git repositories inside a project; terminal escape
  codes that hide text; a `__proto__` key in VS Code workspace files.

**Campaign shapes**
- Loaders disguised as fonts and images (PolinRider), dead drops on blockchains and paste sites, worms that republish
  your packages with your token, CI backdoors, wipers that fire when a stolen token is revoked, wallet hijackers,
  hidden processes and secret sweeps at install time, payloads read out of image pixels.
- GitHub workflows: secrets sent out (GhostAction; blocks), untrusted text pasted into scripts, and AI agent actions
  that act on anyone's issue (both reported to maintainers through SARIF).
- Package managers: project settings that undo the install protections of npm 12, pnpm 11, Yarn and Bun; `bin`
  entries named after system commands.
- `pah checkup` knows the traces of PolinRider, the testmetest worm, MALFEX, SleepyDuck, Apex Accelerator and the
  trojanized Claude Code extension.

**Fewer false alarms**
- Detection tables in JavaScript (regular expressions and their labels), a local server's responses, reads of
  `git config core.hooksPath`, git installs pinned to a commit, skills' own test suites, and skills that only mention
  folders under `~/.claude`.

**Measured**
- TrapRepo: 15 new cases; 63 of 63 malicious repositories caught, 0 of 33 benign flagged.
- Attack drill across nine hook protocols: 951 decisions, 0 unexpected.
- 30 widely used repositories, everything-claude-code now among them: 26 pass, 4 warn, none blocked.

## 0.1.0 (2026-11-12)

First release.

**Scanner**
- `pah scan` maps everything in a repository, skill, MCP server, package, archive or git URL that runs without being
  read, reads every file in full (hidden Unicode, padding, encoded blobs, bytecode, archives, disguised binaries) and
  judges each finding by where the file really runs. 91 rules, each tied to an incident, CVE or paper.
- `pah audit` adds the antivirus engine already on the computer (Microsoft Defender or ClamAV) and, with `--online`,
  malicious, missing and brand-new packages and known vulnerabilities in pinned versions (OSV).
- Output as text (English or Korean), JSON or SARIF.

**Guard and agents**
- One guard for Claude Code, Codex, Gemini CLI, Antigravity, Cursor, Copilot, Devin, Kiro and Cline, each through its
  own hook protocol. Setup commands in a project that fails the scan are denied; agent settings, shell profiles and git
  hooks need your approval.
- `pah install` writes each agent's hooks, the skills and the MCP server, and shows every change first.
- Four Agent Skills: everyday rules, malware audit, security review, incident response. `AGENTS.md` lets any agent use
  the repository directly.
- `pah watch` keeps a baseline of agent and shell configuration; `pah checkup` looks for exposed keys and known traces.

**CI**
- A GitHub Action: annotations on the lines in pull requests, a job summary, a verdict output and a SARIF report for
  code scanning. `pah scan --github` and `--sarif-out` do the same from the command line.
- A pre-commit hook.

**Measured**
- TrapRepo: 54 of 54 malicious repositories caught, 0 of 27 benign look-alikes flagged.
- Attack drill across nine hook protocols: 816 decisions, 0 unexpected.
- Live drill with Claude Code and approvals off: the payload ran in 0 of 12 runs.
- 29 widely used repositories scanned in full: none blocked.
