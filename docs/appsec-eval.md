# How well `pah appsec` works: the held-out evaluation

The twelve apps `pah appsec` was tuned on (2026-11-25) say how it does on those twelve. This evaluation asks how it
does on apps it has never seen. The protocol is in [bench/appsec_eval.py](../bench/appsec_eval.py); the sample, its
pinned commits and the answer key are in
[bench/fixtures/appsec-heldout-round1.json](../bench/fixtures/appsec-heldout-round1.json), committed before the first
run.

## The sample (round one)

| Stratum | Apps | What it measures |
| --- | --- | --- |
| Built to be vulnerable | VAmPI, dvws-node, vulnerable-node, Vulnerable-Flask-App, dvpwa, Tiredful-API, DSVW, Damn Vulnerable GraphQL Application, crAPI | Recall: the share of the vulnerabilities each app documents, in the fourteen classes, that a true finding points at |
| Well built | umami, BoxyHQ SaaS Starter Kit, ixartz SaaS Boilerplate, Hackathon Starter, node-express-boilerplate, express-rest-boilerplate, microblog, FastAPI RealWorld, Django Styleguide Example, supabase-nextjs-template | False alarms on careful code (and any real bugs) |
| Built with AI | 15 apps generated with Lovable that have a Supabase backend, drawn in a seeded order from a GitHub code search for the sentence Lovable writes into every README | The population the tool is for |

The answer key for the vulnerable apps lists the vulnerabilities each app's own documentation names, each mapped to
one of the fourteen classes or marked out of scope (command injection, SSRF, XXE, JWT flaws and the like, and code in
Go or Java). It was written by a reviewer that did not write the rules, from the documentation alone, before the run: 68
documented vulnerabilities in scope (SQL and NoSQL injection 17, XSS 15, IDOR 13, mass assignment 7, admin routes 5,
uploads 3, committed secrets 3, prompt injection 3, quantities 2, prices 1) and 106 out of scope.
Vulnerable-Flask-App documents none, so it counts for precision only. One documented secret in vulnerable-node exists
only in git history; the apps are fetched without history, so it is listed as not measured rather than missed.

## How findings are labeled

Every finding at medium or above is labeled by reviewers that did not write the rules, reading the code of the
fetched app (never running it):

- **true**: an attacker can do what the finding says, and nothing elsewhere in the repository stops it. A real hole
  reported under the wrong class, or with a message that misdescribes it, is still true; the reason says so.
- **false**: the code is not exploitable as the finding claims. Typical reasons: the check exists in another file (a
  middleware, a policy, a wrapper), the value is not attacker-controlled, the code never runs in production (a
  seed script, a story, a demo), or the data is public by design.
- **uncertain**: the answer depends on something outside the repository (hosting settings, a database policy kept
  only in the dashboard, how a third-party service behaves) or on intent the code does not show. The reason names
  what is missing.

In the vulnerable apps the reviewers also note which documented vulnerability a true finding points at; recall counts
a documented vulnerability as caught when at least one true finding points at it.

Precision is true / (true + false), with a Wilson 95% interval; uncertain findings are shown apart, as bounds. The
run is made once, with the code of the commit that pre-registered the sample, and reported whatever it shows. Fixes
made because of it are measured on a fresh draw, and these 34 apps join the development set.

## Results (round one, 2026-11-25)

One run of the code pre-registered at `2a76249` (code hash in the results file): 34 apps, 7,845 files, 93 seconds in
all (median 1.1 seconds per app, longest 19). 249 findings at medium or above, every one labeled.

**It is not yet precise enough to trust on its own.** About one finding in five is a real hole.

| | Findings | True | False | Uncertain | Precision (95% interval) |
| --- | --- | --- | --- | --- | --- |
| All | 249 | 52 | 184 | 13 | **22%** (17–28%) |
| Built to be vulnerable | 77 | 40 | 37 | 0 | 52% (41–63%) |
| Well built | 64 | 0 | 51 | 13 | **0%** (0–7%) |
| Built with AI | 108 | 12 | 96 | 0 | **11%** (7–18%) |
| High severity | 145 | 36 | 96 | 13 | 27% (20–35%) |
| Medium severity | 104 | 16 | 88 | 0 | 15% (10–24%) |

On the ten well-built apps it found nothing real: every finding there is a false alarm, apart from thirteen sample
keys in one `.env.example` whose status the repository cannot show. On the twelve tuning apps the same code raised a
single (real) finding on eight well-built apps; the difference is how much the tuning flattered it.

**It finds about a third of what the vulnerable apps document.** Recall is **25 of 68 (37%, 26–49%)**. The reviewer of
the vulnerable apps pointed out that four entries of the answer key sit in vulnerable-node's `sast/seeds` files, which
the app never runs, so no finding on them can be labeled true; without them recall is 25 of 64 (39%). That adjustment
was made after the run and is shown only beside the pre-registered figure.

| Class | Caught | | Class | Caught |
| --- | --- | --- | --- | --- |
| Query your database (W012) | 11 / 17 | | Edit the price (W007) | 1 / 1 |
| Script in your username (W001) | 4 / 15 | | Order -1 items (W010) | 2 / 2 |
| Change the ID in the URL (W002) | 4 / 13 | | Prompt injection (W005) | 0 / 3 |
| Admin at signup (W006) | 3 / 7 | | Upload a non-photo (W014) | 0 / 3 |
| Type /admin (W003) | 0 / 5 | | .env in Git (W013) | 0 / 2 |

**But in apps built with AI it found real holes.** Four of the fifteen Lovable apps had at least one true finding (12
in all): Supabase policies that let anyone with the public key overwrite or read other users' rows, a stored XSS through
content any user can publish, a payout computed from odds the client sends, and a "paid" flag the browser sets for
itself. These are the holes the tool exists for, and nothing else in the app's own tooling caught them. Their
owners have not been told; the details stay out of this repository (see below).

### Why it was wrong

Precision by rule: SQL and database rules (W012) 31%, ID lookups (W002) 60%, quantities (W010) 80%, mass assignment
(W006) 42%, prices (W007) 33%; XSS (W001) 13%, committed secrets (W013) 15%, payment proof (W008) 5%, admin routes
(W003) 0 of 25, login codes (W011) 0 of 5. The reviewers' reasons group into a few causes, which are the work for
round two:

1. **Supabase migrations read one statement at a time.** A policy dropped or replaced by a later migration was still
   reported, and table names were taken from comment lines (`-- Create table for ...`). About 40 false alarms in the
   apps built with AI. The migrations need to be replayed in order and comments ignored.
2. **Checks kept in another file.** All 25 admin-route findings were false: umami checks the role in a permissions
   module every admin handler calls, other apps check it per route or in row level security, and admin pages that are
   client shells fetch only from protected APIs. This is the cross-file reasoning the rules do not have.
3. **Code that never runs in production.** Unused copies of jQuery and Materialize (13 findings), a Deno test client,
   payment pages no route serves, seed scripts.
4. **Values the attacker does not control.** The stock shadcn `chart.tsx` in every Lovable app (14 findings: its
   HTML comes from developer colours), HTML from the operator's own upstream service, React output.
5. **Words that look like payments.** `status: 'completed'` on a padel match or a league is not a payment.
6. **Sample values in `.env.example`.** Documented test keys, publishable keys and generated example secrets.

And the misses: admin routes, prompt injection and uploads went undetected in the vulnerable apps; a signing key in a
`jwks.json` file was not flagged; and a reviewer found a hole outside the fourteen checks altogether, a
`SECURITY DEFINER` database function that lets any signed-in user make themselves admin.

### What is published, and what is not

The apps built with AI are real people's projects, and a true label says where one can be attacked. The published
results ([bench/results/2026-11-25-appsec-heldout.json](../bench/results/2026-11-25-appsec-heldout.json)) list them
under pseudonyms in an order that is not kept, with each finding's rule, severity and label only; the published labels
([bench/fixtures/appsec-heldout-round1-labels.json](../bench/fixtures/appsec-heldout-round1-labels.json)) cover the
other two strata in full. `python bench/appsec_eval.py score bench/results/2026-11-25-appsec-heldout.json` reproduces
every number above. The full results and labels are kept outside git (`bench/private/`).

### What happens next

Round two fixes the causes above (migration replay, cross-file guard resolution, reachability, and the confidence of
each finding, so that a weak match is reported as such), then measures them on a fresh draw. These 34 apps join the
development set; they are not evaluation data any more.
