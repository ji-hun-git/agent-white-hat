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

## Results

Not run yet.
