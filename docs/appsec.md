# Checking your own app: `pah appsec`

`pah scan` asks whether code someone else wrote is safe to open. `pah appsec` asks the other question: can someone
break into the app your agent built for you? It reads the code for the fourteen holes attackers try first in web apps
made quickly with AI, the ones on every "how I hacked a vibe-coded app" list:

| # | The attack | Rule | What the check looks for |
| --- | --- | --- | --- |
| 1 | Script in your username | PAH-W001 | `dangerouslySetInnerHTML`, `innerHTML`, `v-html`, `{@html}`, `\| safe`, `<%-`, `{{{ }}}`, `Markup`/`mark_safe`/`render_template_string` built from data, request data pasted into an HTML response; nothing a sanitizer has cleaned |
| 2 | Change the ID in the URL | PAH-W002 | A route that looks a record up (`findUnique`, `findById`, `query.get`, `objects.get`) by an ID from the request with no owner in the query and no owner check after it; Django REST Framework viewsets that serve `objects.all()` without `get_queryset` |
| 3 | Type /admin | PAH-W003 | Admin routes, routers mounted at `/admin`, Next.js admin pages and Flask or FastAPI admin blueprints with no role check on the server (a sign-in alone is not one); a Next.js `middleware` that checks the role covers them |
| 4 | API key in the browser | PAH-W004 | Secret names behind a public prefix (`NEXT_PUBLIC_OPENAI_API_KEY`, `VITE_SUPABASE_SERVICE_ROLE_KEY`), `dangerouslyAllowBrowser: true`, AI and payment APIs called from browser code, and real keys (OpenAI, Anthropic, Stripe live, Supabase service role, ...) written into browser code |
| 5 | Prompt-inject your AI | PAH-W005 | The model's answer passed to `eval`, `exec`, a shell, raw SQL or `innerHTML`; request text written into the system prompt |
| 6 | Admin at signup | PAH-W006 | The whole request body saved into a record (`User.create(req.body)`, `data: body`, `User(**request.json)`, `setattr` over the request), `role`, `isAdmin`, `plan` or `credits` set from the request, roles read from Supabase `user_metadata`, `fields = "__all__"` |
| 7 | Edit the price | PAH-W007 | `unit_amount`, `price`, `total` or `amount` taken from the request in payment code. Looking a price up by an ID from the request is fine |
| 8 | Fake a payment | PAH-W008 | Webhook routes that never verify the provider's signature, success pages that mark an order paid without asking the provider, browser code that writes `is_pro` or `paid` itself |
| 9 | Redeem it 100 times | PAH-W009 | Coupon, gift card, credit and stock code that reads, checks "used" and then updates in separate steps, with no conditional update, lock or unique constraint |
| 10 | Order -1 items | PAH-W010 | A quantity from the request with no lower bound, especially when it is multiplied into a total; zod `quantity: z.number()` and pydantic `quantity: int` without one |
| 11 | Guess the login code | PAH-W011 | Routes that compare a login or reset code with no attempt limit anywhere (route, file or a global rate limiter), and codes made with `Math.random()` or Python's `random` |
| 12 | Query your database | PAH-W012 | SQL built from template literals, f-strings, `%` or `+` (`sql\`\`` tagged templates and parameters are fine); Supabase tables with no row level security, policies with `using (true)`; Firebase rules in test mode or `if true`; MongoDB `$where` built from data, and request values put into a MongoDB query as sent (`{"$ne": null}` matches any record) |
| 13 | .env in Git | PAH-W013 | `.env` files git tracks, `.env` files in git history after they were deleted, `.env` files with secrets that `.gitignore` does not cover, real keys in `.env.example`, real keys in code |
| 14 | Upload a non-photo | PAH-W014 | Uploads saved under the name the uploader sent (`file.originalname`, `file.name`, `f.filename` without `secure_filename`), stored with no type or size check, or with SVG allowed |

```
pah appsec                    # this folder
pah appsec path/to/app --json # every finding, for an agent or a script
pah appsec . --sarif-out appsec.sarif --github   # in GitHub Actions: annotations and code scanning
```

High findings make the verdict FIX (exit 2), medium ones REVIEW (exit 1). Each finding names the file, the line and
the fix. Secret values are never printed: a key shows as its kind and first four characters.

## While your agent writes the code

With the Claude Code hooks installed (`pah install`, or the plugin), every file the agent writes or edits is checked
for the holes that one file can show on its own: HTML from data, keys in browser code, model output run as code, a
whole request saved into a record, prices from the request, unsigned webhooks, guessable codes, SQL built from
strings, keys in code and upload names. The agent gets the finding and the fix right after the write, as context, and
fixes it before moving on. It never blocks the write. Ownership, admin routes, races, rate limits and row level
security depend on other files, so only `pah appsec` reports those. `PAH_NO_APP_HINTS=1` turns the notes off.

## What it is and is not

- **It reads, never runs.** Like `pah scan`, nothing in the folder is executed. In a git repository it asks git which
  files are tracked and which `.env` files history holds, with hooks and fsmonitor switched off.
- **It is a set of heuristics, one route handler or one file at a time.** It knows Express, Hono, Fastify, Next.js
  (route handlers, pages, server actions, middleware), SvelteKit, Flask, FastAPI, Django and Django REST Framework,
  Prisma, Mongoose, Sequelize, Supabase, Firebase and Stripe well, and other stacks less. It can miss a hole that spans
  files, and it can flag code whose protection lives somewhere it did not look; each finding says what it saw.
- **A PASS is not a security review.** Hosting settings (is row level security on in the dashboard? is the webhook
  secret set?), dependencies (`pah audit --online`), business rules and anything decided at run time are outside it.
  [skills/app-security](../skills/app-security/SKILL.md) walks an agent through the rest, attack by attack.
- **Test, fixture and example files** are reported as low at most; dependencies and build output (`node_modules`,
  `dist`, `.next`, minified and hashed bundles) are skipped.
- **How well it works, measured on apps it had never seen** ([the held-out evaluation](appsec-eval.md)): about one
  finding in five is a real hole (52 of 236 labeled, 22%); none of 64 findings on ten well-built apps was real; and it
  catches about a third of the vulnerabilities that apps built to be attacked document (25 of 68). In apps generated
  with AI it found real holes in four of fifteen (open Supabase policies, stored XSS, a client-set payout, a browser
  that marks itself paid), at 11% precision. Treat every finding as a lead to confirm by reading the code, which is
  how the agent-facing skill uses it. On the twelve apps it was tuned on it looked far better; that difference is the
  reason the measurement exists.
- **It does not change the scan.** These rules live in their own command; `pah scan`, its benchmarks and the
  held-out evaluation are untouched.
