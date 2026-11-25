---
description: Check your own web app for the 14 holes attackers try first (XSS, IDOR, open /admin, keys in the browser, prompt injection, fake payments, .env in git, ...)
argument-hint: "[app folder; default: current folder]"
---

Check the app in `$ARGUMENTS` (or the current folder if empty) with agent-white-hat and fix what it finds.

1. Run `pah appsec "<folder>" --json` if `pah` is installed; otherwise `python3 -I "${CLAUDE_PLUGIN_ROOT}/pah_entry.py" appsec "<folder>" --json` (use `python` or `py` if `python3` is missing).
2. Lead with the verdict (FIX, REVIEW or PASS) in the user's language, then each high and medium finding: rule, file:line, the attack in one sentence and the fix.
3. Confirm each finding by reading the code around it; drop it only if a guard elsewhere really covers it, and say where.
4. Offer to fix them, smallest change first, and run the check again afterwards. Follow skills/app-security for what the code alone cannot show. Never print secret values; tell the user which keys to rotate.
