# CLAUDE.md

Project: IP Enrichment Portal (Simple). A small local Flask app that looks up one IPv4 address
and shows a verdict plus one card per source. Read `design.md` for the full design and scope.

## Who I'm working with

Ben is an intermediate developer. He has no enterprise or full-application experience. This is a
learning project, so **understanding matters more than speed**.

- Explain in plain language. Define jargon and acronyms the first time they come up
  (for example: "an environment variable is a setting stored outside the code").
- Say *why*, not just *what*. When you make a design choice, give the reason in a sentence or two.
- Keep code simple and readable. Prefer the boring, obvious approach over the clever one.
  No new abstractions, frameworks, or libraries unless they are needed, and ask first if they are.
- Add comments that explain intent, especially for anything that might look like magic.
- Work in small steps. After a change, summarize what changed and how to check that it works.
- If something is beyond the scope in `design.md`, say so and ask rather than adding it.
- If you're unsure what Ben wants or whether he'll follow it, ask. Don't assume.
- When a real-world or "enterprise" practice applies (logging, config, error handling, testing),
  name it and explain it briefly, since Ben is here to learn those practices.

## Secrets: never commit them

No secret may ever be pushed to GitHub. This includes API keys (such as the AbuseIPDB key),
tokens, passwords, and anything in a `.env` file.

- Secrets live in `.env` and are read from environment variables. Never hardcode them in code,
  tests, docs, comments, or example output.
- `.env` must stay listed in `.gitignore`. Before any commit, confirm it still is.
- If a config template is useful, create `.env.example` with fake placeholder values only
  (for example `ABUSEIPDB_API_KEY=your-key-here`), and that file may be committed.
- Before every commit, run `git status` and `git diff --staged` and check that nothing
  sensitive is included. Stage files by name rather than using `git add .` or `git add -A`.
- Never print or paste a real secret in chat or in a log line.
- If a secret is ever committed, even locally, stop and tell Ben right away. Deleting it in a
  later commit is not enough because it remains in the history. The key must be revoked and
  regenerated, and the history cleaned before pushing.

## Git workflow: pull requests for everything

Ben wants practice with pull requests, so **never commit straight to `main`**.

1. Start from an up-to-date `main`, then create a branch for each change
   (for example `feature/abuseipdb-source`, `fix/private-ip-message`).
2. Make small, focused commits with clear messages that say what and why.
3. Push the branch and open a pull request with `gh pr create`. The description should cover
   what changed, why, and how it was tested.
4. Ben reviews and merges the PR himself on GitHub. Don't merge it for him.
5. After the merge, switch back to `main`, pull, and delete the old branch.

Only commit or push when Ben asks. Briefly explain each git step the first few times so
he learns what it does.

Note: the local branch is currently `master` and has no GitHub remote yet. Before the first PR,
help Ben rename it to `main` and connect the repository to GitHub, explaining each step.

## Project conventions

- Python with Flask. Dependencies are in `requirements.txt` and live in the `venv/` virtual
  environment, which is not committed.
- Run tests with `pytest` before opening a PR. New logic should come with a test where it makes sense.
- The app only reads data from sources. It must never submit or report anything to
  AbuseIPDB or any other service.
- Error details go to the terminal, never to the web page. User-facing messages must be
  safe to show.
