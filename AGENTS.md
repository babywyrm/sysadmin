# AGENTS.md

Product truth for this repo. Agent rules in `.cursor/rules/` defer to this file
on conflict.

## What this is

A personal reference collection of sysadmin, security, and CTF notes: one
top-level directory per tool or topic, holding Markdown notes plus the
occasional script and reference PDF. It is a knowledge base, not an application.
There is no build, no test suite, and no package to install.

## Layout

- Topical dirs at the root (e.g. `apache/`, `ansible/`, `k8/`, `crypto/`).
- Consolidated parents group related topics: `recon/`, `databases/`, `lang/`,
  `identity/`, `webappsec/`, `tunneling/`, `observability/`. Each has a
  `README.md` index.
- `cursor/` holds host repair scripts (`clean__.sh`, `respawn___.sh`,
  `migrate__OSx__.py`). Cursor does not read rules from here.
- `.cursor/rules/` holds the agent rules (`ponytail`, `caveman`) and their
  README. This is the only path Cursor loads rules from.

## Conventions

- Commits: one logical change each; subject capitalized, imperative, ≤50 chars;
  body wraps at 72 and says why, not how. No conventional-commit prefixes.
- When consolidating or moving dirs, use `git mv` to preserve history and check
  for inbound links first.

## Safety

Scripts in this repo (notably `cursor/*.sh` and `cursor/migrate__OSx__.py`) can
delete local state or act over SSH. Prefer `--dry-run` first and confirm before
any destructive or irreversible command.

Secret scanning is part of the workflow. Before pushing, and whenever content
is added, run `trufflehog filesystem . --only-verified --fail` (and/or
`gitleaks`). `--only-verified` because this repo holds many example tokens from
writeups; only live, verified credentials are a problem. Scan output is
gitignored. Never commit real secrets, tokens, flags, or live credentials.

## Do not touch

Reference PDFs, images, and binaries are intentional archive material, not
clutter. Do not delete them during cleanup.
