# Cursor rules

Repo-local coding and communication defaults. Version-controlled so every
clone and collaborator gets the same posture, with or without machine-level
Cursor plugins.

## Rules

| File | Concern | Applies |
|---|---|---|
| `ponytail.mdc` | Craft: smallest correct change, reuse first, never cut validation/security | always, advisory |
| `caveman.mdc` | Voice: say less, code/paths verbatim, full sentences for risk | always, advisory |

Both are `alwaysApply: true` — on by default in every session — but
**advisory, not overriding**. Order of precedence on conflict:

1. An explicit instruction in the current request.
2. `AGENTS.md` (repo product truth), if present.
3. These rules.

## Why these

- **ponytail** — "the best code is code never written." Write only what the
  task needs; reuse what exists; small because necessary, not golfed.
- **caveman** — a communication discipline (ASD-STE100 controlled English):
  answer first, one idea per sentence, payload verbatim. Terseness drops when
  clarity matters: security warnings, destructive actions, a confused user.

## Provenance

Both rules are **vendored from upstream** as the baseline we then hone locally.
Local edits will diverge from upstream; keep the attribution footer in each
file when you edit.

| File | Source | License | Change on vendor |
|---|---|---|---|
| `ponytail.mdc` | [dietrichgebert/ponytail](https://github.com/dietrichgebert/ponytail) `/.cursor/rules/ponytail.mdc` | MIT | verbatim |
| `caveman.mdc` | [juliusbrussee/caveman](https://github.com/juliusbrussee/caveman) `/skills/caveman/SKILL.md` | Apache-2.0 | frontmatter adapted to Cursor `.mdc`; Persistence/alias/hook section removed; voice spec otherwise verbatim |

`caveman.mdc` has been honed: the upstream `/caveman` command, alias, and hook
references were removed because this setup has no such host integration. The
nine rules, when-to-break list, and pre-send check are kept verbatim.

## Opt out

- One session: start the request with the opposite instruction; it wins (rung 1).
- Per file type: add `globs:` and set `alwaysApply: false` in the rule.
- Off: delete the `.mdc`, or set `alwaysApply: false`.

## Not here

The npm tools (`@dietrichgebert/ponytail`, `@caveman-ai/cli`) and their slash
commands (`/ponytail-review`, `/caveman`) are not installed — those act
machine-wide across all agents and are heavier than these repo defaults need.
caveman's real token savings come from its proxy/CLI, not this rule; only its
voice is captured here.

## Note on `cursor/`

The repo's `cursor/` directory holds host repair scripts
(`clean__.sh`, `respawn___.sh`, `migrate__OSx__.py`). Cursor does **not** read
rules from there — only from this `.cursor/rules/` directory and `AGENTS.md`.
