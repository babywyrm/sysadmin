# Agent Safety

Defensive tooling and notes for inspecting AI agent control files, Cursor
configuration, skills, rules, hooks, and agent startup context.

## Layout

- `cursor-hooks/`: Hook scripts and configs for scanning suspicious agent
  control files before they are read or written.

## Purpose

Agent control files can become a supply-chain surface. Treat files such as
`SKILL.md`, `AGENTS.md`, `.cursor/rules/**`, `.cursor/hooks/**`, and plugin docs
as executable influence over future agents.

This area is for defensive scanners, guardrails, and operational checks that
help find risky or corrupted agent instructions before an agent trusts them.
