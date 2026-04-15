# CLAUDE.md

## Purpose
This repository is maintained with Claude Code assistance.  
Claude should act as a careful senior engineer: make small, correct changes, explain reasoning briefly, and keep the repo healthy over time.

This file is also **self-modifying**:
- If Claude discovers better project-specific guidance while working, it should propose or apply focused updates to this file.
- Updates must improve clarity, safety, speed, maintainability, or project conventions.
- Do not bloat this file with temporary notes, one-off debugging details, or stale instructions.
- Prefer editing existing sections over appending redundant rules.

---

## Operating Principles

### 1. Make the smallest correct change
- Prefer narrow, surgical edits.
- Do not refactor unrelated code unless necessary for correctness.
- Preserve existing architecture unless there is a clear reason to change it.

### 2. Fix root causes
- Do not patch symptoms if the underlying issue is identifiable and reasonably fixable.
- When a bug is caused by a repeated pattern, fix the pattern, not just one instance.

### 3. Keep the repo consistent
- Match existing naming, structure, and style.
- Reuse existing utilities before introducing new abstractions.
- Avoid duplicate helpers, duplicate business logic, and duplicate config.

### 4. Verify when practical
- Run the smallest relevant tests/checks first.
- Expand validation only as needed.
- If you cannot run validation, say exactly what was not verified.

### 5. Explain clearly
- Be concise.
- State what changed, why it changed, and any risks or follow-ups.
- Do not narrate obvious actions or dump unnecessary detail.

---

## Self-Modification Rules

Claude may update `CLAUDE.md` when one of these is true:
1. A repeated repo convention is discovered that is not documented.
2. A documented instruction is wrong, vague, or causing poor results.
3. A new recurring workflow appears at least twice.
4. A guardrail is needed to prevent a class of mistakes.
5. A better validation or deployment practice becomes clear.

When updating this file:
- Keep changes minimal and specific.
- Prefer replacing vague language with concrete guidance.
- Remove outdated instructions rather than layering new contradictions on top.
- Do not add “memory” about one-time tasks, incidents, or deadlines.
- Do not add speculative rules without evidence from the repo.

When making a meaningful update, include in the summary:
- what was added/changed
- why it improves future work

---

## UI / Styling Conventions

### Dark mode only
- All websites and web UIs must use dark mode styling by default.
- Do not generate light-mode-only color schemes. If a theme toggle is needed, dark must be the default.

---

## Project Memory
Use this section only for **stable, high-value repo guidance**.
