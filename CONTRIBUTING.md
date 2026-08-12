# Contributing

The most valuable contribution is a rule.

If an agent destroyed something of yours, that is a gap the rest of us still
have. Open an issue with the exact command — you do not need to write the
regex, and you do not need to know Python.

## Adding a rule

Rules live in the `RULES` list in [`hooks/guard.py`](./hooks/guard.py). Each one
is a small dictionary:

```python
{
    "id": "git-reset-hard",           # stable, kebab-case; users disable by id
    "category": "git",                # filesystem | git | secrets | database |
                                      # cloud | supply-chain | system
    "severity": "high",               # see below
    "pattern": r"\bgit\s+reset\s+--hard\b",
    "zh": "丢弃所有未提交的改动……",     # what happens, in plain language
    "en": "Discards all uncommitted work…",
    "fix": "想保留改动就先执行 git stash",
    "fix_en": "Run git stash first to keep the changes",
}
```

**Severity**

| | meaning | example |
|---|---|---|
| `critical` | irreversible and catastrophic; denied in every mode | `rm -rf /` |
| `high` | usually destructive, occasionally intentional | `git push --force` |
| `medium` | worth a glance, frequently legitimate | `history -c` |

If you are unsure, pick the lower one. Over-classifying is how a tool becomes
annoying, and an annoying tool gets uninstalled.

**Writing the explanation**

Describe the consequence, not the rule. The reader may not know what a branch
is.

- No: "Dangerous git operation blocked."
- Yes: "Force push overwrites remote history. If anyone else has work on this
  branch, their commits are gone."

Both `zh` and `en` are required. If you can only write one, open the PR anyway
and say so — someone will fill in the other.

## Every rule needs tests

Add cases to `CASES` in [`tests/test_guard.py`](./tests/test_guard.py):

1. One command your rule **should** catch.
2. At least one similar command it **must not** catch.

The second matters more. `git push --force` should trigger;
`git push --force-with-lease` must not. Roughly half the existing suite exists
to prove ordinary work still passes through.

```bash
python3 tests/test_guard.py
```

All three checks must pass: the case table, mode monotonicity (`relaxed` is
never stricter than `balanced`, which is never stricter than `strict`), and
fail-safe behaviour on malformed input.

## Adding support for another agent

`guard.py` speaks the Claude Code `PreToolUse` protocol: a JSON tool call on
stdin, a `permissionDecision` on stdout. Adapters for other agents are welcome.
Keep `analyze()` untouched and put the translation in a thin wrapper — the rules
should not have to know which agent is asking.

## Ground rules

- **Zero dependencies.** Standard library Python 3.8+ only. Someone should be
  able to read the entire guard in one sitting.
- **Fail open.** If the guard itself breaks, the agent must keep working. A
  safety tool that halts your workflow when *it* has a bug is worse than none.
- **No telemetry, no network calls.** Ever.

## Reporting a bypass

Found a way past the guard? Open an issue — it is not a security
vulnerability, because this was never a security boundary (see the Limits
section of the README). It is a missing rule, and public discussion is how it
gets fixed.
