<div align="center">

# vibe-guardrails

**Safety rails for people who let an AI agent run commands they can't read.**

[中文说明](./README.zh-CN.md) · [Rules](./rules/CORE.md) · [Contributing](./CONTRIBUTING.md)

![python](https://img.shields.io/badge/python-3.8%2B-blue)
![dependencies](https://img.shields.io/badge/dependencies-0-green)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

</div>

---

## The problem

Coding agents are now good enough that people who have never written a line of
code are shipping real software with them. That is a genuinely good thing.

It also means a growing number of people are approving commands they cannot
read. When an agent proposes `rm -rf ~/project` and the confirmation prompt says
"Bash command", a non-programmer has no way to know that one of those is a
cleanup and the other is a Tuesday afternoon erased.

The failure mode is not the agent going rogue. It's the ordinary one: a wrong
path, a `git reset --hard` over three hours of unsaved work, an `.env` file
committed to a public repo, a `--force` push that overwrites a teammate.

`vibe-guardrails` sits between the agent and your machine and stops those.

## What it is

Two pieces, both of which work on their own:

**1. A hook** (`hooks/guard.py`) — a single dependency-free Python file that
inspects every command before it runs and blocks the catastrophic ones,
explaining in plain language what was about to happen and why.

**2. A ruleset** (`rules/CORE.md`) — instructions you paste into your
`CLAUDE.md` or `AGENTS.md` so the agent behaves cautiously in the first place.

The hook is the seatbelt. The ruleset is defensive driving. Use both.

## Install

```bash
git clone https://github.com/a349482180/vibe-guardrails.git
cd vibe-guardrails
bash install.sh
```

Then restart your agent and ask it to run `rm -rf /`. You should see this:

```
vibe-guardrails 拦截了这条操作 / blocked by vibe-guardrails

[filesystem] rm-rf-root
  > rm -rf /
  这条命令会递归强制删除根目录、主目录或上级目录 —— 会毁掉整个系统或你的全部
  个人文件，且无法撤销。
  This recursively force-deletes your root, home, or parent directory. It is
  unrecoverable and will destroy the machine or all of your personal files.
  建议 / suggestion: 明确写出要删除的具体目录名，例如 rm -rf ./build
```

For the ruleset, add one line to your `CLAUDE.md`:

```markdown
@./vibe-guardrails/rules/CORE.md
```

or just paste the contents of [`rules/CORE.md`](./rules/CORE.md) in.

## What it catches

| Category | Blocked outright | Asks first |
|---|---|---|
| **Filesystem** | `rm -rf /`, `rm -rf ~`, `sudo rm`, `mkfs`, `dd of=/dev/sda` | `rm -rf` on any real directory, `find -delete`, `chmod 777 /` |
| **Git** | `gh repo delete` | `push --force`, `reset --hard`, `clean -fd`, `filter-branch`, `branch -D` |
| **Secrets** | `git add .env`, hardcoding a live `sk-…` / `ghp_…` / `AKIA…` key into source | writing to `.env`, `.pem`, `~/.ssh/`, echoing `$*_SECRET` |
| **Supply chain** | `curl … \| sh` | `npm publish`, `twine upload`, `cargo publish` |
| **Database** | `DROP DATABASE`, `TRUNCATE TABLE` | `redis-cli flushall`, `prisma migrate reset` |
| **Cloud** | `terraform destroy`, `kubectl delete --all`, `aws s3 rb` | — |
| **System** | `kill -9 1`, fork bombs | `shutdown`, `history -c` |

Three policy levels, set at install time or with `VIBE_GUARDRAILS_MODE`:

| | critical | high | medium |
|---|---|---|---|
| `strict` | deny | deny | ask |
| `balanced` *(default)* | deny | ask | ask |
| `relaxed` | deny | ask | allow |

## Design principles

**False positives are the real failure.** A guard that interrupts `npm install`
gets uninstalled within a day, at which point it protects nobody. Everyday
commands — `rm -rf node_modules`, `git add .`, `git push origin feature/x`,
`curl -o file.json …` — pass through untouched, and there is an allowlist you
can extend when they don't. More than half the test suite exists to verify that
ordinary work is *not* blocked.

**Every message explains the consequence, not the rule.** "Blocked: dangerous
command" teaches nothing. "This discards all uncommitted work; anything not yet
committed is permanently gone — use `git stash` if you want to keep it" teaches
the user something they will still know next month.

**It fails open.** A crash in the guard, a malformed config, an unparseable
payload — none of these block your agent. A safety tool that breaks your
workflow when *it* has a bug is worse than no tool.

**Zero dependencies, one file.** `hooks/guard.py` is standard-library Python
3.8+. You can read the whole thing, and so can an agent you ask to audit it.

## Configuring

Edit `~/.claude/vibe-guardrails/rules.json`. It survives upgrades.

```jsonc
{
  // never inspect these — for the command you run twenty times a day
  "allow": ["^\\s*rm\\s+-rf\\s+\\./tmp-scratch/?\\s*$"],

  // switch off a built-in rule by id (ids appear in every message)
  "disable": ["shutdown"],

  // add your own
  "rules": [{
    "id": "no-prod-ssh",
    "severity": "critical",
    "pattern": "\\bssh\\b[^\\n]*\\bprod\\b",
    "zh": "这条命令会连到生产服务器。",
    "en": "This connects to a production server."
  }]
}
```

Escape hatches:

```bash
VIBE_GUARDRAILS_OFF=1 claude      # disable for one session
VIBE_GUARDRAILS_MODE=strict       # override the policy level
VIBE_GUARDRAILS_LANG=en           # zh | en | both (default: both)
```

## Limits — please read this part

This stops accidents. It is **not** a security boundary.

The guard matches patterns against command text. Anything that hides the
command from that text goes straight through: base64-decoded payloads, a
dangerous line inside a shell script the agent then executes, `$(…)`
substitution, a Makefile target, an `npm postinstall`. Closing those holes would
require sandboxing, not regexes.

Treat it as what it is: a seatbelt for the ordinary mistakes that actually
happen, dozens of times a day, to people who cannot read the command they are
approving. If you need a real boundary, run your agent in a container or VM.

## Compatibility

Built against the Claude Code `PreToolUse` hook protocol. Any agent that sends
`{"tool_name": …, "tool_input": …}` on stdin and honours a
`permissionDecision` response will work as-is.

Contributions adding adapters for other agents are welcome — see
[CONTRIBUTING.md](./CONTRIBUTING.md). Rule contributions are especially
welcome: if an agent destroyed something of yours, that is a rule the rest of us
are missing.

## Tests

```bash
python3 tests/test_guard.py
```

## License

MIT
