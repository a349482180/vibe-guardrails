#!/usr/bin/env python3
"""
vibe-guardrails :: guard.py

A dependency-free PreToolUse hook for AI coding agents (Claude Code, and any
agent that speaks the same hook protocol).

It reads a tool call from stdin as JSON and decides whether to allow, ask, or
deny it -- so that an agent working on your machine cannot silently run
`rm -rf ~`, force-push over your main branch, pipe a random URL into a shell,
or commit your API keys.

Design goals, in order:
  1. Never break a legitimate workflow. False positives are worse than a miss,
     because a noisy guard gets uninstalled.
  2. Be readable by someone who does not write code. Every rule is a small
     dict with a plain-language reason.
  3. Zero dependencies. Python 3.8+ standard library only.

This is defense-in-depth, NOT a security boundary. A determined or adversarial
process can obfuscate its way past regexes. It is built to stop accidents, and
accidents are what actually happen.

Protocol
--------
stdin  : {"tool_name": "Bash", "tool_input": {"command": "..."}, ...}
stdout : {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                 "permissionDecision": "allow|ask|deny",
                                 "permissionDecisionReason": "..."}}
exit 0 : decision delivered on stdout
exit 1 : guard itself failed -- treated as non-blocking, agent continues

Environment
-----------
VIBE_GUARDRAILS_MODE  strict | balanced | relaxed     (default: balanced)
VIBE_GUARDRAILS_LANG  zh | en | both                  (default: both)
VIBE_GUARDRAILS_RULES path to a JSON file of extra/override rules
VIBE_GUARDRAILS_OFF   set to 1 to disable entirely
"""

import json
import os
import re
import sys

__version__ = "0.1.0"

# ---------------------------------------------------------------------------
# Severity -> decision, per mode.
#
#   critical : irreversible and catastrophic. Never silently allowed.
#   high     : usually destructive, occasionally intentional.
#   medium   : worth a glance, frequently legitimate.
# ---------------------------------------------------------------------------

MODES = {
    "strict":   {"critical": "deny", "high": "deny", "medium": "ask"},
    "balanced": {"critical": "deny", "high": "ask",  "medium": "ask"},
    "relaxed":  {"critical": "deny", "high": "ask",  "medium": "allow"},
}
DEFAULT_MODE = "balanced"


# ---------------------------------------------------------------------------
# Allowlist: segments matching these are never inspected.
#
# This is the single most important part of the file. Deleting a build
# directory is not a disaster, and an agent that has to ask permission for
# `rm -rf node_modules` will be turned off within a day.
# ---------------------------------------------------------------------------

ALLOWLIST = [
    r"^\s*rm\s+(-[a-zA-Z]+\s+)*\.?/?(node_modules|dist|build|out|coverage|target|\.next|\.nuxt|\.turbo|\.parcel-cache|__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|\.gradle|vendor)/?\s*$",
    r"^\s*rm\s+(-[a-zA-Z]+\s+)*[\w./-]*\.(log|tmp|temp|pyc|o|class)\s*$",
    r"^\s*rm\s+(-[a-zA-Z]+\s+)*/tmp/\S+\s*$",
    r"^\s*git\s+clean\s+-[a-zA-Z]*d[a-zA-Z]*f?\s+(-[a-zA-Z]+\s+)*(node_modules|dist|build)/?\s*$",
    r"^\s*docker\s+(compose\s+)?(down|stop|rm)\b",
]


# ---------------------------------------------------------------------------
# Rules.
#
# Each rule is a dict:
#   id        stable identifier, used to disable a rule
#   category  grouping, shown to the user
#   severity  critical | high | medium
#   pattern   Python regex, matched case-insensitively
#   whole     if True, matched against the full command instead of each
#             ;/&&/||/| separated segment (needed for pipe-based rules)
#   zh / en   plain-language explanation of what is about to happen
#   fix       a safer alternative, when one exists
# ---------------------------------------------------------------------------

RULES = [
    # -- Filesystem destruction ------------------------------------------------
    {
        "id": "rm-rf-root",
        "category": "filesystem",
        "severity": "critical",
        "pattern": r"\brm\b(?=[^\n]*\s-[a-zA-Z]*r)(?=[^\n]*\s-[a-zA-Z]*f)[^\n]*\s(/|/\*|~|~/|~/\*|\$HOME|\$\{HOME\}|\.\.|/\*)\s*(;|&|\||$)",
        "zh": "这条命令会递归强制删除根目录、主目录或上级目录 —— 会毁掉整个系统或你的全部个人文件，且无法撤销。",
        "en": "This recursively force-deletes your root, home, or parent directory. It is unrecoverable and will destroy the machine or all of your personal files.",
        "fix": "明确写出要删除的具体目录名，例如 rm -rf ./build",
        "fix_en": 'Name the specific directory instead, e.g. rm -rf ./build',
    },
    {
        "id": "rm-rf-broad",
        "category": "filesystem",
        "severity": "high",
        "pattern": r"\brm\b(?=[^\n]*\s-[a-zA-Z]*r)(?=[^\n]*\s-[a-zA-Z]*f)",
        "zh": "递归强制删除（rm -rf）。删掉的文件不进回收站，无法恢复。",
        "en": "Recursive force delete (rm -rf). Files do not go to the trash and cannot be recovered.",
        "fix": "先确认路径写对了；不确定就先用 ls 看一眼要删的是什么",
        "fix_en": 'Check the path is right; run ls on it first if you are not certain what is there',
    },
    {
        "id": "sudo-destructive",
        "category": "filesystem",
        "severity": "critical",
        "pattern": r"\bsudo\b[^\n]*\b(rm|dd|mkfs|chown|chmod)\b",
        "zh": "以管理员权限执行破坏性文件操作。系统级文件一旦损坏，通常只能重装。",
        "en": "A destructive filesystem operation running as root. Damage at this level usually means reinstalling the OS.",
        "fix": "先不加 sudo 试一次；真的需要 sudo 的时候，自己在终端手动执行",
        "fix_en": 'Try it without sudo first; if sudo is genuinely required, run it yourself in a terminal',
    },
    {
        "id": "mkfs",
        "category": "filesystem",
        "severity": "critical",
        "pattern": r"\bmkfs(\.\w+)?\b",
        "zh": "格式化磁盘分区，会抹掉该分区上的所有数据。",
        "en": "Formats a disk partition, erasing everything on it.",
        "fix": None,
    },
    {
        "id": "dd-to-device",
        "category": "filesystem",
        "severity": "critical",
        "pattern": r"\bdd\b[^\n]*\bof=\s*/dev/(sd|nvme|disk|hd)",
        "zh": "直接向物理磁盘写入原始数据，会覆盖分区表并摧毁磁盘上的所有内容。",
        "en": "Writes raw data straight to a physical disk, destroying the partition table and everything on it.",
        "fix": None,
    },
    {
        "id": "chmod-777-system",
        "category": "filesystem",
        "severity": "high",
        "pattern": r"\bchmod\b[^\n]*\b777\b[^\n]*\s(/|/usr|/etc|/var|/bin|~)\b",
        "zh": "把系统目录设为所有人可读写。这会打开一个严重的安全漏洞，而且很难完整还原。",
        "en": "Makes system directories world-writable. This opens a serious security hole and is hard to fully undo.",
        "fix": "只对确实需要的单个文件调整权限，并使用最小必要权限（如 644 / 755）",
        "fix_en": 'Change permissions on the single file that needs it, using the least permissive mode (644 / 755)',
    },
    {
        "id": "find-delete",
        "category": "filesystem",
        "severity": "high",
        "pattern": r"\bfind\b[^\n]*\s(-delete|-exec\s+rm\b)",
        "zh": "find 会遍历整棵目录树并删除所有匹配项。匹配条件写错一个字符，删除范围就可能失控。",
        "en": "find walks an entire directory tree and deletes every match. One wrong character in the filter can widen the blast radius enormously.",
        "fix": "先把 -delete 换成 -print 跑一遍，确认列出的文件正是你想删的",
        "fix_en": 'Replace -delete with -print and confirm the listed files are exactly the ones you meant',
    },
    {
        "id": "overwrite-redirect-system",
        "category": "filesystem",
        "severity": "high",
        "pattern": r">\s*(/etc/|/usr/|/bin/|/boot/|~/\.(ssh|aws|gnupg|config)/)",
        "zh": "用重定向覆盖系统或凭证目录里的文件。单个 > 会直接清空原文件内容。",
        "en": "Overwrites a file in a system or credentials directory. A single > truncates the original immediately.",
        "fix": "先备份：cp 原文件 原文件.bak",
        "fix_en": 'Back it up first: cp file file.bak',
    },

    # -- Git history and remotes -----------------------------------------------
    {
        "id": "git-push-force",
        "category": "git",
        "severity": "high",
        "pattern": r"\bgit\s+push\b(?![^\n]*--force-with-lease)[^\n]*(\s--force\b|\s-f\b)",
        "zh": "强制推送会覆盖远程仓库的历史。如果同事在这个分支上工作，他们的提交会直接消失。",
        "en": "Force push overwrites remote history. If anyone else has work on this branch, their commits are gone.",
        "fix": "改用 git push --force-with-lease，它会在远程有新提交时拒绝覆盖",
        "fix_en": 'Use git push --force-with-lease instead; it refuses when the remote has commits you have not seen',
    },
    {
        "id": "git-reset-hard",
        "category": "git",
        "severity": "high",
        "pattern": r"\bgit\s+reset\s+--hard\b",
        "zh": "丢弃所有未提交的改动。还没 commit 的代码会永久消失，Ctrl+Z 也救不回来。",
        "en": "Discards all uncommitted work. Anything not yet committed is permanently gone.",
        "fix": "想保留改动就先执行 git stash，需要时再 git stash pop",
        "fix_en": 'Run git stash first to keep the changes, then git stash pop when you want them back',
    },
    {
        "id": "git-clean-force",
        "category": "git",
        "severity": "high",
        "pattern": r"\bgit\s+clean\b[^\n]*\s-[a-zA-Z]*f",
        "zh": "删除所有未被 git 跟踪的文件。你手写的、还没 git add 的新文件会一起被删掉。",
        "en": "Deletes every untracked file. New files you wrote but have not staged yet will be deleted too.",
        "fix": "先加 -n 干跑一遍：git clean -nd，看清楚会删哪些文件",
        "fix_en": 'Dry-run it: git clean -nd shows exactly which files would be deleted',
    },
    {
        "id": "git-checkout-discard",
        "category": "git",
        "severity": "medium",
        "pattern": r"\bgit\s+(checkout|restore)\s+(--\s+)?\.\s*$",
        "zh": "还原工作区的全部改动，未提交的编辑会丢失。",
        "en": "Reverts every change in the working tree; uncommitted edits are lost.",
        "fix": "只还原确定不要的那个文件，而不是整个目录",
        "fix_en": 'Restore only the one file you are sure about, not the whole tree',
    },
    {
        "id": "git-history-rewrite",
        "category": "git",
        "severity": "high",
        "pattern": r"\bgit\s+(filter-branch|filter-repo)\b|\bbfg\b",
        "zh": "重写整个仓库的提交历史。所有提交的 ID 都会变，其他人的本地仓库会与远程冲突。",
        "en": "Rewrites the repository's entire commit history. Every commit ID changes and every other clone breaks.",
        "fix": "先完整备份仓库：git clone --mirror",
        "fix_en": 'Make a full backup first: git clone --mirror',
    },
    {
        "id": "git-branch-delete-force",
        "category": "git",
        "severity": "medium",
        "pattern": r"\bgit\s+branch\s+(-D|-d\s+--force)\b",
        "zh": "强制删除分支，即使分支上还有没合并的提交也照删。",
        "en": "Force-deletes a branch even when it still holds unmerged commits.",
        "fix": "用小写 -d，它会在有未合并提交时拒绝删除",
        "fix_en": 'Use lowercase -d, which refuses to delete a branch that still has unmerged commits',
    },
    {
        "id": "repo-delete",
        "category": "git",
        "severity": "critical",
        "pattern": r"\b(gh\s+repo\s+delete|glab\s+repo\s+delete)\b",
        "zh": "删除远程代码仓库。包括 issue、PR、star 在内的一切都会消失，且不可恢复。",
        "en": "Deletes the remote repository. Issues, PRs, stars -- everything goes, permanently.",
        "fix": None,
    },

    # -- Secrets ---------------------------------------------------------------
    {
        "id": "git-add-secrets",
        "category": "secrets",
        "severity": "critical",
        "pattern": r"\bgit\s+add\b[^\n]*(\.env(\.\w+)?|id_rsa|id_ed25519|\.pem|\.p12|credentials|\.npmrc|\.pypirc)\b",
        "zh": "把密钥文件加入 git。一旦推送到远程，密钥就必须视为已泄露 —— 从历史里删掉也不够，必须重新签发。",
        "en": "Stages a secrets file into git. Once pushed, the credential must be treated as leaked; scrubbing history is not enough, it has to be rotated.",
        "fix": "把该文件写进 .gitignore，并只提交一份 .env.example 模板",
        "fix_en": 'Add the file to .gitignore and commit a .env.example template instead',
    },
    {
        "id": "curl-pipe-shell",
        "category": "supply-chain",
        "severity": "critical",
        "whole": True,
        "pattern": r"\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|k|fi|da)?sh\b",
        "zh": "把网上下载的脚本直接交给 shell 执行，你无法看到自己在运行什么。如果那个地址被劫持，等于把电脑交给了对方。",
        "en": "Pipes a downloaded script straight into a shell without you ever seeing it. If that URL is compromised, so is your machine.",
        "fix": "分两步：先 curl -o install.sh <url>，打开看一遍，再 bash install.sh",
        "fix_en": 'Split it in two: curl -o install.sh <url>, read the file, then bash install.sh',
    },
    {
        "id": "env-var-secret-echo",
        "category": "secrets",
        "severity": "medium",
        "whole": True,
        "pattern": r"\b(echo|printf|cat)\b[^\n]*\$(OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|\w*_?(SECRET|TOKEN|PASSWORD|API_KEY))\b",
        "zh": "把密钥打印到输出里。这段输出会被写进 agent 的对话记录和终端历史。",
        "en": "Prints a credential to stdout, where it lands in the agent transcript and your shell history.",
        "fix": "验证是否设置了变量就够了：[ -n \"$MY_KEY\" ] && echo set",
        "fix_en": 'Checking that it is set is enough: [ -n "$MY_KEY" ] && echo set',
    },

    # -- Databases -------------------------------------------------------------
    {
        "id": "sql-drop",
        "category": "database",
        "severity": "critical",
        "pattern": r"\b(drop\s+(database|schema|table)|truncate\s+table)\b",
        "zh": "删除数据库、表或清空表数据。除非有备份，否则数据无法找回。",
        "en": "Drops a database or table, or empties one. Without a backup the data is gone.",
        "fix": "先导出备份：pg_dump / mysqldump",
        "fix_en": 'Export a backup first: pg_dump / mysqldump',
    },
    {
        "id": "redis-flush",
        "category": "database",
        "severity": "high",
        "pattern": r"\bredis-cli\b[^\n]*\bflush(all|db)\b",
        "zh": "清空 Redis 的全部键值。如果 Redis 里存的是会话，所有用户会立刻被登出。",
        "en": "Wipes every key in Redis. If sessions live there, all users are logged out instantly.",
        "fix": None,
    },
    {
        "id": "migrate-reset",
        "category": "database",
        "severity": "high",
        "pattern": r"\b(prisma\s+migrate\s+reset|supabase\s+db\s+reset|rails\s+db:drop|python\s+manage\.py\s+flush)\b",
        "zh": "重置数据库，会删掉所有表并重新建库。开发库里的测试数据也会一起没。",
        "en": "Resets the database: every table is dropped and rebuilt. Your development data goes with it.",
        "fix": None,
    },

    # -- Cloud and deploy ------------------------------------------------------
    {
        "id": "terraform-destroy",
        "category": "cloud",
        "severity": "critical",
        "pattern": r"\bterraform\s+destroy\b",
        "zh": "销毁 terraform 管理的全部云资源，包括正在跑的生产环境。",
        "en": "Destroys every cloud resource under terraform's management, production included.",
        "fix": "先 terraform plan -destroy 看清楚清单，并考虑用 -target 限定范围",
        "fix_en": 'Run terraform plan -destroy first, and consider scoping it with -target',
    },
    {
        "id": "kubectl-delete-all",
        "category": "cloud",
        "severity": "critical",
        "pattern": r"\bkubectl\s+delete\b[^\n]*(--all\b|\bnamespace\b)",
        "zh": "批量删除 Kubernetes 资源或整个命名空间，正在运行的服务会立刻中断。",
        "en": "Bulk-deletes Kubernetes resources or a whole namespace; running services drop immediately.",
        "fix": "加上 --dry-run=client 先看会删掉什么",
        "fix_en": 'Add --dry-run=client first to see what would be removed',
    },
    {
        "id": "s3-remove-bucket",
        "category": "cloud",
        "severity": "critical",
        "pattern": r"\baws\s+s3\s+(rb\b|rm\b[^\n]*--recursive)",
        "zh": "删除 S3 存储桶或递归删除其中的对象。没开版本控制的话，文件无法恢复。",
        "en": "Deletes an S3 bucket or recursively removes its objects. Without versioning enabled, they are unrecoverable.",
        "fix": "先 aws s3 ls 确认桶名和路径",
        "fix_en": 'Run aws s3 ls first to confirm the bucket name and path',
    },
    {
        "id": "publish-package",
        "category": "supply-chain",
        "severity": "high",
        "pattern": r"\b(npm\s+publish|yarn\s+publish|pnpm\s+publish|twine\s+upload|cargo\s+publish|gem\s+push)\b",
        "zh": "把包发布到公共仓库。发布是公开且几乎不可撤回的 —— 如果打包时带进了 .env，密钥就随包发出去了。",
        "en": "Publishes to a public registry. Publication is public and effectively permanent; if a .env slipped into the tarball, the secret ships with it.",
        "fix": "先看清楚会打进哪些文件：npm pack --dry-run",
        "fix_en": 'See what would actually ship first: npm pack --dry-run',
    },

    # -- Process and system ----------------------------------------------------
    {
        "id": "kill-init",
        "category": "system",
        "severity": "critical",
        "pattern": r"\bkill\s+(-9\s+|-KILL\s+)?1\b",
        "zh": "杀死 PID 1（init 进程），会导致系统直接崩溃。",
        "en": "Kills PID 1 (init), which crashes the system outright.",
        "fix": None,
    },
    {
        "id": "fork-bomb",
        "category": "system",
        "severity": "critical",
        "whole": True,
        "pattern": r":\(\)\s*\{\s*:\|\s*:&\s*\}\s*;\s*:",
        "zh": "fork 炸弹，会无限自我复制直到系统耗尽资源死机。",
        "en": "A fork bomb: it replicates until the machine runs out of resources and locks up.",
        "fix": None,
    },
    {
        "id": "shutdown",
        "category": "system",
        "severity": "high",
        "pattern": r"\b(shutdown|reboot|halt|poweroff)\b",
        "zh": "关机或重启。所有未保存的工作会丢失。",
        "en": "Shuts down or reboots the machine. Unsaved work is lost.",
        "fix": None,
    },
    {
        "id": "history-wipe",
        "category": "system",
        "severity": "medium",
        "pattern": r"\bhistory\s+-c\b|>\s*~?/?\.?(bash|zsh)_history",
        "zh": "清空 shell 历史记录。出问题时你将无法回溯刚才执行过什么。",
        "en": "Clears your shell history, removing your ability to reconstruct what was run when something breaks.",
        "fix": None,
    },
]


# ---------------------------------------------------------------------------
# File-level rules, applied to Write / Edit / MultiEdit.
# ---------------------------------------------------------------------------

TEMPLATE_PATH_PATTERN = re.compile(
    r"\.(example|sample|template|dist|md|mdx|txt|rst)$", re.IGNORECASE
)

SECRET_PATH_PATTERN = re.compile(
    r"(^|/)(\.env(\.[\w-]+)?|\.npmrc|\.pypirc|\.netrc|credentials(\.json)?|"
    r"id_rsa|id_ed25519|id_ecdsa|serviceAccount\w*\.json)$"
    r"|\.(pem|key|p12|pfx|keystore|jks)$"
    r"|(^|/)\.(ssh|aws|gnupg)/",
    re.IGNORECASE,
)

# .env files are *supposed* to hold secrets; writing one is fine. What is not
# fine is a live credential landing in source code that gets committed.
# (regex, label_zh, label_en)
SECRET_CONTENT_PATTERNS = [
    (r"sk-ant-[A-Za-z0-9_\-]{24,}", "Anthropic API key", "an Anthropic API key"),
    (r"sk-[A-Za-z0-9_\-]{24,}", "OpenAI 格式的 API key", "an OpenAI-style API key"),
    (r"gh[pousr]_[A-Za-z0-9]{30,}", "GitHub token", "a GitHub token"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID", "an AWS access key ID"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "私钥内容", "a private key"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token", "a Slack token"),
    (r"AIza[0-9A-Za-z_\-]{35}", "Google API key", "a Google API key"),
]

# Writing to these is almost never what the user meant.
PROTECTED_PATH_PATTERN = re.compile(
    r"(^|/)\.git/(?!hooks/)|(^|/)(\.gitignore|LICENSE)$"
    r"|^/(etc|usr|bin|sbin|boot|System|Library)/",
)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

SPLIT_PATTERN = re.compile(r"\s*(?:;|&&|\|\||\||\n)\s*")


def split_command(command):
    """Break a shell line into individually-inspectable segments."""
    parts = [p.strip() for p in SPLIT_PATTERN.split(command)]
    return [p for p in parts if p]


def is_allowlisted(segment, allowlist):
    return any(re.search(p, segment, re.IGNORECASE) for p in allowlist)


def load_config():
    """Built-in rules, plus optional user additions/overrides."""
    rules = {r["id"]: dict(r) for r in RULES}
    allowlist = list(ALLOWLIST)
    disabled = set()

    path = os.environ.get("VIBE_GUARDRAILS_RULES")
    if not path:
        default = os.path.expanduser("~/.claude/vibe-guardrails/rules.json")
        path = default if os.path.exists(default) else None
    if not path or not os.path.exists(path):
        return rules, allowlist, disabled

    try:
        with open(path, "r", encoding="utf-8") as fh:
            user = json.load(fh)
    except Exception:
        # A malformed config must not take the guard offline.
        return rules, allowlist, disabled

    allowlist.extend(user.get("allow", []))
    disabled.update(user.get("disable", []))
    for r in user.get("rules", []):
        if "id" in r and "pattern" in r:
            base = rules.get(r["id"], {})
            base.update(r)
            base.setdefault("category", "custom")
            base.setdefault("severity", "high")
            rules[r["id"]] = base
    return rules, allowlist, disabled


def evaluate_bash(command, rules, allowlist, disabled):
    """Return a list of (rule, matched_segment) findings."""
    findings = []
    seen = set()
    segments = split_command(command)

    for rule in rules.values():
        if rule["id"] in disabled or rule["id"] in seen:
            continue
        targets = [command] if rule.get("whole") else segments
        for target in targets:
            if not rule.get("whole") and is_allowlisted(target, allowlist):
                continue
            if re.search(rule["pattern"], target, re.IGNORECASE):
                findings.append((rule, target))
                seen.add(rule["id"])
                break
    return findings


def evaluate_file_write(tool_name, tool_input, disabled):
    """Rules for Write / Edit / MultiEdit."""
    findings = []
    path = tool_input.get("file_path", "") or ""

    # Template files (.env.example, config.sample.json, docs) are meant to be
    # committed and are expected to contain placeholder-looking credentials.
    if TEMPLATE_PATH_PATTERN.search(path):
        return findings

    if "secret-file-write" not in disabled and SECRET_PATH_PATTERN.search(path):
        findings.append((
            {
                "id": "secret-file-write",
                "category": "secrets",
                "severity": "high",
                "zh": "正在写入一个凭证文件。覆盖它可能会弄丢你现有的密钥，而且这类文件绝不该进入版本库。",
                "en": "Writing to a credentials file. Overwriting it can lose your existing keys, and files like this must never reach version control.",
                "fix": "确认 .gitignore 里已经包含这个文件",
                "fix_en": 'Confirm this file is already listed in .gitignore',
            },
            path,
        ))

    if "protected-path-write" not in disabled and PROTECTED_PATH_PATTERN.search(path):
        findings.append((
            {
                "id": "protected-path-write",
                "category": "filesystem",
                "severity": "high",
                "zh": "正在写入 git 内部目录或系统目录。改动这里可能损坏仓库或操作系统。",
                "en": "Writing into git internals or a system directory. Changes here can corrupt the repository or the OS.",
                "fix": None,
            },
            path,
        ))

    if "hardcoded-secret" in disabled:
        return findings

    # A .env file is *supposed* to hold real credentials; that is its job.
    # What matters is a live key landing in source code that gets committed.
    if SECRET_PATH_PATTERN.search(path):
        return findings

    content = tool_input.get("content") or tool_input.get("new_string") or ""
    if not content and isinstance(tool_input.get("edits"), list):
        content = "\n".join(
            str(e.get("new_string", "")) for e in tool_input["edits"]
        )

    for pattern, label_zh, label_en in SECRET_CONTENT_PATTERNS:
        if re.search(pattern, content):
            findings.append((
                {
                    "id": "hardcoded-secret",
                    "category": "secrets",
                    "severity": "critical",
                    "zh": "检测到源码里被写入了真实密钥（%s）。提交后必须作废重发，删掉这行也没用。" % label_zh,
                    "en": "A live credential (%s) is being hardcoded into source. Once committed it must be rotated; deleting the line later does not help." % label_en,
                    "fix": "把密钥放进 .env，代码里用 os.environ / process.env 读取",
                    "fix_en": 'Put the key in .env and read it via os.environ / process.env',
                },
                path,
            ))
            break
    return findings


def decide(findings, mode):
    """Collapse findings into the single strictest decision."""
    table = MODES.get(mode, MODES[DEFAULT_MODE])
    order = {"allow": 0, "ask": 1, "deny": 2}
    decision = "allow"
    for rule, _ in findings:
        candidate = table.get(rule.get("severity", "high"), "ask")
        if order[candidate] > order[decision]:
            decision = candidate
    return decision


def render(findings, decision, mode, lang):
    headers = {
        "zh":   {"deny": "vibe-guardrails 拦截了这条操作",
                 "ask":  "vibe-guardrails 需要你确认"},
        "en":   {"deny": "blocked by vibe-guardrails",
                 "ask":  "vibe-guardrails needs your confirmation"},
        "both": {"deny": "vibe-guardrails 拦截了这条操作 / blocked by vibe-guardrails",
                 "ask":  "vibe-guardrails 需要你确认 / vibe-guardrails needs your confirmation"},
    }
    header = headers[lang].get(decision, "vibe-guardrails")

    lines = [header, ""]
    for rule, target in findings:
        table = MODES.get(mode, MODES[DEFAULT_MODE])
        verdict = table.get(rule.get("severity", "high"), "ask")
        if verdict == "allow":
            continue
        lines.append("[%s] %s" % (rule.get("category", "?"), rule["id"]))
        snippet = target if len(target) <= 200 else target[:197] + "..."
        lines.append("  > %s" % snippet)
        if lang in ("zh", "both"):
            lines.append("  %s" % rule["zh"])
        if lang in ("en", "both"):
            lines.append("  %s" % rule["en"])
        fix_zh, fix_en = rule.get("fix"), rule.get("fix_en") or rule.get("fix")
        if lang == "en" and fix_en:
            lines.append("  suggestion: %s" % fix_en)
        elif lang == "zh" and fix_zh:
            lines.append("  建议: %s" % fix_zh)
        elif lang == "both":
            if fix_zh:
                lines.append("  建议: %s" % fix_zh)
            if fix_en and fix_en != fix_zh:
                lines.append("  suggestion: %s" % fix_en)
        lines.append("")

    footers = {
        "zh":   {"deny": "如果你确实需要执行它，请自己在终端里手动运行，不要让 agent 代劳。",
                 "ask":  "确认无误后回复继续即可。"},
        "en":   {"deny": "If you truly need this, run it yourself in a terminal rather than delegating it.",
                 "ask":  "Reply to confirm if this is what you intended."},
        "both": {"deny": "如果你确实需要执行它，请自己在终端里手动运行，不要让 agent 代劳。"
                         " / If you truly need this, run it yourself in a terminal rather than delegating it.",
                 "ask":  "确认无误后回复继续即可。"
                         " / Reply to confirm if this is what you intended."},
    }
    lines.append(footers[lang].get(decision, ""))
    return "\n".join(lines).strip()


def emit(decision, reason):
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }))


def analyze(payload):
    """Pure function: payload dict -> (decision, reason). Used by the tests."""
    mode = os.environ.get("VIBE_GUARDRAILS_MODE", DEFAULT_MODE).lower()
    if mode not in MODES:
        mode = DEFAULT_MODE
    lang = os.environ.get("VIBE_GUARDRAILS_LANG", "both").lower()
    if lang not in ("zh", "en", "both"):
        lang = "both"

    rules, allowlist, disabled = load_config()
    tool = payload.get("tool_name", "")
    tool_input = payload.get("tool_input") or {}

    if tool == "Bash":
        command = tool_input.get("command", "") or ""
        findings = evaluate_bash(command, rules, allowlist, disabled)
    elif tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        findings = evaluate_file_write(tool, tool_input, disabled)
    else:
        return "allow", ""

    if not findings:
        return "allow", ""

    decision = decide(findings, mode)
    if decision == "allow":
        return "allow", ""
    return decision, render(findings, decision, mode, lang)


def main():
    if os.environ.get("VIBE_GUARDRAILS_OFF") == "1":
        return 0
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0  # No parseable input: stay out of the way.

    try:
        decision, reason = analyze(payload)
    except Exception as exc:  # A bug in the guard must never block the agent.
        sys.stderr.write("vibe-guardrails internal error: %s\n" % exc)
        return 0

    if decision != "allow":
        emit(decision, reason)
    return 0


if __name__ == "__main__":
    sys.exit(main())
