<div align="center">

# vibe-guardrails

**给"看不懂命令但要按同意"的人准备的 AI 编程安全护栏。**

[English](./README.md) · [规则模板](./rules/CORE.zh-CN.md) · [参与贡献](./CONTRIBUTING.md)

![python](https://img.shields.io/badge/python-3.8%2B-blue)
![dependencies](https://img.shields.io/badge/dependencies-0-green)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

</div>

---

## 它解决什么问题

编程 agent 已经好到这个程度：一个从没写过一行代码的人，也能用它做出真正能用的东西。
这是件好事。

但这也意味着，越来越多的人正在批准他们看不懂的命令。
当 agent 提议执行 `rm -rf ~/project`，而确认框上只写着"Bash command"时，
一个非程序员没有任何办法分辨：这一条是清理缓存，还是把一个下午的工作抹掉。

真正的风险不是 agent 变坏，而是最普通的那些意外：
路径写错一个字符、一句 `git reset --hard` 盖掉三小时没提交的改动、
`.env` 被提交进公开仓库、一次 `--force` 推送覆盖了同事的代码。

`vibe-guardrails` 就站在 agent 和你的电脑之间，把这些拦下来。

## 它是什么

两个部分，各自都能单独用：

**1. 一个 hook**（`hooks/guard.py`）—— 一个零依赖的 Python 文件，
在每条命令执行前检查一遍，拦住毁灭性的那些，
并用大白话告诉你刚才差点发生了什么、为什么危险。

**2. 一套规则**（`rules/CORE.zh-CN.md`）—— 粘贴进你的 `CLAUDE.md` 或 `AGENTS.md`，
让 agent 从一开始就谨慎行事。

hook 是安全带，规则是防御性驾驶。两个都用上。

## 安装

```bash
git clone https://github.com/a349482180/vibe-guardrails.git
cd vibe-guardrails
bash install.sh
```

重启 agent，然后让它执行 `rm -rf /`，你应该会看到：

```
vibe-guardrails 拦截了这条操作 / blocked by vibe-guardrails

[filesystem] rm-rf-root
  > rm -rf /
  这条命令会递归强制删除根目录、主目录或上级目录 —— 会毁掉整个系统或你的全部
  个人文件，且无法撤销。
  建议 / suggestion: 明确写出要删除的具体目录名，例如 rm -rf ./build
```

规则部分，在你的 `CLAUDE.md` 里加一行：

```markdown
@./vibe-guardrails/rules/CORE.zh-CN.md
```

或者直接把 [`rules/CORE.zh-CN.md`](./rules/CORE.zh-CN.md) 的内容粘进去。

## 拦截清单

| 类别 | 直接拒绝 | 先问你 |
|---|---|---|
| **文件系统** | `rm -rf /`、`rm -rf ~`、`sudo rm`、`mkfs`、`dd of=/dev/sda` | 对真实目录的 `rm -rf`、`find -delete`、`chmod 777 /` |
| **Git** | `gh repo delete` | `push --force`、`reset --hard`、`clean -fd`、`filter-branch`、`branch -D` |
| **密钥** | `git add .env`、把真实的 `sk-…` / `ghp_…` / `AKIA…` 写进源码 | 写入 `.env`、`.pem`、`~/.ssh/`，echo `$*_SECRET` |
| **供应链** | `curl … \| sh` | `npm publish`、`twine upload`、`cargo publish` |
| **数据库** | `DROP DATABASE`、`TRUNCATE TABLE` | `redis-cli flushall`、`prisma migrate reset` |
| **云资源** | `terraform destroy`、`kubectl delete --all`、`aws s3 rb` | — |
| **系统** | `kill -9 1`、fork 炸弹 | `shutdown`、`history -c` |

三档策略，安装时选择，或用 `VIBE_GUARDRAILS_MODE` 临时切换：

| | critical | high | medium |
|---|---|---|---|
| `strict` 严格 | 拒绝 | 拒绝 | 询问 |
| `balanced` 平衡 *(默认)* | 拒绝 | 询问 | 询问 |
| `relaxed` 宽松 | 拒绝 | 询问 | 放行 |

## 设计原则

**误报才是真正的失败。** 一个会拦 `npm install` 的工具，一天之内就会被卸载，
卸载之后它谁也保护不了。所以日常命令 —— `rm -rf node_modules`、`git add .`、
`git push origin feature/x`、`curl -o file.json …` —— 一律直接放行；
如果还是误拦了，你可以往白名单里加。
测试用例里有一半以上，是专门用来验证"日常工作不被拦截"的。

**每条提示解释的是后果，不是规则。**
"已拦截：危险命令"什么也没教会你。
"这会丢弃所有未提交的改动，没 commit 的代码永久消失 —— 想留着就先 git stash"
才是你下个月还记得住的东西。

**出错时放行，而不是拦截。** guard 自己崩了、配置文件写坏了、输入解析失败 ——
这些情况一律放行。一个自己有 bug 就把你工作流卡死的安全工具，还不如不装。

**零依赖，单文件。** `hooks/guard.py` 只用 Python 3.8+ 标准库。
你可以整个读完，也可以让 agent 帮你审一遍。

## 自定义配置

编辑 `~/.claude/vibe-guardrails/rules.json`，升级不会覆盖它。

```jsonc
{
  // 永不检查 —— 写你每天要跑二十遍的那条命令
  "allow": ["^\\s*rm\\s+-rf\\s+\\./tmp-scratch/?\\s*$"],

  // 按 id 关掉某条内置规则（id 会出现在每次拦截提示里）
  "disable": ["shutdown"],

  // 加你自己的规则
  "rules": [{
    "id": "no-prod-ssh",
    "severity": "critical",
    "pattern": "\\bssh\\b[^\\n]*\\bprod\\b",
    "zh": "这条命令会连到生产服务器。",
    "en": "This connects to a production server."
  }]
}
```

临时开关：

```bash
VIBE_GUARDRAILS_OFF=1 claude      # 本次会话完全关闭
VIBE_GUARDRAILS_MODE=strict       # 临时切换策略档位
VIBE_GUARDRAILS_LANG=zh           # zh | en | both（默认 both）
```

## 局限 —— 请务必读这段

它防的是意外，**不是**安全边界。

guard 是对命令文本做模式匹配的。任何能让危险动作不出现在这段文本里的方式，
都能绕过去：base64 编码后解码执行、把危险命令藏在一个 shell 脚本里再执行、
`$(…)` 命令替换、Makefile 里的 target、`npm postinstall` 钩子。
要堵上这些，需要的是沙箱，不是正则。

请把它当作它本来的样子：一条安全带，防的是那些每天都真实发生几十次的普通失误 ——
发生在那些看不懂自己正在批准什么的人身上。
如果你需要真正的隔离边界，请把 agent 跑在容器或虚拟机里。

## 兼容性

按 Claude Code 的 `PreToolUse` hook 协议实现。
任何通过 stdin 传入 `{"tool_name": …, "tool_input": …}`、
并接受 `permissionDecision` 返回值的 agent，都可以直接用。

欢迎提交其他 agent 的适配层，见 [CONTRIBUTING.md](./CONTRIBUTING.md)。
**尤其欢迎提交规则** —— 如果 agent 曾经毁掉过你的东西，
那正是我们所有人都还缺的一条规则。

## 测试

```bash
python3 tests/test_guard.py
```

## 许可

MIT
