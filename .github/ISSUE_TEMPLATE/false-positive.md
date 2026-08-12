---
name: False positive / 误拦了正常命令
about: vibe-guardrails blocked something harmless
title: "[false-positive] "
labels: false-positive
---

**What got blocked? / 被拦下的命令是？**

```
paste the exact command here
```

**Which rule fired? / 触发了哪条规则？**

<!-- The id appears in the message, e.g. [filesystem] rm-rf-broad -->

**Why is it safe? / 为什么它是安全的？**

---

False positives are treated as bugs, not as the tool working correctly. A guard
that interrupts everyday work gets uninstalled, and then it protects nobody.

误报在这个项目里算 bug，不算"正常拦截"。
一个会打断日常工作的工具会被卸载，卸载之后它谁也保护不了。

**Immediate workaround / 临时绕过：** add the command to `allow` in
`~/.claude/vibe-guardrails/rules.json`.
