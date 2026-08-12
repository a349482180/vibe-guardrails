---
name: Missing rule / 漏掉了一条危险命令
about: An agent ran something destructive and vibe-guardrails did not stop it
title: "[rule] "
labels: rule
---

**What command ran? / 执行的是什么命令？**

```
paste the exact command here
```

**What did it destroy? / 造成了什么后果？**

<!-- e.g. deleted three hours of uncommitted work / 删掉了三小时没提交的改动 -->

**Was it recoverable? / 能恢复吗？**

- [ ] No, permanently lost / 不能，永久丢失
- [ ] Yes, but painful / 能，但很麻烦
- [ ] Yes, easily / 能，很容易

**Which agent? / 用的哪个 agent？**

<!-- Claude Code / Codex / Cursor / other -->

---

You do not need to write the regex or know Python. The command and the
consequence are enough.

不需要你会写正则、也不需要懂 Python。把命令和后果说清楚就够了。
